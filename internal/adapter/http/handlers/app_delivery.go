package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// AppDeliveryHandler serves the delivery settings of an application: compression, files from a
// folder and the response cache, what its WAF agent reported about them, and the removal of stored
// copies.
type AppDeliveryHandler struct {
	Repo        *repository.Repository
	AgentServer interface {
		PushBundleToProject(projectID string)
		DeliverCachePurges(projectID, appID string)
	}
	// Bundles measures the bundle of an agent; nil when no agent can connect, so there is nothing to measure.
	Bundles BundleSizer
}

// Codes of the delivery answers.
const (
	deliveryCodeInvalid      = "INVALID_DELIVERY_SETTINGS"
	deliveryCodeInvalidPurge = "INVALID_CACHE_PURGE"
	deliveryCodeBundleSize   = "BUNDLE_TOO_LARGE"
	deliveryCodeAgentTooOld  = "AGENT_TOO_OLD"
	deliveryCodeUnsupported  = "FEATURE_UNSUPPORTED"
	deliveryCodeCacheOff     = "CACHE_OFF"
	deliveryCodePurgeQueue   = "PURGE_QUEUE_FULL"
	deliveryPurgesShown      = 10
)

// edgePartLabels name the parts in the sentences of the API.
var edgePartLabels = map[string]string{
	repository.EdgeRedirects:   "the main host name or path prefix",
	repository.EdgeCompression: "compression",
	repository.EdgeStaticFiles: "files from a folder",
	repository.EdgeCache:       "the cache",
}

func joinLabels(parts []string) string {
	labels := make([]string, 0, len(parts))
	for _, p := range parts {
		labels = append(labels, edgePartLabels[p])
	}
	if len(labels) > 1 {
		return strings.Join(labels[:len(labels)-1], ", ") + " and " + labels[len(labels)-1]
	}
	return strings.Join(labels, "")
}

// edgeRefused answers the refusals that name the agent: it is too old for a change, or too old for
// the application that moves to it. handled is false for any other error.
func edgeRefused(c *fiber.Ctx, err error) (handled bool, answered error) {
	var old *repository.AgentTooOldError
	var unsupported *repository.FeatureUnsupportedError
	switch {
	case errors.As(err, &old):
		return true, tlsAnswer(c, fiber.StatusConflict, deliveryCodeAgentTooOld,
			fmt.Sprintf("The WAF agent %s is too old for %s. Upgrade it to use this.", quoteName(old.Agent), edgePartLabels[old.Feature]),
			fiber.Map{"feature": old.Feature, "agent": shownName(old.Agent)})
	case errors.As(err, &unsupported):
		return true, tlsAnswer(c, fiber.StatusConflict, deliveryCodeUnsupported,
			fmt.Sprintf("The WAF agent %s cannot run %s of this application. Turn them off first, or upgrade it.",
				quoteName(unsupported.Agent), joinLabels(unsupported.Features)),
			fiber.Map{"agent": shownName(unsupported.Agent), "parts": unsupported.Features})
	}
	return false, nil
}

func quoteName(name string) string { return fmt.Sprintf("%q", shownName(name)) }

// ── Views ─────────────────────────────────────────────────────────────────

type deliveryAgentView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Online   bool   `json:"online"`
	Features struct {
		Redirects   *bool `json:"redirects"`
		Compression *bool `json:"compression"`
		StaticFiles *bool `json:"static_files"`
		Cache       *bool `json:"cache"`
	} `json:"features"`
}

// deliveryStatusView is the last report of the agent: when it was made, the bundle generation it
// answers, and the state of each part (null when the agent sent none for it).
type deliveryStatusView struct {
	AgentID     string                       `json:"agent_id"`
	Generation  int64                        `json:"generation"`
	ReceivedAt  time.Time                    `json:"received_at"`
	Redirects   *repository.EdgeFeatureState `json:"redirects"`
	Compression *repository.EdgeFeatureState `json:"compression"`
	StaticFiles *repository.EdgeFeatureState `json:"static_files"`
	Cache       *repository.EdgeFeatureState `json:"cache"`
}

type cachePurgeView struct {
	ID         string     `json:"id"`
	Scope      string     `json:"scope"`
	URL        string     `json:"url"`
	State      string     `json:"state"`
	Error      string     `json:"error"`
	By         string     `json:"by"`
	Agent      string     `json:"agent"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

func purgeView(p repository.CachePurge) cachePurgeView {
	return cachePurgeView{ID: p.ID, Scope: p.Scope, URL: p.URL, State: p.State, Error: p.Error, By: p.By, Agent: p.AgentName,
		CreatedAt: p.CreatedAt.UTC(), FinishedAt: utcOrNil(p.FinishedAt)}
}

func agentView(a *repository.EdgeAgent) *deliveryAgentView {
	if a == nil {
		return nil
	}
	v := &deliveryAgentView{ID: a.ID, Name: a.Name, Online: repository.AgentIsOnline(a.LastSeen)}
	v.Features.Redirects, v.Features.Compression = a.Redirects, a.Compression
	v.Features.StaticFiles, v.Features.Cache = a.StaticFiles, a.Cache
	return v
}

func edgeStatusView(s *repository.EdgeStatus) *deliveryStatusView {
	if s == nil {
		return nil
	}
	v := &deliveryStatusView{AgentID: s.AgentID, Generation: s.Generation, ReceivedAt: s.ReceivedAt.UTC()}
	for i := range s.Features {
		f := &s.Features[i]
		switch f.Feature {
		case repository.EdgeRedirects:
			v.Redirects = f
		case repository.EdgeCompression:
			v.Compression = f
		case repository.EdgeStaticFiles:
			v.StaticFiles = f
		case repository.EdgeCache:
			v.Cache = f
		}
	}
	return v
}

func rawOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// ── Reads ─────────────────────────────────────────────────────────────────

// Get returns the three delivery objects with their defaults filled in, the agent that serves the
// application, what that agent last reported, and the newest removals.
//
//	GET /api/projects/:id/apps/:appId/delivery
func (h *AppDeliveryHandler) Get(c *fiber.Ctx) error {
	ctx := c.UserContext()
	projectID, appID := c.Params("id"), c.Params("appId")
	d, err := h.Repo.Edge.GetDelivery(ctx, projectID, appID)
	if err != nil {
		return h.refused(c, err)
	}
	agent, err := h.Repo.Edge.AppEdgeAgent(ctx, projectID, appID)
	if err != nil {
		return h.refused(c, err)
	}
	out := fiber.Map{
		"compression": d.Compression, "static_files": d.StaticFiles, "cache": d.Cache,
		"agent": agentView(agent), "generation": nil, "status": nil,
		"cache_stats": json.RawMessage("null"), "compression_stats": json.RawMessage("null"),
	}
	if agent != nil {
		gen, err := h.Repo.Edge.BundleGeneration(ctx, agent.ID)
		if err != nil {
			return h.refused(c, err)
		}
		status, err := h.Repo.Edge.GetEdgeStatus(ctx, projectID, appID, agent.ID)
		if err != nil {
			return h.refused(c, err)
		}
		out["generation"] = gen
		if status != nil {
			out["status"] = edgeStatusView(status)
			out["cache_stats"], out["compression_stats"] = rawOrNull(status.Cache), rawOrNull(status.Compression)
		}
	}
	purges, err := h.Repo.Edge.ListCachePurges(ctx, projectID, appID, deliveryPurgesShown)
	if err != nil {
		return h.refused(c, err)
	}
	views := make([]cachePurgeView, 0, len(purges))
	for _, p := range purges {
		views = append(views, purgeView(p))
	}
	out["purges"] = views
	return c.JSON(out)
}

func (h *AppDeliveryHandler) refused(c *fiber.Ctx, err error) error {
	var field *domain.DeliveryFieldError
	var refuse *refusal
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return maintenanceNotFound(c)
	case errors.As(err, &field):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": field.Msg, "code": deliveryCodeInvalid, "field": field.Field})
	case errors.As(err, &refuse):
		return c.Status(refuse.status).JSON(refuse.body)
	}
	if handled, answered := edgeRefused(c, err); handled {
		return answered
	}
	apiErr := ResolveDBError(err, "app")
	return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
}

// ── Saves ─────────────────────────────────────────────────────────────────

func badBody(c *fiber.Ctx) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
}

// PutCompression replaces the compression settings.
//
//	PUT /api/projects/:id/apps/:appId/delivery/compression
func (h *AppDeliveryHandler) PutCompression(c *fiber.Ctx) error {
	var in domain.Compression
	if err := c.BodyParser(&in); err != nil {
		return badBody(c)
	}
	if err := in.Normalize(); err != nil {
		return h.refused(c, err)
	}
	return h.save(c, repository.DeliveryCompression, repository.AuditAppCompressionUpdated, in, in.Enabled)
}

// PutStaticFiles replaces the settings of files from a folder.
//
//	PUT /api/projects/:id/apps/:appId/delivery/static-files
func (h *AppDeliveryHandler) PutStaticFiles(c *fiber.Ctx) error {
	var in domain.StaticFiles
	if err := c.BodyParser(&in); err != nil {
		return badBody(c)
	}
	if err := in.Normalize(); err != nil {
		return h.refused(c, err)
	}
	return h.save(c, repository.DeliveryStaticFiles, repository.AuditAppStaticFilesUpdated, in, in.Enabled)
}

// PutCache replaces the response cache settings.
//
//	PUT /api/projects/:id/apps/:appId/delivery/cache
func (h *AppDeliveryHandler) PutCache(c *fiber.Ctx) error {
	var in domain.Cache
	if err := c.BodyParser(&in); err != nil {
		return badBody(c)
	}
	if err := in.Normalize(); err != nil {
		return h.refused(c, err)
	}
	return h.save(c, repository.DeliveryCache, repository.AuditAppCacheUpdated, in, in.Enabled)
}

// admit is the judgment of a save under the locks of the application and its agent. A part that is
// switched on and differs from the stored one needs an agent that did not report that it lacks it;
// turning a part off and saving the stored value again never does. A part that is switched on is also
// measured against the size of the bundle of its agent, with the object this save would give it.
func (h *AppDeliveryHandler) admit(c *fiber.Ctx, projectID, appID string, part repository.DeliveryPart, value any, enabled bool) repository.DeliveryAdmit {
	return func(stored repository.AppDelivery, agent repository.EdgeAgent, agentID string) error {
		if agentID == "" || !enabled {
			return nil
		}
		was, err1 := json.Marshal(stored.Part(part))
		now, err2 := json.Marshal(value)
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		if string(was) == string(now) {
			return nil
		}
		if agent.Lacks(string(part)) {
			return &repository.AgentTooOldError{Feature: string(part), Agent: agent.Name}
		}
		if h.Bundles == nil {
			return nil
		}
		name, size, over, err := bundleOverLimit(c.UserContext(), h.Repo, h.Bundles, projectID, agentID, func(rows []repository.WAFBundleAppRow) []repository.WAFBundleAppRow {
			for i := range rows {
				if rows[i].AppID != appID {
					continue
				}
				switch part {
				case repository.DeliveryCompression:
					rows[i].Compression = now
				case repository.DeliveryStaticFiles:
					rows[i].StaticFiles = now
				case repository.DeliveryCache:
					rows[i].Cache = now
				}
			}
			return rows
		})
		if err != nil || !over {
			return err
		}
		return &refusal{status: fiber.StatusConflict, body: fiber.Map{
			"error": fmt.Sprintf("The WAF agent %q can receive a configuration of at most %s bytes; with these settings it would be %s bytes. "+
				"Use fewer rules and a shorter list, or serve some applications from another agent.",
				shownName(name), groupDigits(engine.MaxAgentBundleBytes), groupDigits(size)),
			"code": deliveryCodeBundleSize,
		}}
	}
}

func (h *AppDeliveryHandler) save(c *fiber.Ctx, part repository.DeliveryPart, action string, value any, enabled bool) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	upd, err := h.Repo.Edge.UpdateDelivery(c.UserContext(), projectID, appID, part, value, h.admit(c, projectID, appID, part, value, enabled))
	if err != nil {
		return h.refused(c, err)
	}
	if upd.BundleBumped && h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
	h.audit(c, action, projectID, appID, map[string]any{"previous": upd.Previous.Part(part), "current": value})
	return c.JSON(fiber.Map{string(part): value, "generation": nullGeneration(upd.Generation)})
}

// nullGeneration is the generation the agent gets with the save, null while no agent serves the
// application.
func nullGeneration(gen int64) any {
	if gen == 0 {
		return nil
	}
	return gen
}

func (h *AppDeliveryHandler) audit(c *fiber.Ctx, action, projectID, appID string, meta map[string]any) {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	appName := ""
	if app, err := h.Repo.App.GetByID(c.UserContext(), appID); err == nil {
		appName = app.Name
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: action, TargetType: "app", TargetID: appID, TargetName: appName,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: meta,
	})
}

// ── Removal of stored copies ──────────────────────────────────────────────

type cachePurgeBody struct {
	Scope string `json:"scope"`
	URL   string `json:"url"`
}

// PurgeCache queues the removal of stored copies and sends it to the agent that serves the
// application, or to the agent when it comes back.
//
//	POST /api/projects/:id/apps/:appId/cache/purge
func (h *AppDeliveryHandler) PurgeCache(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	var in cachePurgeBody
	if err := c.BodyParser(&in); err != nil {
		return badBody(c)
	}
	url, err := domain.NormalizePurge(in.Scope, in.URL)
	if err != nil {
		var field *domain.DeliveryFieldError
		if errors.As(err, &field) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": field.Msg, "code": deliveryCodeInvalidPurge, "field": field.Field})
		}
		return h.refused(c, err)
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)
	p, err := h.Repo.Edge.CreateCachePurge(c.UserContext(), projectID, appID, userID, in.Scope, url)
	switch {
	case errors.Is(err, repository.ErrCacheOff):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "The cache of this application is off, so nothing is stored. Turn it on first.", "code": deliveryCodeCacheOff})
	case errors.Is(err, repository.ErrPurgeQueueFull):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "Too many removals are waiting for the WAF agent. Try again when they finish.", "code": deliveryCodePurgeQueue})
	case err != nil:
		return h.refused(c, err)
	}
	h.audit(c, repository.AuditAppCachePurged, projectID, appID, map[string]any{"scope": p.Scope, "url": p.URL, "purge_id": p.ID})
	if h.AgentServer != nil {
		go h.AgentServer.DeliverCachePurges(projectID, appID)
	}
	return c.Status(fiber.StatusAccepted).JSON(purgeView(p))
}

// stripPrefixOf reads proxy_config.strip_path_prefix, "" when there is none or the object does not parse.
func stripPrefixOf(raw json.RawMessage) string {
	pc, err := domain.ParseProxyConfig(raw)
	if err != nil {
		return ""
	}
	return pc.StripPathPrefix
}

// requireRedirectsForPrefix refuses a proxy_config that sets a path prefix that is new, when the
// agent that serves the application reported that it does not apply one (*repository.AgentTooOldError).
// A prefix that is empty, or the stored one again, always passes, so an application whose agent is
// older keeps saving. stored is the proxy_config now, patch the one the request carries.
func requireRedirectsForPrefix(ctx context.Context, repo *repository.Repository, projectID, appID string, stored, patch json.RawMessage) error {
	next := stripPrefixOf(patch)
	if next == "" || next == stripPrefixOf(stored) {
		return nil
	}
	agent, err := repo.Edge.AppEdgeAgent(ctx, projectID, appID)
	if err != nil || agent == nil {
		return err
	}
	if agent.Lacks(repository.EdgeRedirects) {
		return &repository.AgentTooOldError{Feature: repository.EdgeRedirects, Agent: agent.Name}
	}
	return nil
}
