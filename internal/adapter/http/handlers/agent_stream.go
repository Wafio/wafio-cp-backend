package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// AgentStreamHandler streams live WAF decisions for a project to the
// dashboard. Subscribers receive events as Server-Sent Events:
//
//	event: decision
//	data: {"ts_unix":..., "host":"app.example.com", "action":"block", ...}
//
// The handler subscribes to the in-process DecisionBroker; events come from
// the gRPC stream maintained by internal/agentserver.
//
// With ?app_id=<app> the stream carries no decisions: it sends
//
//	event: stored
//	data: {"app_id":"…"}
//
// at most once per storedNotifyInterval after the control plane has written
// decisions of that app to waf_decisions. The app's Decisions tab then reads
// the rows newer than the ones it shows from GET …/apps/:appId/waf/decisions,
// so a burst of traffic costs each open tab one small query per interval
// instead of one event per decision.
type AgentStreamHandler struct {
	Repo   *repository.Repository
	Broker *agentserver.DecisionBroker
	// Guard re-checks the viewer while the stream is open. Nil =
	// the stream is refused.
	Guard StreamGuard
	// GeoEnricher fills country_code: the agent event carries none (the
	// control plane resolves it when storing), so without it a live row has
	// no country until the page reloads. Nil = no country.
	GeoEnricher GeoEnricher

	// appProject returns the project of an app; nil = Repo.App. Tests set it.
	appProject func(ctx context.Context, appID string) (string, error)
	// ownerOf replaces the project-owner lookup (tests only).
	ownerOf func(projectID string) string
}

// agentStreamHeartbeat is the keep-alive comment interval; the
// authorization re-check runs on it. A variable only for tests.
var agentStreamHeartbeat = 25 * time.Second

// storedNotifyInterval is the shortest gap between two `stored` events of one
// stream; signals in between are folded into the next event. A variable only
// for tests.
var storedNotifyInterval = 2 * time.Second

// Stream is GET /api/projects/:id/agent-decisions/stream
func (h *AgentStreamHandler) Stream(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing project id"})
	}
	uid, _ := c.Locals("user_id").(string)
	if uid == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	// Access is already enforced by RequireProjectAccess("viewer") on the pViewer group.
	// No redundant ownership check here — project members must also be able to stream.
	if h.Broker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "broker not initialized"})
	}
	if h.Guard == nil {
		return refuseUnguardedStream(c)
	}
	watch := newStreamWatch(c, h.Guard, "viewer")
	if appID := c.Query("app_id"); appID != "" {
		// Any value selects this form; one that is not an app of the
		// project is 404, never the project-wide decision stream.
		return h.storedStream(c, projectID, uid, appID, watch)
	}

	// Subscribe before the SSE headers go out. Once they are set the response
	// is committed to being a stream, and a refusal has to be an ordinary JSON
	// status the browser can act on.
	ownerID := streamProjectOwner(c.UserContext(), h.Repo, h.ownerOf, projectID)
	sub, err := h.Broker.SubscribeUserOwned(projectID, ownerID, uid, 128)
	if err != nil {
		return streamLimitResponse(c, err)
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	// Not c.UserContext(): that one ends when this handler returns, which is
	// before the stream starts. The stream lives until the client goes, the
	// viewer loses access, or the server shuts down.
	life := newSSELifetime(c)
	streamCtx, cancel := context.WithCancel(context.Background())

	c.Status(fiber.StatusOK)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer cancel()
		defer h.Broker.Unsubscribe(sub)

		_, _ = w.WriteString(": stream-open\n\n")
		_ = life.flush(w)

		hb := time.NewTicker(agentStreamHeartbeat)
		defer hb.Stop()

		for {
			select {
			case <-streamCtx.Done():
				return
			case <-life.done:
				// Plain close: the client reconnects with its normal backoff.
				return
			case <-hb.C:
				if reason := watch.check(); reason != "" {
					writeStreamClosed(w, reason)
					return
				}
				_, _ = w.WriteString(": hb " + strconv.FormatInt(time.Now().Unix(), 10) + "\n\n")
				if err := life.flush(w); err != nil {
					return
				}
			case ev, ok := <-sub.Ch:
				if !ok {
					return
				}
				dto := newLiveDecisionDTO(ev)
				dto.CountryCode = liveCountry(h.GeoEnricher, ev.GetRemoteIp())
				payload, err := json.Marshal(dto)
				if err != nil {
					continue
				}
				_, _ = w.WriteString("event: decision\ndata: ")
				_, _ = w.Write(payload)
				_, _ = w.WriteString("\n\n")
				if err := life.flush(w); err != nil {
					return
				}
			}
		}
	})
	return nil
}

// streamLimitResponse answers a subscription the broker refused with 429
// STREAM_LIMIT. Every subscriber is a held connection, a goroutine and a
// channel; at a ceiling, refuse rather than degrade the stream for everyone
// already connected. The per-user ceiling keeps one account from
// filling the process-wide one.
func streamLimitResponse(c *fiber.Ctx, err error) error {
	msg := "too many open event streams for this project; close an existing one and retry"
	switch {
	case errors.Is(err, agentserver.ErrStreamLimitUser):
		msg = "too many open event streams for this account; close an existing one and retry"
	case errors.Is(err, agentserver.ErrStreamLimitOwner):
		msg = ownerStreamLimitMessage("event", agentserver.MaxSubscribersPerOwner)
	}
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error": msg,
		"code":  "STREAM_LIMIT",
	})
}

// storedStream serves the ?app_id= form of the stream: `stored` events for one
// app of the project (see AgentStreamHandler). An app outside the project is
// 404, like every app route.
func (h *AgentStreamHandler) storedStream(c *fiber.Ctx, projectID, uid, rawAppID string, watch *streamWatch) error {
	parsed, err := uuid.Parse(rawAppID)
	if err != nil || len(rawAppID) != 36 || !h.appInProject(c.UserContext(), projectID, parsed.String()) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	}
	appID := parsed.String()
	ownerID := streamProjectOwner(c.UserContext(), h.Repo, h.ownerOf, projectID)
	sub, err := h.Broker.SubscribeStoredOwned(projectID, ownerID, appID, uid)
	if err != nil {
		return streamLimitResponse(c, err)
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	life := newSSELifetime(c)
	payload, _ := json.Marshal(struct {
		AppID string `json:"app_id"`
	}{appID})

	c.Status(fiber.StatusOK)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer h.Broker.Unsubscribe(sub)

		_, _ = w.WriteString(": stream-open\n\n")
		_ = life.flush(w)

		hb := time.NewTicker(agentStreamHeartbeat)
		defer hb.Stop()
		// A signal inside storedNotifyInterval of the last event waits on
		// this timer; further signals until it fires add nothing.
		var last time.Time
		var wait *time.Timer
		var waitC <-chan time.Time
		defer func() {
			if wait != nil {
				wait.Stop()
			}
		}()
		send := func() bool {
			last = time.Now()
			_, _ = w.WriteString("event: stored\ndata: ")
			_, _ = w.Write(payload)
			_, _ = w.WriteString("\n\n")
			return life.flush(w) == nil
		}

		for {
			select {
			case <-life.done:
				return
			case <-hb.C:
				if reason := watch.check(); reason != "" {
					writeStreamClosed(w, reason)
					return
				}
				_, _ = w.WriteString(": hb " + strconv.FormatInt(time.Now().Unix(), 10) + "\n\n")
				if err := life.flush(w); err != nil {
					return
				}
			case _, ok := <-sub.Stored:
				if !ok {
					return
				}
				if waitC != nil {
					continue // an event is already scheduled
				}
				if d := storedNotifyInterval - time.Since(last); d > 0 {
					wait = time.NewTimer(d)
					waitC = wait.C
					continue
				}
				if !send() {
					return
				}
			case <-waitC:
				waitC = nil
				if !send() {
					return
				}
			}
		}
	})
	return nil
}

// appInProject reports whether appID (canonical UUID) is an app of projectID.
func (h *AgentStreamHandler) appInProject(ctx context.Context, projectID, appID string) bool {
	if h.appProject != nil {
		p, err := h.appProject(ctx, appID)
		return err == nil && p == projectID
	}
	if h.Repo == nil || h.Repo.App == nil {
		return false
	}
	app, err := h.Repo.App.GetByID(ctx, appID)
	return err == nil && app != nil && app.ProjectID == projectID
}

// liveDecisionDTO is the SSE "decision" event payload: the agent's
// WAFDecisionEvent in snake_case JSON.
type liveDecisionDTO struct {
	TsUnix   int64  `json:"ts_unix"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	URI      string `json:"uri"`
	RemoteIP string `json:"remote_ip"`
	// Status is the HTTP status the client received; 0 = not recorded.
	Status         int32             `json:"status"`
	Score          int32             `json:"score"`
	Action         string            `json:"action"`
	Categories     []string          `json:"categories"`
	MatchDetail    string            `json:"match_detail,omitempty"`
	AnalyzeMethod  string            `json:"analyze_method,omitempty"`
	AppID          string            `json:"app_id,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	BodySize       int32             `json:"body_size,omitempty"`
	BodyPreview    string            `json:"body_preview,omitempty"`
	CWE            string            `json:"cwe,omitempty"`
	LatencyUS      int32             `json:"latency_us,omitempty"`
	MatchSource    string            `json:"match_source,omitempty"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RequestBody    string            `json:"request_body,omitempty"`
	QueryParams    string            `json:"query_params,omitempty"`
	PayloadType    string            `json:"payload_type,omitempty"`
	// Coverage: semantic-scan gap flags; omitted when complete. The
	// engine_disabled and engine_log_only marks of the agent's coverage text are in
	// EnginesOff and EnginesLogOnly.
	Coverage string `json:"coverage,omitempty"`
	// EnginesOff: keys of the engines the operator switched off for the
	// request; [] when none.
	EnginesOff []string `json:"engines_off"`
	// EnginesLogOnly: keys of the engines whose blocking detection was held
	// back as a LOG decision on the request; [] when none.
	EnginesLogOnly []string `json:"engines_log_only"`
	// CountryCode: ISO 3166-1 alpha-2 of remote_ip, as stored rows carry it.
	CountryCode string `json:"country_code,omitempty"`
	// Strength: "block", "weak" or null, as on a stored row (domain.DecisionStrength).
	Strength *string `json:"strength"`
}

// liveCountry resolves the client's country for a live decision with the
// same GeoIP data the dashboard uses; "" when unknown.
func liveCountry(geo GeoEnricher, remoteIP string) string {
	if geo == nil || remoteIP == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}
	_, cc, _, _, _ := geo.Enrich(remoteIP)
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		return ""
	}
	return cc
}

func newLiveDecisionDTO(ev *agentv1.WAFDecisionEvent) liveDecisionDTO {
	coverage, enginesOff, enginesLogOnly := domain.SplitCoverage(ev.GetCoverage())
	return liveDecisionDTO{
		TsUnix:         ev.GetTsUnix(),
		Method:         ev.GetMethod(),
		Host:           ev.GetHost(),
		URI:            ev.GetUri(),
		RemoteIP:       ev.GetRemoteIp(),
		Status:         ev.GetStatus(),
		Score:          ev.GetScore(),
		Action:         ev.GetAction(),
		Categories:     ev.GetCategories(),
		MatchDetail:    ev.GetMatchDetail(),
		AnalyzeMethod:  domain.CanonicalAnalyzeMethod(ev.GetAnalyzeMethod()),
		AppID:          ev.GetAppId(),
		UserAgent:      ev.GetUserAgent(),
		ContentType:    ev.GetContentType(),
		BodySize:       ev.GetBodySize(),
		BodyPreview:    ev.GetBodyPreview(),
		CWE:            ev.GetCwe(),
		LatencyUS:      ev.GetLatencyUs(),
		MatchSource:    ev.GetMatchSource(),
		RequestHeaders: ev.GetRequestHeaders(),
		RequestBody:    ev.GetRequestBody(),
		QueryParams:    ev.GetQueryParams(),
		PayloadType:    ev.GetPayloadType(),
		Coverage:       coverage,
		EnginesOff:     enginesOff,
		EnginesLogOnly: enginesLogOnly,
		Strength:       domain.DecisionStrength(ev.GetAction(), ev.GetCategories(), enginesLogOnly),
	}
}
