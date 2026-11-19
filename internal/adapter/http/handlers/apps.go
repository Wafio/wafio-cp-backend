package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// errResponseSent is a sentinel used by ownerApp to signal that an HTTP
// response (404/400) was already written and the caller should just return.
var errResponseSent = errors.New("response sent")

// AppsHandler serves Application CRUD — a drastically slimmer model than the
// legacy PaaS deployer. An "application" is now a pure WAF target:
// (name, host_header, upstream_url) + a WAF Key issued to authorise the
// customer's self-hosted WAF agent to serve that target.
type AppsHandler struct {
	Repo        *repository.Repository
	AgentServer interface{ PushBundleToProject(projectID string) }
	// Bundles measures the bundle of an agent; nil when no agent can connect.
	Bundles BundleSizer
}

// ── List ──────────────────────────────────────────────────────────────────

// List returns the project's applications, paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=.
//
//	GET /api/projects/:id/apps?limit=&offset=
func (h *AppsHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required", "code": "BAD_REQUEST"})
	}
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found", "code": "PROJECT_NOT_FOUND"})
	}
	apps, err := h.Repo.App.ListByProject(c.UserContext(), projectID)
	if err != nil {
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if apps == nil {
		apps = []repository.App{}
	}
	page := parsePage(c, maxListLimit)
	out := pageOf(apps, page)
	for i := range out {
		appForReader(c, &out[i])
	}
	return c.JSON(fiber.Map{"apps": out, "total": len(apps), "limit": page.Limit, "offset": page.Offset})
}

// ── Create ────────────────────────────────────────────────────────────────

// createAppBody is the JSON request for POST /projects/:id/apps.
//
// Only `name` is strictly required; listen_host and upstream_url can be filled
// in later through Update (or from the "WAF Key" tab in the UI).
type createAppBody struct {
	Name        string `json:"name"         validate:"required,min=2,max=64"`
	ListenHost  string `json:"listen_host"  validate:"omitempty,max=255"`
	UpstreamURL string `json:"upstream_url" validate:"omitempty,max=512"`
}

func (h *AppsHandler) Create(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	projectID := c.Params("id")

	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	var err error

	var body createAppBody
	err = c.BodyParser(&body)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	err = validate.Struct(&body)
	if err != nil {
		return validationFailed(c, err)
	}
	err = validateListenHost(body.ListenHost)
	if err != nil {
		return invalidInput(c, "INVALID_HOST", err)
	}
	err = validateUpstreamURL(body.UpstreamURL)
	if err != nil {
		return invalidInput(c, "INVALID_UPSTREAM", err)
	}

	app := &repository.App{
		ProjectID: projectID,
		Name:      body.Name,
	}
	created, err := h.Repo.App.Create(c.UserContext(), app)
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "An application with this name already exists in this project.",
				"code":  "CONFLICT",
			})
		}
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}

	// Persist routing info immediately if supplied. A new application has no
	// WAF agent yet, so its listen address cannot clash (uniqueness is per
	// agent, migration 000094); the mapping stays for safety.
	if body.ListenHost != "" || body.UpstreamURL != "" {
		if err := h.Repo.App.SetRouting(c.UserContext(), created.ID, body.ListenHost, body.UpstreamURL); err != nil {
			if conflict, ok := appUniqueConflict(err); ok {
				_ = h.Repo.App.Delete(c.UserContext(), created.ID)
				return c.Status(fiber.StatusConflict).JSON(conflict)
			}
			apiErr := ResolveDBError(err, "app")
			return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
		}
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAppCreated, TargetType: "app", TargetID: created.ID, TargetName: created.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"name": created.Name, "listen_host": body.ListenHost, "upstream_url": domain.StripURLUserinfo(body.UpstreamURL)},
	})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"app": created})
}

// ── Get ───────────────────────────────────────────────────────────────────

func (h *AppsHandler) Get(c *fiber.Ctx) error {
	app, err := h.ownerApp(c)
	if err != nil {
		return nil
	}
	appForReader(c, app)
	return c.JSON(fiber.Map{"app": app})
}

// ── Update ────────────────────────────────────────────────────────────────

type updateAppBody struct {
	Name        string `json:"name"         validate:"omitempty,min=2,max=64"`
	ListenHost  string `json:"listen_host"  validate:"omitempty,max=255"`
	ListenPort  *int   `json:"listen_port"  validate:"omitempty,min=1,max=65535"`
	UpstreamURL string `json:"upstream_url" validate:"omitempty,max=512"`
	// FastCGI fields are patched one by one: nil (absent) keeps the stored
	// value, "" clears the doc root or resets the index to index.php.
	FCGIDocRoot  *string         `json:"fcgi_doc_root" validate:"omitempty,max=512"`
	FCGIIndex    *string         `json:"fcgi_index"    validate:"omitempty,max=128"`
	FCGIKeepConn *bool           `json:"fcgi_keep_conn"`
	ProxyConfig  json.RawMessage `json:"proxy_config"`
}

func (h *AppsHandler) Update(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	app, fErr := h.ownerApp(c)
	if fErr != nil {
		return nil
	}

	var body updateAppBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if err := validateListenHost(body.ListenHost); err != nil {
		return invalidInput(c, "INVALID_HOST", err)
	}
	if err := validateUpstreamURL(body.UpstreamURL); err != nil {
		return invalidInput(c, "INVALID_UPSTREAM", err)
	}

	if len(body.ProxyConfig) > 0 {
		pc, err := domain.ParseProxyConfig(body.ProxyConfig)
		if err == nil {
			err = pc.Validate()
		}
		if err != nil {
			return invalidInput(c, "INVALID_PROXY_CONFIG", err)
		}
	}
	patch := repository.AppPatch{ListenPort: body.ListenPort, ProxyConfig: body.ProxyConfig}
	if body.Name != "" {
		patch.Name = &body.Name
		app.Name = body.Name
	}
	if body.ListenHost != "" {
		patch.ListenHost = &body.ListenHost
	}
	if body.UpstreamURL != "" {
		patch.Upstream = &body.UpstreamURL
	}
	patch.FCGIDocRoot, patch.FCGIIndex = fcgiPatch(body.FCGIDocRoot, body.FCGIIndex)
	patch.FCGIKeepConn = body.FCGIKeepConn
	if err := h.Repo.App.UpdateAtomic(c.UserContext(), app.ProjectID, app.ID, patch,
		admitRouteChange(c.UserContext(), h.Repo, h.Bundles, app.ProjectID, app.ID, patch)); err != nil {
		var refuse *refusal
		if errors.As(err, &refuse) {
			return c.Status(refuse.status).JSON(refuse.body)
		}
		if conflict, ok := appUniqueConflict(err); ok {
			return c.Status(fiber.StatusConflict).JSON(conflict)
		}
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(app.ProjectID)
	}

	fresh, _ := h.Repo.App.GetByID(c.UserContext(), app.ID)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: app.ProjectID, ActorUserID: userID,
		Action: repository.AuditAppUpdated, TargetType: "app", TargetID: app.ID, TargetName: app.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: withFCGIKeepConn(withProxyTrust(map[string]any{"name": body.Name, "listen_host": body.ListenHost, "listen_port": body.ListenPort, "upstream_url": domain.StripURLUserinfo(body.UpstreamURL)}, body.ProxyConfig), body.FCGIKeepConn),
	})
	return c.JSON(fiber.Map{"app": fresh})
}

// ── Delete ────────────────────────────────────────────────────────────────

func (h *AppsHandler) Delete(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	app, fErr := h.ownerApp(c)
	if fErr != nil {
		return nil
	}
	if err := h.Repo.App.Delete(c.UserContext(), app.ID); err != nil {
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	appDeleteMeta := map[string]any{"name": app.Name}
	if app.ListenHost != nil {
		appDeleteMeta["listen_host"] = *app.ListenHost
	}
	if app.UpstreamURL != nil {
		appDeleteMeta["upstream_url"] = domain.StripURLUserinfo(*app.UpstreamURL)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: app.ProjectID, ActorUserID: userID,
		Action: repository.AuditAppDeleted, TargetType: "app", TargetID: app.ID, TargetName: app.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: appDeleteMeta,
	})
	return c.JSON(fiber.Map{"deleted": true})
}

// ── Helpers ──────────────────────────────────────────────────────────────

func (h *AppsHandler) ownerApp(c *fiber.Ctx) (*repository.App, error) {
	projectID := c.Params("id")
	appID := c.Params("appId")
	if projectID == "" || appID == "" {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id and app id required"})
		return nil, errResponseSent
	}
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		return nil, errResponseSent
	}
	app, err := h.Repo.App.GetByID(c.UserContext(), appID)
	if err != nil || app.ProjectID != projectID {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "app not found"})
		return nil, errResponseSent
	}
	return app, nil
}

// validateListenHost validates the bind address for an inline proxy route.
// Accepts a valid IPv4/IPv6 address (e.g. 0.0.0.0, 127.0.0.1, ::) or empty
// string (the agent defaults to 0.0.0.0).
func validateListenHost(h string) error {
	if h == "" {
		return nil
	}
	if net.ParseIP(h) == nil {
		return errors.New("listen_host must be a valid IP address (e.g. 0.0.0.0, 127.0.0.1)")
	}
	return nil
}

func validateUpstreamURL(u string) error {
	if u == "" {
		return nil
	}
	// Unix socket: nginx-style "unix:/path/to.sock" or Go-style "http://unix:/path:"
	if strings.HasPrefix(u, "unix:") || strings.HasPrefix(u, "http://unix:") || strings.HasPrefix(u, "https://unix:") {
		return nil
	}
	// FastCGI: fcgi:unix:/path/to.sock or fcgi://host:port
	if strings.HasPrefix(u, "fcgi:") {
		return nil
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return errors.New("upstream_url is not a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("upstream_url must use http, https, unix:, or fcgi:") //nolint:staticcheck // ST1005: client-facing text names the fcgi: scheme
	}
	if parsed.Host == "" {
		return errors.New("upstream_url must include a host")
	}
	return nil
}

// defaultFCGIIndex is the FastCGI index script used when none is given.
const defaultFCGIIndex = "index.php"

// fcgiPatch turns the optional FastCGI fields of an update body into an
// AppPatch pair: a field the request did not send stays nil (keep the stored
// value); an index sent empty becomes index.php.
func fcgiPatch(docRoot, index *string) (*string, *string) {
	if index != nil && *index == "" {
		def := defaultFCGIIndex
		index = &def
	}
	return docRoot, index
}

// withFCGIKeepConn records the keep-alive choice in an audit entry only when the request sent it.
func withFCGIKeepConn(meta map[string]any, keepConn *bool) map[string]any {
	if keepConn != nil {
		meta["fcgi_keep_conn"] = *keepConn
	}
	return meta
}

// derefString returns *p, or "" for nil.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
