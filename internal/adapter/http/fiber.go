package httpadapter

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

// OnConfigUpdated is called when a project's WAF config is updated (PUT /api/projects/:id/config).
// Optional; may be nil.
type OnConfigUpdated func(projectID string)

// ErrorHandler answers every error a handler or middleware returns instead of
// writing a response itself.
//
//   - *handlers.PublicError: its status, message and code, written for API
//     clients (e.g. 404 PROJECT_NOT_FOUND / AGENT_NOT_FOUND / NO_AGENTS from
//     the host resolvers).
//   - *fiber.Error: its status, with a generic message and code chosen by
//     status. The error's own text is logged, never sent: it can be library
//     text that was not written for a client.
//   - anything else: 500 INTERNAL_ERROR.
//
// This used to answer every error with 500 INTERNAL_ERROR, so a 404 raised as
// fiber.NewError by ~36 /host/* handlers — including cross-tenant lookups —
// reached the dashboard as a server failure. INTERNAL_ERROR is now
// reserved for 5xx.
func ErrorHandler(c *fiber.Ctx, err error) error {
	status, body := errorResponse(err)
	if status >= fiber.StatusInternalServerError {
		log.Printf("[fiber ErrorHandler] %s %s: %d: %v", c.Method(), c.Path(), status, err)
	} else {
		slog.Debug("request_error", "method", c.Method(), "path", c.Path(), "status", status, "err", err)
	}
	return c.Status(status).JSON(body)
}

func errorResponse(err error) (int, fiber.Map) {
	var pe *handlers.PublicError
	if errors.As(err, &pe) {
		if pe.Status >= fiber.StatusInternalServerError {
			return pe.Status, fiber.Map{"error": genericErrorMessage(pe.Status), "code": "INTERNAL_ERROR"}
		}
		return pe.Status, fiber.Map{"error": pe.Message, "code": pe.Code}
	}
	var fe *fiber.Error
	if errors.As(err, &fe) && fe.Code >= 400 && fe.Code < 600 {
		return fe.Code, fiber.Map{"error": genericErrorMessage(fe.Code), "code": genericErrorCode(fe.Code)}
	}
	return fiber.StatusInternalServerError, fiber.Map{
		"error": genericErrorMessage(fiber.StatusInternalServerError),
		"code":  "INTERNAL_ERROR",
	}
}

// genericErrorMessage is the client text for a status whose specific cause is
// not meant for the client.
func genericErrorMessage(status int) string {
	switch {
	case status == fiber.StatusBadRequest:
		return "The request is invalid."
	case status == fiber.StatusUnauthorized:
		return "Authentication is required."
	case status == fiber.StatusForbidden:
		return "You do not have access to this resource."
	case status == fiber.StatusNotFound:
		return "Not found."
	case status == fiber.StatusMethodNotAllowed:
		return "Method not allowed."
	case status == fiber.StatusConflict:
		return "The request conflicts with the current state of the resource."
	case status == fiber.StatusRequestEntityTooLarge:
		return "The request body is too large."
	case status == fiber.StatusUnprocessableEntity:
		return "The request could not be processed."
	case status == fiber.StatusTooManyRequests:
		return "Too many requests. Please retry later."
	case status == fiber.StatusServiceUnavailable:
		return "Service temporarily unavailable. Please try again later."
	case status >= 500:
		return "An error occurred. Please try again or contact support."
	default:
		return "The request could not be completed."
	}
}

// genericErrorCode is the machine-readable code for genericErrorMessage.
func genericErrorCode(status int) string {
	switch {
	case status == fiber.StatusBadRequest:
		return "BAD_REQUEST"
	case status == fiber.StatusUnauthorized:
		return "UNAUTHORIZED"
	case status == fiber.StatusForbidden:
		return "FORBIDDEN"
	case status == fiber.StatusNotFound:
		return "NOT_FOUND"
	case status == fiber.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case status == fiber.StatusConflict:
		return "CONFLICT"
	case status == fiber.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case status == fiber.StatusTooManyRequests:
		return "RATE_LIMITED"
	case status >= 500:
		return "INTERNAL_ERROR"
	default:
		return "REQUEST_FAILED"
	}
}

// sseQueryTokenAllowed reads WAFIO_SSE_QUERY_TOKEN, the compatibility switch
// for the deprecated ?token=<JWT> carrier on SSE endpoints. The
// dashboard uses single-use stream tickets, so ?token= is refused by default;
// "allow" turns it back on for an old client (each use logged, answered with a
// Deprecation header). Agents authenticate with mTLS and X-Agent-Key, never an
// SSE query string.
func sseQueryTokenAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAFIO_SSE_QUERY_TOKEN"))) {
	case "allow", "on", "true", "1":
		return true
	default:
		return false
	}
}

// startupSeedDelay lets the server finish starting before seedBuiltinRules
// queries the database. Tests that assert on unseeded rows raise it.
var startupSeedDelay = 2 * time.Second

// seedBuiltinRules seeds the built-in trace detection rules of every host, and
// the built-in correlation chains of every project, that have none yet. It
// replaces the seeding that GET /host/trace/rules and GET /correlation-rules
// used to perform, which made a viewer's read write to the database.
// New hosts and projects are seeded when created; this covers older ones.
func seedBuiltinRules(ctx context.Context, repo *repository.Repository, delay time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	seedCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if n, err := repo.DetectionRules.SeedUnseededHosts(seedCtx); err != nil {
		log.Printf("[startup] built-in trace rule seeding stopped after %d host(s): %v", n, err) //nolint:gosec // G706: counts and repository errors, no request data
	} else if n > 0 {
		log.Printf("[startup] seeded built-in trace rules for %d host(s)", n) //nolint:gosec // G706: counts and repository errors, no request data
	}
	if n, err := repo.CorrelationRules.SeedUnseededProjects(seedCtx); err != nil {
		log.Printf("[startup] built-in correlation rule seeding stopped after %d project(s): %v", n, err) //nolint:gosec // G706: counts and repository errors, no request data
	} else if n > 0 {
		log.Printf("[startup] seeded built-in correlation rules for %d project(s)", n) //nolint:gosec // G706: counts and repository errors, no request data
	}
}

// NewFiberApp builds the HTTP application. Without a gRPC server
// (agentServer nil) every handler field that takes it through an interface
// stays a nil interface, never a nil *agentserver.Server inside a non-nil
// interface, which the handlers' nil checks would not catch
// (TestDBAgentSecurityDataWithoutGRPCServer).
func NewFiberApp(ctx context.Context, cfg *config.Config, repo *repository.Repository, onConfigUpdated OnConfigUpdated, geoEnricher handlers.GeoEnricher, decisionBroker *agentserver.DecisionBroker, agentServer *agentserver.Server, secDataH *handlers.SecurityDataHandler, currentVersion string, opts ...AppOption) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler:          ErrorHandler,
		ReadTimeout:           httpReadTimeout,
		WriteTimeout:          httpWriteTimeout,
		IdleTimeout:           httpIdleTimeout,
	})
	// First: every later middleware and handler reads the resolved client
	// address through c.IP() (server.trusted_proxies; never Fiber's
	// ProxyHeader, which takes the client-written leftmost hop).
	app.Use(clientIPMiddleware(clientIPPolicy(cfg)))
	app.Use(recoverMiddleware())
	app.Use(requestContext(requestTimeout))
	// No query strings (SSE ?token=) and no invite tokens in the access log;
	// see accessLogConfig.
	app.Use(logger.New(accessLogConfig(nil)))
	ApplySecurityMiddleware(app, cfg)

	// The browser-driven setup wizard was removed. It ran unauthenticated, kept
	// running after installation, and GET /api/setup/config returned the JWT
	// signing secret and the database password to anyone who could reach the
	// port. First-run bootstrap now happens on the host, through
	// the control plane installer (install-controlplane.sh of wafio-release):
	//
	//	wafio migrate up
	//	wafio admin create --email you@example.com --name "Your Name"
	//
	// runServe refuses to start without a database, so repo is never nil here.

	// Persistent DB-backed lockout survives restarts.
	loginLimiter := repository.NewLoginAttemptRepo(repo.DB, cfg.Server.LoginMaxAttempts, cfg.Server.LoginLockMinutes)
	// Token revocation: RequireJWT re-reads each token's user through
	// this cache; handlers that revoke tokens invalidate it.
	userStates := newUserStates(repo, opts)
	// Open SSE streams re-check their viewer against the same state.
	streamGuard := newStreamAccess(repo, userStates)
	authH := &handlers.AuthHandler{
		Repo: repo,
		JWT: struct {
			Secret      string
			ExpireHours int
		}{cfg.JWT.Secret, cfg.JWT.ExpireHours},
		LoginAttempts: loginLimiter,
		UserStates:    userStates,
	}
	projectsH := &handlers.ProjectsHandler{
		Repo:            repo,
		OnConfigUpdated: onConfigUpdated,
	}
	if agentServer != nil {
		projectsH.Streams = agentServer
	}
	dashboardH := &handlers.DashboardHandler{Repo: repo, GeoEnricher: geoEnricher}

	rateAuthByIP := RateLimitAuthByIP(cfg)
	// The 2FA step verifies a 6-digit one-time code, which is exactly what the
	// separately-configurable OTP budget is for. It previously shared the
	// generic auth budget, leaving server.rate_limit_otp_max unused.
	rateOTPByIP := RateLimitOTPByIP(cfg)
	rateRegisterByIP := RateLimitRegisterByIP(cfg)
	rateLoginByIP := RateLimitLoginByIP(cfg)
	rateReadByUser := RateLimitReadByUser(cfg)
	rateWriteByUser := RateLimitWriteByUser(cfg)

	app.Post("/api/register/invite", rateRegisterByIP, authH.RegisterInvite)
	app.Post("/api/login", rateLoginByIP, authH.Login)
	app.Post("/api/login/2fa", rateOTPByIP, authH.Login2FA)

	// Live mail configuration (Administration › Email (SMTP)): the server
	// configuration where it sets smtp.host / server.base_url, else the
	// saved settings, read per send. Invitations, password recovery and the
	// admin test email all use it.
	mailSettings := newMailSettings(cfg, repo)

	// Password recovery by email: public, so registered
	// before the JWT group. forgot-password and reset-password each get their
	// own per-IP counter on the registration budget; forgot-password also
	// throttles per account (one email per five minutes, in the database).
	recovery := resolveOptions(opts).passwordRecovery
	if recovery == nil {
		recovery = newPasswordRecovery(repo, mailSettings)
		go recovery.Run(ctx)
	}
	recoveryH := &handlers.PasswordRecoveryHandler{Recovery: recovery, UserStates: userStates, LoginAttempts: loginLimiter}
	rateForgotByIP := RateLimitRecoveryByIP(cfg)
	rateResetByIP := RateLimitRecoveryByIP(cfg)
	app.Get("/api/auth/recovery", rateAuthByIP, recoveryH.RecoveryInfo)
	app.Post("/api/auth/forgot-password", rateForgotByIP, recoveryH.ForgotPassword)
	app.Post("/api/auth/reset-password", rateResetByIP, recoveryH.ResetPassword)

	// Host-key enrollment: the host's
	// installer sends a CSR with its host key and gets a client certificate
	// bound to that host and one agent. Public (no JWT, not under
	// RequireAgentKey, which accepts the previous key and creates agent
	// rows); its own limiter counts failed requests per IP and stops them
	// before the argon2id key check.
	//
	// Registered BEFORE the /api/internal/host group below: Fiber v2 matches
	// group middleware by plain path prefix, so "/api/internal/host" would
	// otherwise run rateAgentByIP and RequireAgentKey on
	// "/api/internal/host-enroll" first (TestEnrollRouteNotBehindIngestGroup).
	rateEnrollByIP := RateLimitEnrollByIP(cfg)
	enrollment := &application.HostEnrollment{
		Store:          repo.HostEnroll,
		GRPCEndpoint:   handlers.AgentGRPCEndpoint(cfg.Server.GRPCDomain, handlers.ControlPlanePortFromAddr(cfg.Server.AgentGRPCAddr)),
		GRPCServerName: handlers.AgentGRPCServerName(cfg.Server.GRPCDomain),
	}
	if agentServer != nil {
		enrollment.Streams = agentServer
	}
	hostEnrollH := &handlers.HostEnrollHandler{Svc: enrollment}
	app.Post("/api/internal/host-enroll", rateEnrollByIP, hostEnrollH.Enroll)

	// ── Agent ingestion endpoints (authenticated via X-Agent-Key, NOT JWT) ──
	// Must be registered BEFORE the JWT-protected /api group to avoid JWT middleware interception.
	// Rate-limited per source IP to prevent bearer-token brute force; the
	// limiter runs before auth so a flood of invalid keys can't exhaust
	// argon2id work.
	rateAgentByIP := RateLimitAgentByIP(cfg)
	hostIngest := &handlers.HostIngestHandler{Repo: repo}
	if agentServer != nil {
		hostIngest.GRPCSrv = agentServer
	}
	ingestAPI := app.Group("/api/internal/host", rateAgentByIP, hostIngest.RequireAgentKey())
	ingestAPI.Post("/ingest", hostIngest.Ingest)

	// WAF agents pull their app bundle and push decision telemetry here.
	// RequireAgentKey middleware is shared with the host ingest path; the
	// agents table carries a `kind` column (host|waf) — handlers ignore
	// kind for now but it becomes relevant once per-kind quotas land.
	wafAgent := &handlers.WAFAgentHandler{Repo: repo, OverviewCache: handlers.NewOverviewCache(), GeoEnricher: geoEnricher}
	if agentServer != nil {
		wafAgent.AgentServer = agentServer
	}
	wafAgent.WarmOverviewCache(1440) // pre-warm with 24h window (common dashboard default)
	wafAgentAPI := app.Group("/api/internal/waf", rateAgentByIP, hostIngest.RequireAgentKey())
	wafAgentAPI.Get("/bundle", wafAgent.Bundle)
	wafAgentAPI.Post("/ingest", wafAgent.Ingest)

	// Public invite info endpoint — must be registered BEFORE the JWT group.
	inviteH := &handlers.InviteHandler{Repo: repo, Mail: mailSettings}
	// Public and unauthenticated, and it validates a secret: without a limiter
	// an invite token can be guessed at network speed.
	app.Get("/api/invite/:token", rateAuthByIP, inviteH.GetInviteInfo)
	app.Get("/api/version", rateAuthByIP, func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"version": currentVersion})
	})

	// SSE endpoints authenticate with a single-use stream ticket; the
	// deprecated ?token=<JWT> is accepted only with WAFIO_SSE_QUERY_TOKEN=allow.
	streamTickets := auth.NewStreamTickets(cfg.JWT.Secret)
	api := app.Group("/api", RequireJWTWith(cfg.JWT.Secret, JWTOptions{
		Users:           userStates,
		StreamTickets:   streamTickets,
		AllowQueryToken: sseQueryTokenAllowed(),
	}))
	api.Post("/invite/:token/accept", rateWriteByUser, inviteH.AcceptInvite)
	api.Get("/me", rateReadByUser, authH.GetMe)
	api.Post("/profile/2fa/setup", rateWriteByUser, authH.Setup2FA)
	api.Get("/profile/2fa/setup", rateReadByUser, authH.Setup2FAMethodNotAllowed)
	api.Post("/profile/2fa/enable", rateWriteByUser, authH.Enable2FA)
	api.Post("/profile/2fa/disable", rateWriteByUser, authH.Disable2FA)
	api.Post("/profile/2fa/backup-codes/regenerate", rateWriteByUser, authH.RegenerateBackupCodes)
	api.Put("/me", rateWriteByUser, authH.UpdateProfile)
	api.Put("/me/password", rateWriteByUser, authH.ChangePassword)
	api.Post("/account/logout-all", rateWriteByUser, authH.LogoutAll)
	api.Get("/country-codes", rateReadByUser, handlers.CountryCodes)
	api.Get("/bot-defaults/ua-blocklist", rateReadByUser, handlers.UADefaultBlocklist)
	api.Get("/bot-defaults/ja4-blocklist", rateReadByUser, handlers.JA4DefaultBlocklist)
	api.Get("/bot-defaults/ja4-allowlist", rateReadByUser, handlers.JA4DefaultAllowlist)
	api.Get("/bot-defaults/ja3-blocklist", rateReadByUser, handlers.JA3DefaultBlocklist)
	api.Get("/projects", rateReadByUser, projectsH.List)
	api.Post("/projects", rateWriteByUser, projectsH.Create)

	// Project-scoped route groups with role-based access control.
	// viewer(read-only) < member(view+write) < owner(full access). Admins bypass.
	pViewer := api.Group("/projects/:id", RequireProjectAccess(repo, "viewer"))

	pViewer.Get("", rateReadByUser, projectsH.Get)
	pViewer.Put("", RequireProjectAccess(repo, "member"), rateWriteByUser, projectsH.Update)
	pViewer.Delete("", RequireProjectAccess(repo, "owner"), rateWriteByUser, projectsH.Delete)
	pViewer.Get("/config", rateReadByUser, projectsH.GetConfig)
	pViewer.Put("/config", RequireProjectAccess(repo, "member"), rateWriteByUser, projectsH.PutConfig)
	pViewer.Get("/config-history", rateReadByUser, projectsH.ConfigHistory)
	pViewer.Post("/config-history/:revision/rollback", RequireProjectAccess(repo, "member"), rateWriteByUser, projectsH.RollbackConfig)

	// Single-use SSE tickets for /host/stream, /waf/stream and
	// /agent-decisions/stream. Viewer access, like the streams themselves;
	// the read limiter, because issuing one is the first half of a read.
	streamTicketH := &handlers.StreamTicketHandler{Tickets: streamTickets}
	pViewer.Post("/stream-ticket", rateReadByUser, streamTicketH.Issue)

	// Agent gRPC mTLS credentials (provision / list / revoke). The actual
	// gRPC stream lives in internal/agentserver.
	agentCredH := &handlers.AgentCredentialHandler{Repo: repo, CertWarnBeforeDays: cfg.MTLS.CertWarnBeforeDays,
		GRPCDomain: cfg.Server.GRPCDomain, GRPCPort: handlers.ControlPlanePortFromAddr(cfg.Server.AgentGRPCAddr),
		ControlPlaneVersion: currentVersion}
	if agentServer != nil {
		agentCredH.Streams = agentServer
	}
	pViewer.Get("/agent-connect-info", rateReadByUser, agentCredH.ConnectInfo)
	pViewer.Post("/agent-grpc-credentials", RequireProjectAccess(repo, "member"), rateWriteByUser, agentCredH.Provision)
	pViewer.Get("/agent-grpc-credentials", rateReadByUser, agentCredH.List)
	pViewer.Delete("/agent-grpc-credentials/:credId", RequireProjectAccess(repo, "member"), rateWriteByUser, agentCredH.Revoke)

	// Live WAF decisions (SSE) sourced from the gRPC decision broker.
	if decisionBroker != nil {
		agentStream := &handlers.AgentStreamHandler{Repo: repo, Broker: decisionBroker, Guard: streamGuard, GeoEnricher: geoEnricher}
		pViewer.Get("/agent-decisions/stream", agentStream.Stream)
	}

	// Dashboard (per-project WAF event log — PostgreSQL/TimescaleDB).
	pViewer.Get("/dashboard/overview", rateReadByUser, dashboardH.Overview)
	pViewer.Get("/dashboard/logs", rateReadByUser, dashboardH.Logs)
	pViewer.Get("/dashboard/summary", rateReadByUser, dashboardH.Summary)
	pViewer.Get("/dashboard/stats/by-action", rateReadByUser, dashboardH.ByAction)
	pViewer.Get("/dashboard/stats/by-category", rateReadByUser, dashboardH.ByCategory)
	pViewer.Get("/dashboard/stats/by-analyze-method", rateReadByUser, dashboardH.ByAnalyzeMethod)
	pViewer.Get("/dashboard/stats/by-method", rateReadByUser, dashboardH.ByMethod)
	pViewer.Get("/dashboard/stats/by-country", rateReadByUser, dashboardH.ByCountry)
	pViewer.Get("/dashboard/stats/time-series", rateReadByUser, dashboardH.TimeSeries)
	pViewer.Get("/dashboard/top/uris", rateReadByUser, dashboardH.TopURIs)
	pViewer.Get("/dashboard/top/ips", rateReadByUser, dashboardH.TopIPs)
	pViewer.Get("/dashboard/top/countries", rateReadByUser, dashboardH.TopCountries)
	pViewer.Get("/dashboard/geo", rateReadByUser, dashboardH.GeoLocations)

	// ── Host agent dataplane (DB-backed — data pushed by agents, per-project) ──
	hostH := &handlers.HostPolicyHandler{Repo: repo, GeoEnricher: geoEnricher,
		GeoRanges:        resolveOptions(opts).geoRanges,
		ControlPlanePort: handlers.ControlPlanePortFromAddr(cfg.Server.AgentGRPCAddr)}
	if agentServer != nil {
		hostH.GRPCSrv = agentServer
	}
	hostH.StartFirewallCacheWarmer(ctx)
	go seedBuiltinRules(ctx, repo, startupSeedDelay)
	hostStream := &handlers.HostStreamHandler{Repo: repo, Guard: streamGuard}
	if agentServer != nil {
		hostStream.Live = agentServer
	}

	hostAPI := api.Group("/projects/:id/host", RequireProjectAccess(repo, "viewer"))
	// Agent management
	hostAPI.Post("/agents", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.RegisterAgent)
	hostAPI.Get("/agents", rateReadByUser, hostH.ListAgents)
	hostAPI.Delete("/agents/:agentId", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeleteAgent)
	// SSE streaming (authenticated via JWT)
	hostAPI.Get("/stream", hostStream.Stream)
	// Telemetry read (from PostgreSQL)
	hostAPI.Get("/status", rateReadByUser, hostH.GetStatus)
	hostAPI.Get("/metrics", rateReadByUser, hostH.GetMetrics)
	hostAPI.Get("/config", rateReadByUser, hostH.GetConfig)
	hostAPI.Put("/config", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.PutConfig)
	hostAPI.Get("/blocklist", rateReadByUser, hostH.ListBlocklist)
	hostAPI.Post("/blocklist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.AddBlocklist)
	hostAPI.Delete("/blocklist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeleteBlocklist)
	hostAPI.Get("/allowlist", rateReadByUser, hostH.ListAllowlist)
	hostAPI.Post("/allowlist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.AddAllowlist)
	hostAPI.Delete("/allowlist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeleteAllowlist)
	hostAPI.Get("/geo/blocked", rateReadByUser, hostH.ListGeoBlocked)
	hostAPI.Put("/geo/blocked", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.UpdateGeoBlocked)
	hostAPI.Get("/connections", rateReadByUser, hostH.ListConnections)
	hostAPI.Get("/bandwidth", rateReadByUser, hostH.ListBandwidth)
	hostAPI.Get("/events", rateReadByUser, hostH.GetEvents)
	// Port Policy endpoints (enterprise ingress/egress port firewall)
	hostAPI.Get("/port-policies", rateReadByUser, hostH.ListPortPolicies)
	hostAPI.Post("/port-policies", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.AddPortPolicy)
	hostAPI.Delete("/port-policies", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeletePortPolicy)
	hostAPI.Get("/port-policies/config", rateReadByUser, hostH.GetPortPolicyConfig)
	hostAPI.Put("/port-policies/config", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.UpdatePortPolicyConfig)
	// Egress IP blocklist
	hostAPI.Get("/egress-blocklist", rateReadByUser, hostH.ListEgressBlocklist)
	hostAPI.Post("/egress-blocklist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.AddEgressBlocklist)
	hostAPI.Delete("/egress-blocklist", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeleteEgressBlocklist)
	// Project-wide aggregate endpoints (all agents in one call)
	hostAPI.Get("/aggregate/status", rateReadByUser, hostH.GetAggregateStatus)
	hostAPI.Get("/aggregate/metrics", rateReadByUser, hostH.GetAggregateMetrics)
	hostAPI.Get("/aggregate/events", rateReadByUser, hostH.GetAggregateFirewallEvents)
	hostAPI.Get("/aggregate/trace/stats", rateReadByUser, hostH.GetAggregateTraceStats)
	hostAPI.Get("/aggregate/trace/events", rateReadByUser, hostH.GetAggregateTraceEvents)
	hostAPI.Get("/firewall/top-ips", rateReadByUser, hostH.GetFirewallTopIPs)
	hostAPI.Get("/firewall/drops-summary", rateReadByUser, hostH.GetFirewallDropsSummary)
	hostAPI.Get("/firewall/analytics", rateReadByUser, hostH.GetFirewallAnalytics)

	// Trace endpoints (DB-backed)
	hostAPI.Get("/trace/status", rateReadByUser, hostH.GetTraceStatus)
	hostAPI.Get("/trace/config", rateReadByUser, hostH.GetTraceConfig)
	hostAPI.Put("/trace/config", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.PutTraceConfig)
	hostAPI.Get("/trace/events", rateReadByUser, hostH.GetTraceEvents)
	hostAPI.Get("/trace/events/:category", rateReadByUser, hostH.GetTraceEventsByCategory)
	hostAPI.Get("/trace/stats", rateReadByUser, hostH.GetTraceStats)

	// ── Incidents (triage units grouping critical/high runtime events) ────
	incidentsH := &handlers.IncidentsHandler{Repo: repo}
	hostAPI.Get("/incidents", rateReadByUser, incidentsH.List)
	hostAPI.Get("/incidents/stats", rateReadByUser, incidentsH.Stats)
	hostAPI.Post("/incidents/:iid/ack", RequireProjectAccess(repo, "member"), rateWriteByUser, incidentsH.Acknowledge)
	hostAPI.Post("/incidents/:iid/resolve", RequireProjectAccess(repo, "member"), rateWriteByUser, incidentsH.Resolve)

	hostAPI.Get("/trace/types", rateReadByUser, hostH.GetTraceTypes)
	hostAPI.Get("/trace/policies", rateReadByUser, hostH.ListPolicies)
	hostAPI.Post("/trace/policies", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.CreatePolicy)
	hostAPI.Get("/trace/policies/:policyId", rateReadByUser, hostH.GetPolicy)
	hostAPI.Put("/trace/policies/:policyId", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.UpdatePolicy)
	hostAPI.Delete("/trace/policies/:policyId", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.DeletePolicy)
	hostAPI.Get("/trace/enforcement", rateReadByUser, hostH.GetEnforcementLog)
	hostAPI.Delete("/trace/enforcement-log", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.ClearEnforcementLog)

	// ── Runtime Security Detection Rules (Falco-like rule engine) ─────────
	drH := &handlers.DetectionRulesHandler{Repo: repo}
	hostAPI.Get("/trace/rules", rateReadByUser, drH.List)
	hostAPI.Post("/trace/rules", RequireProjectAccess(repo, "member"), rateWriteByUser, drH.Create)
	hostAPI.Put("/trace/rules/:ruleId", RequireProjectAccess(repo, "member"), rateWriteByUser, drH.Update)
	hostAPI.Post("/trace/rules/:ruleId/toggle", RequireProjectAccess(repo, "member"), rateWriteByUser, drH.Toggle)
	hostAPI.Delete("/trace/rules/:ruleId", RequireProjectAccess(repo, "member"), rateWriteByUser, drH.Delete)

	// ── Runtime Security Correlation Rules (multi-stage chains) ───────────
	crH := &handlers.CorrelationRulesHandler{Repo: repo}
	pViewer.Get("/correlation-rules", rateReadByUser, crH.List)
	pViewer.Post("/correlation-rules", RequireProjectAccess(repo, "owner"), rateWriteByUser, crH.Create)
	pViewer.Put("/correlation-rules/:ruleId", RequireProjectAccess(repo, "owner"), rateWriteByUser, crH.Update)
	pViewer.Delete("/correlation-rules/:ruleId", RequireProjectAccess(repo, "owner"), rateWriteByUser, crH.Delete)

	// ── Applications (logical WAF targets; not PaaS) ──
	appsH := &handlers.AppsHandler{Repo: repo}
	if agentServer != nil {
		appsH.AgentServer = agentServer
	}
	pViewer.Get("/apps", rateReadByUser, appsH.List)
	pViewer.Post("/apps", RequireProjectAccess(repo, "member"), rateWriteByUser, appsH.Create)
	pViewer.Get("/apps/:appId", RequireAppInProject(repo), rateReadByUser, appsH.Get)
	pViewer.Put("/apps/:appId", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, appsH.Update)
	pViewer.Delete("/apps/:appId", RequireAppInProject(repo), RequireProjectAccess(repo, "owner"), rateWriteByUser, appsH.Delete)

	// ── WAF agent assignment per app (fleet management) ──
	pViewer.Get("/apps/:appId/waf-agent", RequireAppInProject(repo), rateReadByUser, wafAgent.GetAppAgent)
	pViewer.Put("/apps/:appId/waf-agent", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, wafAgent.AssignAppAgent)
	pViewer.Delete("/apps/:appId/waf-agent", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, wafAgent.UnassignAppAgent)
	// Per-app WAF dashboard (decisions + counters pushed by the WAF agents)
	pViewer.Get("/apps/:appId/waf/decisions", RequireAppInProject(repo), rateReadByUser, wafAgent.AppDecisions)
	feedbackH := &handlers.WAFFeedbackHandler{Repo: repo, SummarySvc: &application.FeedbackSummary{Store: repo.WAF}}
	// False-positive feedback aggregate.
	pViewer.Get("/waf/feedback/summary", rateReadByUser, feedbackH.Summary)
	pViewer.Get("/apps/:appId/waf/decisions/:decisionId/feedback", RequireAppInProject(repo), rateReadByUser, feedbackH.List)
	pViewer.Post("/apps/:appId/waf/decisions/:decisionId/feedback", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, feedbackH.Create)
	pViewer.Get("/apps/:appId/waf/summary", RequireAppInProject(repo), rateReadByUser, wafAgent.AppSummary)
	// Per-app Overview dashboard (timeline chart + top-N panels)
	pViewer.Get("/apps/:appId/waf-events/timeline", RequireAppInProject(repo), rateReadByUser, wafAgent.AppTimeline)
	pViewer.Get("/apps/:appId/waf-events/top/:dim", RequireAppInProject(repo), rateReadByUser, wafAgent.AppTop)
	pViewer.Get("/apps/:appId/waf-events/geo", RequireAppInProject(repo), rateReadByUser, dashboardH.AppGeoLocations)

	// WAF agent liveness SSE stream (realtime online/offline dot)
	wafSSE := &handlers.WAFStreamHandler{Repo: repo, Guard: streamGuard}
	pViewer.Get("/waf/stream", wafSSE.Stream)
	registerHTTPMetrics(resolveOptions(opts).metrics, hostStream, wafSSE)

	// WAF custom rules — app-scoped (GUI + script mode)
	// RequireAppInProject on every route: the handlers' own app check used to
	// fall through on a miss (see resolveApp).
	customRulesH := &handlers.WafCustomRulesHandler{Repo: repo}
	if agentServer != nil {
		customRulesH.AgentServer = agentServer
	}
	pViewer.Get("/apps/:appId/custom-rules", RequireAppInProject(repo), rateReadByUser, customRulesH.List)
	pViewer.Post("/apps/:appId/custom-rules/validate", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, customRulesH.ValidateScript)
	pViewer.Post("/apps/:appId/custom-rules/validate-gui", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, customRulesH.ValidateGUI)
	pViewer.Post("/apps/:appId/custom-rules", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, customRulesH.Create)
	pViewer.Put("/apps/:appId/custom-rules/:ruleId", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, customRulesH.Update)
	pViewer.Delete("/apps/:appId/custom-rules/:ruleId", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, customRulesH.Delete)

	// Unified overview endpoint — returns all dashboard data in one response.
	pViewer.Get("/overview", rateReadByUser, wafAgent.ProjectOverview)
	pViewer.Get("/overview/evidence", rateReadByUser, wafAgent.OverviewEvidence)

	// Project-level WAF dashboard (Overview page — aggregates across every app
	// + agent in the project, including unmapped Host-header traffic).
	pViewer.Get("/waf-events/summary", rateReadByUser, wafAgent.ProjectSummary)
	pViewer.Get("/waf-events/recent", rateReadByUser, wafAgent.ProjectRecent)
	pViewer.Get("/waf-events/timeline", rateReadByUser, wafAgent.ProjectTimeline)
	pViewer.Get("/waf-events/top/:dim", rateReadByUser, wafAgent.ProjectTop)

	// ── Hosts (first-class entity for Pro / Enterprise self-hosted fleet) ──
	fleetSvc := &application.HostFleet{Store: repo.HostFleet, ControlPlaneVersion: currentVersion}
	hostsH := &handlers.HostsHandler{Repo: repo, FleetSvc: fleetSvc}
	if agentServer != nil {
		fleetSvc.Bundles = agentServer
		hostsH.Streams = agentServer
	}
	pViewer.Get("/hosts", rateReadByUser, hostsH.List)
	pViewer.Post("/hosts", RequireProjectAccess(repo, "member"), rateWriteByUser, hostsH.Create)
	// Fleet view and multi-host writes.
	// Registered before /hosts/:hostId, or Fiber would read "fleet",
	// "labels" and "apply" as host ids.
	pViewer.Get("/hosts/fleet", rateReadByUser, hostsH.Fleet)
	pViewer.Post("/hosts/labels", RequireProjectAccess(repo, "member"), rateWriteByUser, hostsH.UpdateLabels)
	pViewer.Post("/hosts/apply/firewall", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.ApplyFirewall)
	pViewer.Post("/hosts/apply/trace-policies", RequireProjectAccess(repo, "member"), rateWriteByUser, hostH.ApplyTracePolicies)
	pViewer.Post("/hosts/apply/detection-rules", RequireProjectAccess(repo, "member"), rateWriteByUser, drH.Apply)
	pViewer.Get("/hosts/:hostId", rateReadByUser, hostsH.Get)
	pViewer.Post("/hosts/:hostId/rotate-key", RequireProjectAccess(repo, "member"), rateWriteByUser, hostsH.RotateKey)
	pViewer.Post("/hosts/:hostId/revoke", RequireProjectAccess(repo, "member"), rateWriteByUser, hostsH.Revoke)
	pViewer.Delete("/hosts/:hostId", RequireProjectAccess(repo, "owner"), rateWriteByUser, hostsH.Delete)
	pViewer.Get("/hosts/:hostId/agents", rateReadByUser, hostsH.ListAgents)

	// The Instant SSH Setup endpoints were removed. They accepted an arbitrary
	// ssh_host and ssh_port from any project member and dialled them from the
	// control plane, which turned the control plane into an internal port
	// scanner, and they carried SSH credentials through the API. Agent
	// installation is now performed on the target host with
	// the agent installers (install-host-agent.sh and install-waf-agent.sh of wafio-release).

	// ── Audit log (security-sensitive operations) ──
	auditH := &handlers.AuditHandler{Repo: repo}
	pViewer.Get("/audit-log", rateReadByUser, auditH.List)

	userMgmtH := &handlers.UserManagementHandler{
		Repo:       repo,
		UserStates: userStates,
		JWT: struct {
			Secret      string
			ExpireHours int
		}{cfg.JWT.Secret, cfg.JWT.ExpireHours},
	}
	if agentServer != nil {
		userMgmtH.Streams = agentServer
	}
	// Allow any authenticated user to read audit log (write stays admin-only).

	adminAPI := api.Group("/admin", RequireAdmin())
	adminAPI.Get("/audit-log", rateReadByUser, auditH.ListSystem)
	adminAPI.Use("/users", auditH.AuditUserMutation)
	adminAPI.Get("/users", rateReadByUser, userMgmtH.ListUsers)
	adminAPI.Post("/users", rateWriteByUser, userMgmtH.CreateUser)
	adminAPI.Get("/users/:userId", rateReadByUser, userMgmtH.GetUser)
	adminAPI.Put("/users/:userId", rateWriteByUser, userMgmtH.UpdateUser)
	adminAPI.Delete("/users/:userId", rateWriteByUser, userMgmtH.DeleteUser)
	adminAPI.Post("/users/:userId/reset-password", rateWriteByUser, userMgmtH.ResetPassword)
	adminAPI.Get("/invites", rateReadByUser, inviteH.ListInvites)
	adminAPI.Post("/invites", rateWriteByUser, inviteH.CreateInvite)
	adminAPI.Delete("/invites/:token", rateWriteByUser, inviteH.DeleteInvite)

	// ── Email (SMTP) settings (admin only): live, password write-only ──
	mailH := &handlers.MailSettingsHandler{Settings: mailSettings, Repo: repo}
	rateMailTestByUser := RateLimitMailTestByUser(cfg)
	adminAPI.Get("/smtp-settings", rateReadByUser, mailH.GetSMTPSettings)
	adminAPI.Put("/smtp-settings", rateWriteByUser, mailH.UpdateSMTPSettings)
	adminAPI.Delete("/smtp-settings", rateWriteByUser, mailH.DeleteSMTPSettings)
	adminAPI.Post("/smtp-settings/test", rateMailTestByUser, mailH.TestSMTPSettings)

	// ── Data retention and database size (admin only) ──
	// The service reconciles saved retention at boot, runs the hourly
	// control-plane retention pass and the 10-minute size check.
	if storage := newStorage(ctx, cfg, repo, mailSettings, opts); storage != nil {
		storageH := &handlers.StorageHandler{Svc: storage, Repo: repo}
		adminAPI.Get("/storage", rateReadByUser, storageH.GetStatus)
		adminAPI.Get("/storage/alert", rateReadByUser, storageH.GetAlert)
		adminAPI.Put("/storage/retention", rateWriteByUser, storageH.UpdateRetention)
		adminAPI.Put("/storage/budget", rateWriteByUser, storageH.UpdateBudget)
		registerStorageMetrics(resolveOptions(opts).metrics, storage)
	}

	// ── Security data management (admin only) ──
	if secDataH != nil {
		adminAPI.Get("/security-data/status", rateReadByUser, secDataH.Status)
		adminAPI.Get("/security-data/malware-credentials", rateReadByUser, secDataH.MalwareCredentialStatus)
		adminAPI.Put("/security-data/malware-credentials", rateWriteByUser, secDataH.SaveMalwareCredential)
		adminAPI.Delete("/security-data/malware-credentials", rateWriteByUser, secDataH.DeleteMalwareCredential)
		// An update downloads and replaces data: POST only. The retired GET
		// answers 405 instead of falling through to the SPA.
		adminAPI.Post("/security-data/update", rateWriteByUser, secDataH.Update)
		adminAPI.Get("/security-data/update", rateReadByUser, secDataH.UpdateMethodNotAllowed)
	}

	// ── Project member management (owner only for add/change/remove) ──
	membersH := &handlers.ProjectMembersHandler{Repo: repo}
	pViewer.Get("/members", rateReadByUser, membersH.ListMembers)
	pViewer.Post("/members/invite", RequireProjectAccess(repo, "owner"), rateWriteByUser, inviteH.CreateProjectInvite)
	pViewer.Get("/members/invites", RequireProjectAccess(repo, "owner"), rateReadByUser, inviteH.ListProjectInvites)
	pViewer.Delete("/members/invites/:token", RequireProjectAccess(repo, "owner"), rateWriteByUser, inviteH.DeleteProjectInvite)
	pViewer.Post("/members", RequireProjectAccess(repo, "owner"), rateWriteByUser, membersH.AddMember)
	pViewer.Put("/members/:userId", RequireProjectAccess(repo, "owner"), rateWriteByUser, membersH.UpdateMemberRole)
	pViewer.Delete("/members/:userId", RequireProjectAccess(repo, "owner"), rateWriteByUser, membersH.RemoveMember)

	// GET /api/users/search was removed: it listed every
	// account across tenants to any authenticated user and had no caller.

	// ── Fleet-wide agent management (enterprise) ──
	agentMgrH := &handlers.AgentManagerHandler{Repo: repo}
	if agentServer != nil {
		agentMgrH.AgentServer = agentServer
		agentMgrH.AgentFetcher = agentServer
	}
	api.Get("/fleet/agents", rateReadByUser, agentMgrH.ListAgents)
	api.Get("/fleet/agents/:agentId", rateReadByUser, agentMgrH.GetAgent)
	// Not project-scoped in the path, so the handler checks the caller's role
	// in the agent's project: member or owner (or system admin), like every
	// other agent mutation below.
	api.Delete("/fleet/agents/:agentId", rateWriteByUser, agentMgrH.DeleteAgent)
	pViewer.Post("/agents", RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.RegisterAgent)
	pViewer.Delete("/agents/:agentId", RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.DeleteProjectAgent)
	// Per-agent inline-proxy listen port (WAF agents only).
	pViewer.Put("/agents/:agentId/proxy-port", RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.PutAgentProxyPort)
	// Per-agent security-data component status (host agents: geoip-country; WAF agents: all).
	pViewer.Get("/agents/:agentId/security-data", rateReadByUser, agentMgrH.GetAgentSecurityData)
	// Agent-scoped inline-proxy routes (replaces the separate Applications UI).
	pViewer.Get("/agents/:agentId/routes", rateReadByUser, wafAgent.ListAgentRoutes)
	pViewer.Post("/agents/:agentId/routes", RequireProjectAccess(repo, "member"), rateWriteByUser, wafAgent.CreateAgentRoute)
	pViewer.Put("/agents/:agentId/routes/:appId", RequireProjectAccess(repo, "member"), rateWriteByUser, wafAgent.UpdateAgentRoute)
	// Deleting a route deletes the application (and its rules and history): owner, like DELETE /apps/:appId.
	pViewer.Delete("/agents/:agentId/routes/:appId", RequireProjectAccess(repo, "owner"), rateWriteByUser, wafAgent.DeleteAgentRoute)
	// Per-app WAF config (rules_json + sensitivity per application).
	pViewer.Get("/agents/:agentId/routes/:appId/config", rateReadByUser, agentMgrH.GetAppConfig)
	pViewer.Delete("/agents/:agentId/routes/:appId/config", RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.ResetAppConfig)
	pViewer.Put("/agents/:agentId/routes/:appId/config", RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.PutAppConfig)
	pViewer.Get("/apps/:appId/waf/config-history", RequireAppInProject(repo), rateReadByUser, agentMgrH.AppConfigHistory)
	pViewer.Post("/apps/:appId/waf/config-history/:revision/rollback", RequireAppInProject(repo), RequireProjectAccess(repo, "member"), rateWriteByUser, agentMgrH.RollbackAppConfig)
	// Replay recent decisions against a proposed config — what-if dry run.

	// Block Window: live view of IPs blocked by LoginProtection / BlockPolicy.
	blockWindowH := &handlers.BlockWindowHandler{Server: agentServer, Repo: repo}
	pViewer.Get("/agents/:agentId/block-window", rateReadByUser, blockWindowH.List)
	pViewer.Delete("/agents/:agentId/block-window/:entryId", RequireProjectAccess(repo, "member"), rateWriteByUser, blockWindowH.Delete)

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	app.Get("/ready", rateReadByUser, handlers.Readiness(newReadiness(ctx, cfg, repo.DB.Ping, agentServer)))

	// An /api path no route matched is a JSON 404, not the SPA's index.html
	// with 200 — a removed endpoint (e.g. /api/users/search) must look
	// removed. Unauthenticated requests never get here: the /api group's JWT
	// middleware answers them with 401 first.
	app.All("/api/*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Not found.", "code": "NOT_FOUND"})
	})

	// Static frontend (SPA, frontend.go). Unmatched routes return index.html
	// so SvelteKit's client-side router handles a full page reload; a missing
	// file (anything under /_app/, a known asset extension) is a 404.
	//
	// This used to read index.html on every request and splice a <script> into
	// <head> that monkey-patched window.fetch, rewriting absolute
	// http://localhost:<port> URLs to same-origin. That existed for bundles
	// built with VITE_API_BASE_URL=http://localhost:9087. Current builds do not
	// need it: getBase() in web/src/lib/api.ts returns '' in the browser, so
	// requests are already same-origin, and the only localhost string left in
	// the bundle is the server-side-render fallback. Serving the file untouched
	// removes a per-request read, a per-request string rewrite, and one of the
	// reasons 'unsafe-inline' is still in the script-src CSP directive.
	frontendPath := cfg.Server.FrontendPath
	if frontendPath == "" {
		frontendPath = "frontend"
	}
	registerFrontend(app, frontendPath)

	return app
}
