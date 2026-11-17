package httpadapter

import (
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// isSSEPath reports whether a path is one of the server-sent-event endpoints,
// the only places where a credential may travel in the query string.
func isSSEPath(p string) bool {
	return strings.HasSuffix(p, "/stream")
}

// sseStreamScope splits an SSE path /api/projects/{id}/{stream}/stream into
// the project id and the stream name a ticket must be bound to ("host",
// "waf", "agent-decisions"). ok is false for any other shape.
func sseStreamScope(p string) (projectID, stream string, ok bool) {
	const prefix = "/api/projects/"
	if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, "/stream") {
		return "", "", false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(p, prefix), "/stream")
	projectID, stream, ok = strings.Cut(rest, "/")
	if !ok || projectID == "" || stream == "" {
		return "", "", false
	}
	return projectID, stream, true
}

// JWTOptions configures RequireJWTWith.
type JWTOptions struct {
	// Users re-reads each token's user (existence, role, token version) so a
	// deleted, demoted or logged-out user's token stops working.
	// Required: RequireJWTWith panics without it.
	Users *auth.UserStates
	// StreamTickets redeems ?ticket= on SSE endpoints. Nil disables tickets.
	StreamTickets *auth.StreamTickets
	// AllowQueryToken keeps the deprecated ?token=<JWT> carrier working on SSE
	// endpoints. Every use is logged (rate limited) and answered with a
	// Deprecation header. False rejects it with 401 QUERY_TOKEN_REJECTED.
	AllowQueryToken bool
}

// queryTokenWarned rate-limits the ?token= deprecation log line.
var queryTokenWarned atomic.Int64

func warnQueryToken(c *fiber.Ctx) {
	now := time.Now().Unix()
	last := queryTokenWarned.Load()
	if now-last < 60 || !queryTokenWarned.CompareAndSwap(last, now) {
		return
	}
	// The path only — never the query string, which holds the token.
	log.Printf("[JWT] deprecated ?token= credential on %s; clients must request POST /api/projects/:id/stream-ticket and connect with ?ticket=", logPath(c))
}

// RequireJWT validates the Bearer token and sets user_id, user_email and
// user_role in Locals. It is RequireJWTWith without stream tickets and with the
// deprecated ?token= SSE carrier allowed.
func RequireJWT(secret string, users *auth.UserStates) fiber.Handler {
	return RequireJWTWith(secret, JWTOptions{Users: users, AllowQueryToken: true})
}

// RequireJWTWith validates the Bearer token and sets user_id, user_email and
// user_role in Locals. The Authorization header is the only accepted carrier
// except on SSE endpoints, where EventSource cannot set headers: there a
// single-use stream ticket (?ticket=, bound to the user, the project and the
// stream) is accepted, and, while opts.AllowQueryToken is set, the deprecated
// ?token=<JWT>.
//
// A valid signature is not enough: the user must still exist and the
// token's tv claim must not be lower than users.token_version. user_role in
// Locals is the role stored now, never the role claim.
func RequireJWTWith(secret string, opts JWTOptions) fiber.Handler {
	if opts.Users == nil {
		panic("httpadapter: RequireJWTWith needs JWTOptions.Users (token revocation)")
	}
	return func(c *fiber.Ctx) error {
		var tokenString string

		// Try Authorization header first.
		//
		// Nothing here may log the header or the token. This used to print the
		// raw Authorization value on a format error, which wrote live bearer
		// tokens into the server log.
		authHeader := c.Get("Authorization")
		if authHeader != "" {
			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				log.Printf("[JWT] %s %s: malformed Authorization header", c.Method(), logPath(c))
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid Authorization format"})
			}
			tokenString = strings.TrimSpace(authHeader[len(prefix):])
		}

		// SSE endpoints only: a query string lands in access logs, proxy logs
		// and Referer headers, so no other route accepts a credential there.
		if tokenString == "" && isSSEPath(c.Path()) {
			if ticket := c.Query("ticket"); ticket != "" {
				return redeemStreamTicket(c, opts.StreamTickets, opts.Users, ticket)
			}
			if queryToken := c.Query("token"); queryToken != "" {
				if !opts.AllowQueryToken {
					log.Printf("[JWT] %s %s: ?token= rejected; stream ticket required", c.Method(), logPath(c))
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "a stream ticket is required for this endpoint",
						"code":  "QUERY_TOKEN_REJECTED",
					})
				}
				warnQueryToken(c)
				c.Set("Deprecation", "true")
				tokenString = queryToken
			}
		}

		if tokenString == "" {
			log.Printf("[JWT] %s %s: no credentials", c.Method(), logPath(c))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing Authorization header"})
		}

		claims, err := auth.ParseJWT(tokenString, secret)
		if err != nil {
			if errors.Is(err, auth.ErrTokenExpired) {
				log.Printf("[JWT] %s %s: token expired", c.Method(), logPath(c))
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token expired"})
			}
			log.Printf("[JWT] %s %s: token rejected: %v", c.Method(), logPath(c), err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		// A pre-auth token proves the password only; it exists to be exchanged
		// at POST /api/login/2fa. Accepting it here would skip the second
		// factor for every API route.
		if claims.PreAuth {
			log.Printf("[JWT] %s %s: pre-auth token rejected", c.Method(), logPath(c))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token", "code": "TWO_FACTOR_REQUIRED"})
		}
		state, handled, err := currentUserState(c, opts.Users, claims.UserID)
		if handled {
			return err
		}
		if claims.TokenVersion < state.TokenVersion {
			return tokenRevoked(c, "token version superseded")
		}
		c.Locals(auth.UserIDKey, claims.UserID)
		c.Locals(auth.UserEmailKey, claims.Email)
		c.Locals(auth.UserRoleKey, state.Role)
		c.Locals(auth.TokenVersionKey, claims.TokenVersion)
		return c.Next()
	}
}

// currentUserState loads the user's current state. handled=true means the
// request was answered: 503 when the state cannot be read (fail closed, and
// not 401, which would end the client's session over an outage), 401
// TOKEN_REVOKED when the user no longer exists.
func currentUserState(c *fiber.Ctx, users *auth.UserStates, userID string) (auth.UserState, bool, error) {
	state, err := users.Get(c.UserContext(), userID)
	if err != nil {
		log.Printf("[JWT] %s %s: user state unavailable: %v", c.Method(), logPath(c), err)
		return state, true, c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "authentication temporarily unavailable",
			"code":  "AUTH_UNAVAILABLE",
		})
	}
	if !state.Exists {
		return state, true, tokenRevoked(c, "user no longer exists")
	}
	return state, false, nil
}

// tokenRevoked answers 401 TOKEN_REVOKED. The reason is logged only; the
// client is not told whether the account was deleted or the token revoked.
func tokenRevoked(c *fiber.Ctx, reason string) error {
	log.Printf("[JWT] %s %s: token rejected: %s", c.Method(), logPath(c), reason)
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "session is no longer valid",
		"code":  "TOKEN_REVOKED",
	})
}

// redeemStreamTicket authenticates an SSE request by its ?ticket=. The ticket
// must be bound to the project and stream named by the path; it is spent on
// success. The user must still exist and the role in Locals is the stored
// one, not the one captured in the ticket. Membership is re-checked by
// RequireProjectAccess on the route.
func redeemStreamTicket(c *fiber.Ctx, tickets *auth.StreamTickets, users *auth.UserStates, ticket string) error {
	reject := func(reason error) error {
		log.Printf("[JWT] %s %s: stream ticket rejected: %v", c.Method(), logPath(c), reason)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid or expired stream ticket",
			"code":  "STREAM_TICKET_INVALID",
		})
	}
	if tickets == nil {
		return reject(auth.ErrTicketMalformed)
	}
	projectID, stream, ok := sseStreamScope(c.Path())
	if !ok {
		return reject(auth.ErrTicketScope)
	}
	claims, err := tickets.Redeem(ticket, projectID, stream)
	if err != nil {
		return reject(err)
	}
	state, handled, err := currentUserState(c, users, claims.UserID)
	if handled {
		return err
	}
	if claims.TokenVersion < state.TokenVersion {
		return tokenRevoked(c, "stream ticket issued before a revocation")
	}
	c.Locals(auth.UserIDKey, claims.UserID)
	c.Locals(auth.UserEmailKey, claims.Email)
	c.Locals(auth.UserRoleKey, state.Role)
	c.Locals(auth.TokenVersionKey, claims.TokenVersion)
	return c.Next()
}

// RequireAdmin allows only users with role="admin".
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, _ := c.Locals(auth.UserRoleKey).(string)
		if role != "admin" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin access required"})
		}
		return c.Next()
	}
}

// roleLevel maps project membership roles to a numeric access level.
// Higher level = more access. viewer(1) < member(2) < owner(3).
func roleLevel(role string) int {
	switch role {
	case "viewer":
		return 1
	case "member":
		return 2
	case "owner":
		return 3
	default:
		return 0
	}
}

// isCanonicalUUID reports whether s is a UUID in its canonical spelling
// (lower-case, hyphenated, no braces or urn prefix).
func isCanonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// RequireProjectAccess checks that the authenticated user has at least minRole on the project.
// Hierarchy: viewer(1) < member(2) < owner(3). Admins bypass the check.
func RequireProjectAccess(repo *repository.Repository, minRole string) fiber.Handler {
	minLevel := roleLevel(minRole)
	return func(c *fiber.Ctx) error {
		// Only the canonical spelling of a project id (lower-case, hyphenated
		// UUID) names a project: per-project state keyed by the URL id (apply
		// locks, agent streams) must not see two spellings of one project.
		// Anything else is the same 404 as an unknown project, admins included.
		projectID := c.Params("id")
		if !isCanonicalUUID(projectID) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		role, _ := c.Locals(auth.UserRoleKey).(string)
		if role == "admin" {
			c.Locals("project_role", "owner")
			return c.Next()
		}
		userID, _ := c.Locals(auth.UserIDKey).(string)
		memberRole, err := repo.ProjectMember.GetRole(c.UserContext(), projectID, userID)
		if err != nil || memberRole == "" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		c.Locals("project_role", memberRole)
		if roleLevel(memberRole) < minLevel {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": minRole + " access required"})
		}
		return c.Next()
	}
}

// RequireAppInProject verifies that the :appId in the path really belongs to
// the :id project before any handler reads it.
//
// RequireProjectAccess only proves the caller may touch :id. Without this
// check a viewer of any one project could pass another tenant's app UUID and
// read its WAF traffic, including request bodies and headers. Repository
// queries also filter on project_id; both layers are required, neither is
// sufficient alone.
//
// Cross-tenant lookups return 404, never 403, so the existence of another
// tenant's app is not disclosed.
func RequireAppInProject(repo *repository.Repository) fiber.Handler {
	return func(c *fiber.Ctx) error {
		appID := c.Params("appId")
		if appID == "" {
			return c.Next()
		}
		app, err := repo.App.GetByID(c.UserContext(), appID)
		if err != nil || app == nil || app.ProjectID != c.Params("id") {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
		}
		return c.Next()
	}
}
