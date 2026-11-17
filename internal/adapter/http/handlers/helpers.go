package handlers

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/wafio/wafio-cp-backend/internal/application"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	if errors.As(err, &e) && e.Code == "23505" {
		return true
	}
	return false
}

// listenAddrUniqueIndex is the unique index on (agent, listen host, listen
// port) of enabled WAF routes (migration 000094).
const listenAddrUniqueIndex = "uq_waf_agent_apps_listen_addr"

// isListenAddrTaken reports whether err is a clash on a WAF agent's listen
// address, as opposed to another unique violation (the app name).
func isListenAddrTaken(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505" && e.ConstraintName == listenAddrUniqueIndex
}

// appUniqueConflict maps a unique violation from an application or route
// write to its 409 body: LISTEN_HOST_TAKEN for the listen address, CONFLICT
// for anything else (the only other unique key on apps is the name within
// the project). ok is false when err is not a unique violation.
func appUniqueConflict(err error) (body fiber.Map, ok bool) {
	if !isUniqueViolation(err) {
		return nil, false
	}
	if isListenAddrTaken(err) {
		return fiber.Map{"error": "Another application on this WAF agent already uses this listen address.", "code": "LISTEN_HOST_TAKEN"}, true
	}
	return fiber.Map{"error": "An application with this name already exists in this project.", "code": "CONFLICT"}, true
}

func isForeignKeyViolation(err error) bool {
	var e *pgconn.PgError
	if errors.As(err, &e) && e.Code == "23503" {
		return true
	}
	return false
}

// APIError is used for API response: safe message for client, no technical details.
type APIError struct {
	HTTPStatus int
	Message    string
	Code       string // optional, for client (e.g. SESSION_INVALID)
}

// ResolveDBError maps DB/domain errors to APIError. Never send err.Error() to client.
func ResolveDBError(err error, context string) APIError {
	if err == nil {
		return APIError{HTTPStatus: fiber.StatusInternalServerError, Message: "An error occurred. Please try again."}
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503": // foreign_key_violation
			// user_id does not exist (session invalid / user deleted)
			if context == "project" || context == "config" || context == "mtls" {
				return APIError{
					HTTPStatus: fiber.StatusUnauthorized,
					Message:    "Your session is no longer valid. Please sign in again.",
					Code:       "SESSION_INVALID",
				}
			}
			return APIError{HTTPStatus: fiber.StatusBadRequest, Message: "The request references invalid or missing data. Please refresh and try again.", Code: "INVALID_REFERENCE"}
		case "23505": // unique_violation
			return APIError{HTTPStatus: fiber.StatusConflict, Message: "A resource with this value already exists.", Code: "CONFLICT"}
		case "3D000": // invalid_catalog_name (database does not exist)
		case "28P01": // invalid_password
			return APIError{HTTPStatus: fiber.StatusServiceUnavailable, Message: "Service temporarily unavailable. Please try again later.", Code: "SERVICE_UNAVAILABLE"}
		default:
			slog.Warn("unmapped_db_error", "code", pgErr.Code, "context", context)
		}
	}
	return APIError{
		HTTPStatus: fiber.StatusInternalServerError,
		Message:    "An error occurred while processing your request. Please try again or contact support.",
		Code:       "INTERNAL_ERROR",
	}
}

// ── Request body parsing ─────────────────────────────────────────────────

// BindJSON parses the request body into dst and runs struct validation in one
// step, writing the 400 response itself when either fails.
//
// Parsing and validation used to be two independent calls, and fifteen call
// sites across eight files performed the first without the second. Whether a
// handler validated its input could only be established by reading it line by
// line. Binding the two together makes the safe path the shortest one:
//
//	var body createFooRequest
//	if err := BindJSON(c, &body); err != nil {
//	    return err
//	}
//
// The parse error is logged rather than returned: encoding/json reports the Go
// package, struct and field type it failed on, which tells a caller about
// internal layout it has no business knowing.
func BindJSON[T any](c *fiber.Ctx, dst *T) error {
	if err := c.BodyParser(dst); err != nil {
		slog.Debug("body_parse_failed", "path", c.Path(), "err", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid body",
			"code":  "BAD_REQUEST",
		})
	}
	if err := validate.Struct(dst); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ValidationMessage(err),
			"code":  "VALIDATION_FAILED",
		})
	}
	return nil
}

// ValidationMessage renders validator errors as a caller-facing sentence.
//
// go-playground's default rendering is
//
//	Key: 'createFooRequest.Email' Error:Field validation for 'Email' failed on the 'email' tag
//
// which exposes internal struct names and is unreadable to an API consumer.
// This reduces it to the wire field name and the rule that failed.
func ValidationMessage(err error) string {
	var ve validator.ValidationErrors
	if !errors.As(err, &ve) || len(ve) == 0 {
		return "validation failed"
	}
	parts := make([]string, 0, len(ve))
	for _, fe := range ve {
		field := toSnakeCase(fe.Field())
		switch fe.Tag() {
		case "required":
			parts = append(parts, field+" is required")
		case "email":
			parts = append(parts, field+" must be a valid email address")
		case "min":
			parts = append(parts, field+" must be at least "+fe.Param())
		case "max":
			parts = append(parts, field+" must be at most "+fe.Param())
		case "oneof":
			parts = append(parts, field+" must be one of: "+fe.Param())
		default:
			parts = append(parts, field+" is invalid")
		}
	}
	return strings.Join(parts, "; ")
}

// toSnakeCase converts a Go field name to the snake_case form used on the wire.
func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ── Client-facing errors ─────────────────────────────────────────────────

// PublicError is an error whose Message and Code were written for API clients.
// A handler may return one instead of writing the response itself; the Fiber
// ErrorHandler (NewFiberApp) sends Status, Message and Code unchanged. Any
// other error a handler returns is answered with a generic message chosen by
// status class, so text that was never meant for a client cannot leak.
//
// Cause is the internal error, if any. It is logged by the ErrorHandler and
// never sent.
type PublicError struct {
	Status  int
	Code    string
	Message string
	Cause   error
}

func (e *PublicError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap exposes the cause and an equivalent *fiber.Error, so a Fiber app
// with the default ErrorHandler still answers with the right status.
func (e *PublicError) Unwrap() []error {
	out := []error{fiber.NewError(e.Status, e.Message)}
	if e.Cause != nil {
		out = append(out, e.Cause)
	}
	return out
}

// newPublicError builds a PublicError without an internal cause.
func newPublicError(status int, code, message string) *PublicError {
	return &PublicError{Status: status, Code: code, Message: message}
}

// Not-found errors for the resolvers project-scoped handlers go through.
// Cross-tenant ids produce the same answer as missing ones (404, never 403),
// so another tenant's resources are not disclosed.
var (
	errProjectNotFound = newPublicError(fiber.StatusNotFound, "PROJECT_NOT_FOUND", "Project not found.")
	errAgentNotFound   = newPublicError(fiber.StatusNotFound, "AGENT_NOT_FOUND", "Agent not found.")
	errAppNotFound     = newPublicError(fiber.StatusNotFound, "APP_NOT_FOUND", "Application not found.")
	errNoHostAgents    = newPublicError(fiber.StatusNotFound, "NO_AGENTS", "No host agent is registered for this project.")
)

// validationFailed answers a go-playground validator error with the wire
// field names and failed rules (ValidationMessage), never the raw validator
// text, which names Go structs and fields.
// passwordTooLong answers a new password bcrypt cannot hash: it reads at
// most 72 bytes and GenerateFromPassword refuses a longer one
// (bcrypt.ErrPasswordTooLong), which used to surface as a 500. Same answer
// as POST /api/auth/reset-password.
func passwordTooLong(c *fiber.Ctx) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": passwordTooLongMessage, "code": "VALIDATION_FAILED"})
}

const passwordTooLongMessage = "The password can be at most 72 bytes long."

// newPasswordTooLong reports whether pw is longer than bcrypt can hash.
func newPasswordTooLong(pw string) bool { return len(pw) > application.MaxPasswordBytes }

func validationFailed(c *fiber.Ctx, err error) error {
	slog.Debug("request_validation_failed", "path", c.Path(), "err", err)
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error": ValidationMessage(err),
		"code":  "VALIDATION_FAILED",
	})
}

// invalidInput answers a 400 for an error returned by one of the validators
// written to explain a rejected value to the caller (validateUpstreamURL,
// engine.ValidateRulesJSON, domain *.Validate, …). The detail is logged; the
// response carries the validator's sentence only when clientText judges it
// safe, and a generic message otherwise.
func invalidInput(c *fiber.Ctx, code string, err error) error {
	return writeClientError(c, code, err, "The request contains an invalid value.")
}

// writeClientError logs err and writes a 400 with a caller-safe message.
func writeClientError(c *fiber.Ctx, code string, err error, fallback string) error {
	slog.Info("request_rejected", "path", c.Path(), "status", fiber.StatusBadRequest, "code", code, "err", err)
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error": clientText(err, fallback),
		"code":  code,
	})
}

// internalMarkers identify error text produced by libraries rather than by a
// validator written for API clients: struct and field names, driver and
// decoder errors, developer paths, file-system and network errors, panics.
var internalMarkers = []string{
	"Key: '", "Error:Field", "json:", "cannot unmarshal", "Go struct", "struct field",
	"SQLSTATE", "pgx", "pgconn", "pq:", "sql:", "runtime error", "goroutine", "panic",
	"invalid memory", ".go:", "/Users/", "/home/", "/root/", "no such file",
	"permission denied", "dial tcp", "connection refused", "context deadline",
	"context canceled", "x509",
	// URLs can carry credentials (MaxMind's license_key is a query parameter).
	"://", "license_key", "token=", "password",
}

// clientText returns err's message when it reads as a sentence meant for an
// API client, and fallback otherwise. It is the one place where handler error
// text may reach a response body.
func clientText(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" || len(msg) > 300 || strings.ContainsAny(msg, "\n\r\t") {
		return fallback
	}
	for _, marker := range internalMarkers {
		if strings.Contains(msg, marker) {
			return fallback
		}
	}
	return msg
}

// ── Pagination ───────────────────────────────────────────────────────────

// List bounds. Configuration lists return at most maxListLimit rows per
// request, desired-state IP lists maxBlocklistLimit, feeds maxFeedLimit.
const (
	maxListLimit      = 100
	maxBlocklistLimit = 1000
	maxFeedLimit      = 1000
)

// pageRequest is a parsed ?limit=&offset= pair.
type pageRequest struct {
	Limit  int
	Offset int
}

// parsePage reads ?limit= and ?offset= for a list endpoint.
//
// An omitted limit returns up to maxLimit rows: callers written before the
// endpoint was paged asked for "the list" and still get it, now bounded, with
// "total" telling them when there is more. An explicit limit is clamped to
// [1, maxLimit] and a negative offset is treated as 0; clamping instead of
// rejecting keeps existing callers that send a larger limit working.
func parsePage(c *fiber.Ctx, maxLimit int) pageRequest {
	limit := maxLimit
	if strings.TrimSpace(c.Query("limit")) != "" {
		limit = c.QueryInt("limit", maxLimit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset := c.QueryInt("offset", 0)
	if offset < 0 {
		offset = 0
	}
	return pageRequest{Limit: limit, Offset: offset}
}

// pageOf returns the requested window of items, never nil.
func pageOf[T any](items []T, p pageRequest) []T {
	if p.Offset >= len(items) {
		return []T{}
	}
	end := p.Offset + p.Limit
	if end > len(items) {
		end = len(items)
	}
	return items[p.Offset:end]
}

// boundedLimit reads ?limit= for a "most recent N" feed: def when omitted or
// not positive, clamped to maxFeedLimit. Feeds have no offset; callers poll for the
// newest rows.
func boundedLimit(c *fiber.Ctx, def int) int {
	limit := c.QueryInt("limit", def)
	if limit < 1 {
		limit = def
	}
	if limit > maxFeedLimit {
		limit = maxFeedLimit
	}
	return limit
}

// isNotFoundOrInvalidID reports whether a lookup failed because the row does
// not exist or because the id cannot name a row at all (malformed UUID). Both
// are a 404 to the caller.
func isNotFoundOrInvalidID(err error) bool {
	if errors.Is(err, pgx.ErrNoRows) {
		return true
	}
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "22P02"
}
