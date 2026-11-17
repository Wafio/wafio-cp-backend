package handlers

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// configForReader prepares a WAF rules JSON for a config read.
// Callers below member (viewers) get the credential-bearing fields —
// siem.webhook_url, challenge.secret_key, path-exception AES keys — blanked;
// members and owners, who may edit and save the config, get it unchanged.
// The returned map carries "secrets_redacted" and "<field>_set" flags, so a
// viewer still sees whether a webhook, captcha secret or AES key is set.
// The legacy keys of a v1 document are rewritten (engine.NormalizeRulesJSON), so the
// editor shows what the next save stores; the stored document is not changed.
func configForReader(c *fiber.Ctx, raw []byte) (json.RawMessage, fiber.Map) {
	raw, _ = engine.NormalizeRulesJSON(raw)
	redacted, found := domain.RedactWAFConfigSecrets(raw)
	flags := fiber.Map{
		"secrets_redacted":         false,
		"webhook_url_set":          found.WebhookURLSet,
		"challenge_secret_key_set": found.ChallengeSecretKeySet,
		"aes_keys_set":             found.AESKeysSet,
	}
	if canReadSecrets(c) {
		return json.RawMessage(raw), flags
	}
	flags["secrets_redacted"] = true
	return json.RawMessage(redacted), flags
}

// canReadSecrets: members and owners (admins act as owner) see configured
// credentials; viewers do not.
func canReadSecrets(c *fiber.Ctx) bool {
	role, _ := c.Locals("project_role").(string)
	return role == "member" || role == "owner"
}

// appForReader redacts an app for a caller below member: proxy_config
// header values blanked (names kept) and userinfo stripped from upstream_url.
func appForReader(c *fiber.Ctx, app *repository.App) {
	if app == nil || canReadSecrets(c) {
		return
	}
	app.SecretsRedacted = true
	app.ProxyConfig, app.ProxyHeaderValuesSet = domain.RedactProxyHeaderValues(app.ProxyConfig)
	if app.UpstreamURL != nil {
		stripped := domain.StripURLUserinfo(*app.UpstreamURL)
		app.UpstreamURL = &stripped
	}
}

// routeForReader is appForReader for an agent route row.
func routeForReader(c *fiber.Ctx, route *repository.AgentRouteRow) {
	if route == nil || canReadSecrets(c) {
		return
	}
	route.SecretsRedacted = true
	route.ProxyConfig, route.ProxyHeaderValuesSet = domain.RedactProxyHeaderValues(route.ProxyConfig)
	route.Upstream = domain.StripURLUserinfo(route.Upstream)
}

// withFlags copies flags into m and returns m.
func withFlags(m, flags fiber.Map) fiber.Map {
	for k, v := range flags {
		m[k] = v
	}
	return m
}
