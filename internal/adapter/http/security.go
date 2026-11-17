package httpadapter

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

func ApplySecurityMiddleware(app *fiber.App, cfg *config.Config) {
	if app == nil {
		return
	}
	if cfg != nil && cfg.Server.CORSEnabled {
		allowOrigins := strings.TrimSpace(cfg.Server.CORSAllowOrigins)
		if allowOrigins == "" {
			allowOrigins = "http://localhost:5173"
			log.Printf("[SECURITY WARNING] server.cors_enabled=true but server.cors_allow_origins is empty; defaulting to %s", allowOrigins)
		}
		allowMethods := strings.TrimSpace(cfg.Server.CORSAllowMethods)
		if allowMethods == "" {
			allowMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
		}
		allowHeaders := strings.TrimSpace(cfg.Server.CORSAllowHeaders)
		if allowHeaders == "" {
			allowHeaders = "Origin,Content-Type,Accept,Authorization"
		}
		app.Use(cors.New(cors.Config{
			AllowOrigins:     allowOrigins,
			AllowMethods:     allowMethods,
			AllowHeaders:     allowHeaders,
			ExposeHeaders:    strings.TrimSpace(cfg.Server.CORSExposeHeaders),
			AllowCredentials: cfg.Server.CORSAllowCredentials,
			MaxAge:           cfg.Server.CORSMaxAgeSec,
		}))
	}

	securityHeadersEnabled := true
	if cfg != nil {
		securityHeadersEnabled = cfg.Server.SecurityHeadersEnabled
	}
	if securityHeadersEnabled {
		app.Use(helmet.New(helmet.Config{
			// unsafe-none allows the dashboard to load external resources (map tiles, fonts, etc.)
			CrossOriginEmbedderPolicy: "unsafe-none",
			// cross-origin allows embedded iframes and external resources to load
			CrossOriginOpenerPolicy:   "same-origin-allow-popups",
			CrossOriginResourcePolicy: "cross-origin",
			// CSP whitelists exactly the external origins the dashboard uses:
			//   - Google Fonts (fonts.googleapis.com / fonts.gstatic.com)
			//   - Map tiles: OpenStreetMap + CARTO basemaps; Leaflet CSS (unpkg)
			// The dashboard loads no analytics (Google Analytics removed
			// 2026-10-16), so scripts and connections are same-origin only.
			// 'unsafe-inline' is required for SvelteKit's hydration script/styles
			// and the theme and chunk-reload bootstraps in app.html; external
			// script origins are locked down, so injected third-party
			// <script src> is blocked. Tighten to nonces if SvelteKit CSP nonce
			// support is wired later.
			ContentSecurityPolicy: "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline'; " +
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com https://services.arcgisonline.com https://wafio.cloud; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
		}))
	}
}
