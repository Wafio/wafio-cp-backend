package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/setup"
)

type AgentFetcher interface {
	BroadcastFetchSecurityData(components []string, force bool) int
	GetAgentComponentStatus() map[string]agentserver.AgentComponentInfo
	GetAgentComponentStatusPerAgent() []agentserver.AgentComponentReport
}

type GeoLookupReloader interface {
	Reload(path string) error
}

type GeoEnricherReloader interface {
	Reload(cityPath, asnPath string) error
}

type SecurityDataHandler struct {
	MalwareCredentials  *application.MalwareCredentials
	Repo                *repository.Repository
	Cfg                 *config.Config
	GeoLookupReloader   GeoLookupReloader
	GeoEnricherReloader GeoEnricherReloader
	AgentSrv            AgentFetcher
}

type securityComponentSpec struct {
	Component string
	Label     string
	Profile   string
	Path      string
}

type securityComponentStatus struct {
	Component  string `json:"component"`
	Label      string `json:"label"`
	Profile    string `json:"profile"`
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"`
}

type securityDataEvent struct {
	Type       string   `json:"type"`
	Total      int      `json:"total,omitempty"`
	Components []string `json:"components,omitempty"`
	Component  string   `json:"component,omitempty"`
	Label      string   `json:"label,omitempty"`
	Status     string   `json:"status,omitempty"`
	Message    string   `json:"message,omitempty"`
	SizeBytes  int64    `json:"size_bytes,omitempty"`
	Ok         bool     `json:"ok,omitempty"`
	Failed     int      `json:"failed,omitempty"`
	ElapsedMS  int64    `json:"elapsed_ms,omitempty"`
}

var canonicalSecurityComponents = []string{
	"geoip-country",
	"geoip-city",
	"geoip-asn",
	"firehol-level1",
	"firehol-level2",
	"ja4",
	"ua",
	"malware",
}

var fetchSecurityComponentOrder = []string{
	"geoip-country",
	"geoip-city",
	"geoip-asn",
	"firehol",
	"ja4",
	"ja3",
	"ua",
	"malware",
}

func (h *SecurityDataHandler) Status(c *fiber.Ctx) error {
	components := h.componentSpecs()
	statuses := make([]securityComponentStatus, 0, len(components))
	var lastUpdated time.Time

	// For agent-profile components, prefer the status reported by connected
	// agents over a local filesystem check (agent files live on the agent server,
	// not necessarily on the control plane).
	var agentStatus map[string]agentserver.AgentComponentInfo
	var agentReports []agentserver.AgentComponentReport
	if h.AgentSrv != nil {
		agentStatus = h.AgentSrv.GetAgentComponentStatus()
		agentReports = h.AgentSrv.GetAgentComponentStatusPerAgent()
	}

	for _, spec := range components {
		var exists bool
		var size int64
		var modifiedAt time.Time

		if spec.Profile == "both" {
			// Always check local CP filesystem for size/modifiedAt (files exist on CP).
			// Use agent-reported status for the exists flag when agents are connected.
			localExists, localSize, localModAt := componentFileState(spec.Path)
			size = localSize
			modifiedAt = localModAt
			if len(agentStatus) > 0 {
				info := agentStatus[spec.Component]
				exists = info.Exists || localExists
			} else {
				exists = localExists
			}
		} else if spec.Profile == "agent" && len(agentStatus) > 0 {
			// Agent-only components: use agent-reported exists/size/modifiedAt.
			info := agentStatus[spec.Component]
			exists = info.Exists
			size = info.SizeBytes
			if info.ModifiedAt != "" {
				if t, err := time.Parse(time.RFC3339, info.ModifiedAt); err == nil {
					modifiedAt = t
				}
			}
		} else {
			exists, size, modifiedAt = componentFileState(spec.Path)
		}

		if modifiedAt.After(lastUpdated) {
			lastUpdated = modifiedAt
		}
		statuses = append(statuses, securityComponentStatus{
			Component:  spec.Component,
			Label:      spec.Label,
			Profile:    spec.Profile,
			Path:       spec.Path,
			Exists:     exists,
			SizeBytes:  size,
			ModifiedAt: formatTimestamp(modifiedAt),
		})
	}

	// Build per-agent breakdown for multi-agent display in the UI.
	type agentComponentRow struct {
		Component  string `json:"component"`
		Label      string `json:"label"`
		Path       string `json:"path"`
		Exists     bool   `json:"exists"`
		SizeBytes  int64  `json:"size_bytes"`
		ModifiedAt string `json:"modified_at"`
	}
	type agentStatusReport struct {
		AgentName    string              `json:"agent_name"`
		CredentialID string              `json:"credential_id"`
		AgentKind    string              `json:"agent_kind"`
		Components   []agentComponentRow `json:"components"`
	}

	labelByComp := make(map[string]string, len(components))
	pathByComp := make(map[string]string, len(components))
	for _, s := range components {
		labelByComp[s.Component] = s.Label
		pathByComp[s.Component] = s.Path
	}

	agentStatusReports := make([]agentStatusReport, 0, len(agentReports))
	for _, r := range agentReports {
		rows := make([]agentComponentRow, 0, len(r.Components))
		for _, spec := range components {
			if spec.Profile != "agent" && spec.Profile != "both" {
				continue
			}
			// Only include components the agent actually reported.
			// This ensures host agents (which only report geoip-country) don't
			// show WAF-only components as "not installed".
			info, reported := r.Components[spec.Component]
			if !reported {
				continue
			}
			var modAt string
			if info.ModifiedAt != "" {
				if t, err := time.Parse(time.RFC3339, info.ModifiedAt); err == nil {
					modAt = formatTimestamp(t)
				}
			}
			// Use the agent's reported absolute path if available;
			// fall back to the CP-configured path.
			displayPath := info.Path
			if displayPath == "" {
				displayPath = pathByComp[spec.Component]
			}
			rows = append(rows, agentComponentRow{
				Component:  spec.Component,
				Label:      labelByComp[spec.Component],
				Path:       displayPath,
				Exists:     info.Exists,
				SizeBytes:  info.SizeBytes,
				ModifiedAt: modAt,
			})
		}
		agentStatusReports = append(agentStatusReports, agentStatusReport{
			AgentName:    r.AgentName,
			CredentialID: r.CredentialID,
			AgentKind:    r.AgentKind,
			Components:   rows,
		})
	}

	return c.JSON(fiber.Map{
		"components":    statuses,
		"last_updated":  formatTimestamp(lastUpdated),
		"agent_reports": agentStatusReports,
	})
}

// securityDataUpdateRequest is the POST body of an update run. Every field is
// optional; the same names are accepted as query parameters (components as a
// comma-separated list) for callers that send no body.
type securityDataUpdateRequest struct {
	Profile    string   `json:"profile"`
	Components []string `json:"components"`
	Force      bool     `json:"force"`
}

// UpdateMethodNotAllowed answers the retired GET form of the update. An update
// downloads and replaces security data, so it is a POST: a GET can be
// triggered by a prefetch, a crawler or an <img> tag.
//
//	GET /api/admin/security-data/update → 405
func (h *SecurityDataHandler) UpdateMethodNotAllowed(c *fiber.Ctx) error {
	c.Set("Allow", fiber.MethodPost)
	return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
		"error": "security-data update is a POST request",
		"code":  "METHOD_NOT_ALLOWED",
	})
}

// Update downloads the requested security-data components and streams the
// progress as server-sent events.
//
//	POST /api/admin/security-data/update  {"components": [...], "force": bool, "profile": ""}
func (h *SecurityDataHandler) Update(c *fiber.Ctx) error {
	var req securityDataUpdateRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
		}
	}
	rawProfile := req.Profile
	if rawProfile == "" {
		rawProfile = c.Query("profile")
	}
	rawComponents := strings.Join(req.Components, ",")
	if len(req.Components) == 0 {
		rawComponents = c.Query("components")
	}
	force := req.Force || parseBoolQuery(c.Query("force"))

	profile, err := parseSecurityProfile(rawProfile)
	if err != nil {
		return invalidInput(c, "INVALID_PROFILE", err)
	}

	components, err := requestedSecurityComponents(profile, rawComponents)
	if err != nil {
		return invalidInput(c, "INVALID_COMPONENT", err)
	}
	var malwareKey string
	if slices.Contains(components, "malware") && h.MalwareCredentials != nil {
		malwareKey, err = h.MalwareCredentials.Resolve(c.UserContext())
		if err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Unable to read MalwareBazaar credentials.", "code": "SERVICE_UNAVAILABLE"})
		}
	}
	fetchSteps := fetchStepsForComponents(components)
	requestedSet := make(map[string]bool, len(components))
	for _, component := range components {
		requestedSet[component] = true
	}

	actorID, _ := c.Locals(auth.UserIDKey).(string)
	clientIP := c.IP()
	userAgent := string(c.Request().Header.UserAgent())

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")
	c.Status(fiber.StatusOK)
	life := newSSELifetime(c)

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		send := func(eventType string, data any) {
			b, err := json.Marshal(data)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, b) // bufio errors are sticky; the flush reports a gone client
			_ = life.flush(w)
		}

		startedAt := time.Now()
		failed := 0
		send("start", securityDataEvent{Type: "start", Total: len(components), Components: components})

		for _, step := range fetchSteps {
			stepComponents := requestedComponentsForFetchStep(step, components)
			if len(stepComponents) == 0 {
				continue
			}
			for _, component := range stepComponents {
				send("downloading", securityDataEvent{
					Type:      "downloading",
					Component: component,
					Label:     securityComponentLabel(component),
					Message:   fmt.Sprintf("Updating %s...", securityComponentLabel(component)),
				})
			}

			cfg := setup.FetchConfig{
				Dir:               h.securityDataDir(),
				MaxMindLicenseKey: h.maxMindLicenseKey(),
				MalwareAuthKey:    malwareKey,
				Force:             force,
				Only:              []string{step},
				Log: func(format string, args ...any) {
					msg := strings.TrimSpace(fmt.Sprintf(format, args...))
					if msg == "" {
						return
					}
					for _, component := range stepComponents {
						send("log", securityDataEvent{
							Type:      "log",
							Component: component,
							Label:     securityComponentLabel(component),
							Message:   msg,
						})
					}
				},
			}

			results := setup.FetchAll(context.Background(), cfg)
			for _, result := range results {
				component := normalizeFetchedComponent(result.Component)
				if !requestedSet[component] {
					continue
				}

				label := securityComponentLabel(component)
				switch {
				case result.Skipped:
					send("skipped", securityDataEvent{
						Type:      "skipped",
						Component: component,
						Label:     label,
						Message:   "File already up-to-date",
						SizeBytes: result.Size,
					})
				case result.Err != nil:
					failed++
					// Fetch errors can quote the download URL, which for
					// MaxMind carries the license key: log the detail,
					// send only a caller-safe sentence.
					slog.Warn("security_data_download_failed", "component", component, "err", result.Err)
					send("error", securityDataEvent{
						Type:      "error",
						Component: component,
						Label:     label,
						Message:   "Download failed: " + clientText(result.Err, "see the control-plane log for details."),
					})
				default:
					send("done", securityDataEvent{
						Type:      "done",
						Component: component,
						Label:     label,
						Message:   fmt.Sprintf("Downloaded %s", humanSize(result.Size)),
						SizeBytes: result.Size,
					})
					if reloadMessage, reloadErr := h.reloadComponent(component); reloadErr != nil {
						failed++
						slog.Warn("security_data_reload_failed", "component", component, "err", reloadErr)
						send("error", securityDataEvent{
							Type:      "error",
							Component: component,
							Label:     label,
							Message:   "Hot-reload failed: " + clientText(reloadErr, "see the control-plane log for details."),
						})
					} else if reloadMessage != "" {
						send("log", securityDataEvent{Type: "log", Component: component, Message: reloadMessage})
					}
				}
			}
		}

		// Always broadcast to agents any component that agents also use (GeoIP, JA3,
		// UA, FireHOL) — regardless of the requested profile, because agents
		// need these files too.  filterAgentFetchSteps filters out CP-only steps.
		if h.AgentSrv != nil {
			broadcast := filterAgentFetchSteps(fetchSteps)
			if len(broadcast) > 0 {
				count := h.AgentSrv.BroadcastFetchSecurityData(broadcast, force)
				log.Printf("security data update: broadcast fetch command to %d agent(s) for %s", count, strings.Join(broadcast, ","))
				send("agents", securityDataEvent{
					Type:    "agents",
					Message: fmt.Sprintf("Broadcast update to %d connected agent(s)", count),
				})
			}
		}

		send("complete", securityDataEvent{
			Type:      "complete",
			Ok:        failed == 0,
			Failed:    failed,
			ElapsedMS: time.Since(startedAt).Milliseconds(),
			Message:   fmt.Sprintf("Update complete — %d failed", failed),
		})

		outcome := "success"
		if failed > 0 {
			outcome = "failure"
		}
		if h.Repo != nil && h.Repo.Audit != nil {
			target := strings.Join(components, ",")
			if len(target) > 64 {
				target = target[:64]
			}
			_ = h.Repo.Audit.LogSystem(context.Background(), repository.SystemAuditEvent{
				ActorUserID: actorID,
				Action:      "admin.security_data_updated",
				TargetType:  "security_data",
				TargetID:    target,
				Outcome:     outcome,
				HTTPStatus:  fiber.StatusOK,
				IP:          clientIP,
				UserAgent:   userAgent,
			})
		}
	})

	return nil
}

func (h *SecurityDataHandler) componentSpecs() []securityComponentSpec {
	return []securityComponentSpec{
		{Component: "geoip-country", Label: securityComponentLabel("geoip-country"), Profile: "both", Path: absPath(h.countryDBPath())},
		{Component: "geoip-city", Label: securityComponentLabel("geoip-city"), Profile: "both", Path: absPath(h.cityDBPath())},
		{Component: "geoip-asn", Label: securityComponentLabel("geoip-asn"), Profile: "both", Path: absPath(h.asnDBPath())},
		{Component: "firehol-level1", Label: securityComponentLabel("firehol-level1"), Profile: "agent", Path: absPath(filepath.Join(h.securityDataDir(), "firehol", "firehol_level1.netset"))},
		{Component: "firehol-level2", Label: securityComponentLabel("firehol-level2"), Profile: "agent", Path: absPath(filepath.Join(h.securityDataDir(), "firehol", "firehol_level2.netset"))},
		{Component: "ja4", Label: securityComponentLabel("ja4"), Profile: "both", Path: absPath(filepath.Join(h.securityDataDir(), "ja4", "ja4.txt"))},
		{Component: "ua", Label: securityComponentLabel("ua"), Profile: "both", Path: absPath(filepath.Join(h.securityDataDir(), "user-agents", "bot.txt"))},
		{Component: "malware", Label: securityComponentLabel("malware"), Profile: "both", Path: absPath(filepath.Join(h.securityDataDir(), "malware", "malware_hashes.txt"))},
	}
}

// absPath resolves p to an absolute path; returns p unchanged if resolution fails.
func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func (h *SecurityDataHandler) reloadComponent(component string) (string, error) {
	switch component {
	case "geoip-country":
		if h.GeoLookupReloader == nil {
			return "", nil
		}
		if err := h.GeoLookupReloader.Reload(h.countryDBPath()); err != nil {
			return "", err
		}
		return "Hot-reloaded country GeoIP database", nil
	case "geoip-city", "geoip-asn":
		if h.GeoEnricherReloader == nil {
			return "", nil
		}
		if err := h.GeoEnricherReloader.Reload(h.cityDBPath(), h.asnDBPath()); err != nil {
			return "", err
		}
		return "Hot-reloaded GeoIP city/ASN databases", nil
	case "ja4":
		engine.ReloadDefaultJA4()
		return "Hot-reloaded JA4 fingerprint rules", nil
	case "ua":
		engine.ReloadDefaultBadBotUA()
		return "Hot-reloaded bot User-Agent rules", nil
	case "malware":
		if err := engine.ReloadDefaultMalwareEngine(filepath.Join(h.securityDataDir(), "malware", "malware_hashes.txt")); err != nil {
			return "", err
		}
		return "Reloaded malware hash database", nil
	case "firehol-level1", "firehol-level2", "ja3":
		log.Printf("security data update: %s updated at %s", component, componentPath(component, h))
	}
	return "", nil
}

func (h *SecurityDataHandler) securityDataDir() string {
	return "security-data"
}

func (h *SecurityDataHandler) maxMindLicenseKey() string {
	if h.Cfg == nil {
		return ""
	}
	return strings.TrimSpace(h.Cfg.Geo.MaxMindLicenseKey)
}

func (h *SecurityDataHandler) countryDBPath() string {
	if h.Cfg != nil && strings.TrimSpace(h.Cfg.Geo.CountryDBPath) != "" {
		return strings.TrimSpace(h.Cfg.Geo.CountryDBPath)
	}
	return filepath.Join(h.securityDataDir(), "geoip", "country.mmdb")
}

func (h *SecurityDataHandler) cityDBPath() string {
	if h.Cfg != nil && strings.TrimSpace(h.Cfg.Geo.CityDBPath) != "" {
		return strings.TrimSpace(h.Cfg.Geo.CityDBPath)
	}
	return filepath.Join(h.securityDataDir(), "geoip", "city.mmdb")
}

func (h *SecurityDataHandler) asnDBPath() string {
	if h.Cfg != nil && strings.TrimSpace(h.Cfg.Geo.ASNDBPath) != "" {
		return strings.TrimSpace(h.Cfg.Geo.ASNDBPath)
	}
	return filepath.Join(h.securityDataDir(), "geoip", "asn.mmdb")
}

func parseSecurityProfile(raw string) (setup.Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return setup.ProfileAll, nil
	}
	profile := setup.Profile(raw)
	switch profile {
	case setup.ProfileControlPlane, setup.ProfileAgent, setup.ProfileAll:
		return profile, nil
	default:
		return "", fmt.Errorf("invalid profile")
	}
}

func requestedSecurityComponents(profile setup.Profile, raw string) ([]string, error) {
	requested := make(map[string]bool)
	if strings.TrimSpace(raw) == "" {
		for _, component := range defaultSecurityComponents(profile) {
			requested[component] = true
		}
	} else {
		for _, token := range strings.Split(raw, ",") {
			token = strings.TrimSpace(strings.ToLower(token))
			switch token {
			case "", "all":
				for _, component := range defaultSecurityComponents(profile) {
					requested[component] = true
				}
			case "geoip":
				requested["geoip-country"] = true
				requested["geoip-city"] = true
				requested["geoip-asn"] = true
			case "firehol":
				requested["firehol-level1"] = true
				requested["firehol-level2"] = true
			case "crs":
				// Legacy name: v1 downloaded a rule set under it. A client that
				// still names it is ignored, not refused.
			case "geoip-country", "geoip-city", "geoip-asn", "firehol-level1", "firehol-level2", "ja4", "ja3", "ua", "malware":
				requested[token] = true
			default:
				return nil, fmt.Errorf("invalid component %q", token)
			}
		}
	}

	components := make([]string, 0, len(requested))
	for _, component := range canonicalSecurityComponents {
		if requested[component] {
			components = append(components, component)
		}
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("no components selected")
	}
	return components, nil
}

func defaultSecurityComponents(profile setup.Profile) []string {
	switch profile {
	case setup.ProfileControlPlane:
		return []string{"geoip-country", "geoip-city", "geoip-asn", "ja4", "ua"}
	case setup.ProfileAgent, setup.ProfileAll:
		return append([]string(nil), canonicalSecurityComponents...)
	default:
		return []string{"geoip-country", "geoip-city", "geoip-asn", "ja4", "ua"}
	}
}

func fetchStepsForComponents(components []string) []string {
	requested := make(map[string]bool)
	for _, component := range components {
		requested[fetchStepForComponent(component)] = true
	}
	steps := make([]string, 0, len(requested))
	for _, step := range fetchSecurityComponentOrder {
		if requested[step] {
			steps = append(steps, step)
		}
	}
	return steps
}

func requestedComponentsForFetchStep(step string, components []string) []string {
	matched := make([]string, 0, len(components))
	for _, component := range components {
		if fetchStepForComponent(component) == step {
			matched = append(matched, component)
		}
	}
	return matched
}

func fetchStepForComponent(component string) string {
	switch component {
	case "firehol-level1", "firehol-level2":
		return "firehol"
	default:
		return component
	}
}

func filterAgentFetchSteps(steps []string) []string {
	agentSet := make(map[string]bool)
	for _, component := range setup.ProfileComponents(setup.ProfileAgent) {
		agentSet[component] = true
	}
	filtered := make([]string, 0, len(steps))
	for _, step := range steps {
		if agentSet[step] {
			filtered = append(filtered, step)
		}
	}
	return filtered
}

func securityComponentLabel(component string) string {
	switch component {
	case "geoip-country":
		return "GeoIP Country"
	case "geoip-city":
		return "GeoIP City"
	case "geoip-asn":
		return "GeoIP ASN"
	case "firehol-level1":
		return "FireHOL Level 1"
	case "firehol-level2":
		return "FireHOL Level 2"
	case "ja4":
		return "JA4 Fingerprints"
	case "ja3":
		return "JA3 (Legacy)"
	case "ua":
		return "Bot User Agents"
	case "malware":
		return "Malware Hashes"
	default:
		return component
	}
}

func normalizeFetchedComponent(component string) string {
	switch component {
	case "geoip/country.mmdb":
		return "geoip-country"
	case "geoip/city.mmdb":
		return "geoip-city"
	case "geoip/asn.mmdb":
		return "geoip-asn"
	case "firehol/firehol_level1.netset":
		return "firehol-level1"
	case "firehol/firehol_level2.netset":
		return "firehol-level2"
	case "malware-hashes", "malware-bloom":
		return "malware"
	default:
		return component
	}
}

func componentPath(component string, h *SecurityDataHandler) string {
	for _, spec := range h.componentSpecs() {
		if spec.Component == component {
			return spec.Path
		}
	}
	return component
}

func componentFileState(path string) (bool, int64, time.Time) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false, 0, time.Time{}
	}
	return true, info.Size(), info.ModTime().UTC()
}

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseBoolQuery(raw string) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	return raw == "1" || raw == "true" || raw == "yes"
}

func humanSize(size int64) string {
	if size <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}
