package handlers

import (
	"context"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/dashboard"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"github.com/wafio/wafio-cp-backend/shared/geo"
)

// GeoEnricher optionally enriches IP with city, ISO country, lat, lon, ISP. May be nil.
type GeoEnricher interface {
	Enrich(ip string) (city string, countryISO string, lat, lon float64, isp string)
}

// DashboardHandler serves dashboard API (logs, stats) backed by PostgreSQL/TimescaleDB.
type DashboardHandler struct {
	Repo        *repository.Repository
	GeoEnricher GeoEnricher
}

// ensureProject returns the project and ensures the current user owns it. On failure writes the response and returns nil.
func (h *DashboardHandler) ensureProject(c *fiber.Ctx) *repository.Project {
	p := ProjectIDParam{ID: c.Params("id")}
	if err := validate.Struct(&p); err != nil {
		_ = validationFailed(c, err)
		return nil
	}
	projectID := p.ID
	proj, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		apiErr := ResolveDBError(err, "project")
		_ = c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
		return nil
	}
	return proj
}

// parseTimeRange reads from_ts, to_ts from query (unix seconds). Defaults to last 24h if not set.
func parseTimeRange(c *fiber.Ctx) (fromTS, toTS int64) {
	now := time.Now().UTC().Unix()
	toTS = now
	fromTS = now - 86400 // 24h ago
	if s := c.Query("to_ts"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			toTS = n
		}
	}
	if s := c.Query("from_ts"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
			fromTS = n
		}
	}
	return fromTS, toTS
}

// Overview returns summary, by_action, and time_series for the project (single call for initial load).
// Query: from_ts, to_ts (unix sec; default last 24h), interval (hour=3600, day=86400; default 3600).
func (h *DashboardHandler) Overview(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	interval := 3600
	if s := c.Query("interval"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			interval = n
		}
	}
	if interval > 86400 {
		interval = 86400
	}
	return h.overviewFromAgentDecisions(c, proj.ID, fromTS, toTS, interval)
}

func (h *DashboardHandler) overviewFromAgentDecisions(c *fiber.Ctx, projectID string, fromTS, toTS int64, interval int) error {
	ctx := c.UserContext()
	summary, byAction, _, series, err := h.Repo.WAF.DashboardOverviewFromDecisions(ctx, projectID, fromTS, toTS, interval)
	if err != nil {
		log.Printf("dashboard Overview (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load monitoring data.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	byCountry := h.byCountryFromAgentDecisions(ctx, projectID, fromTS, toTS, "")
	out := fiber.Map{
		"summary": fiber.Map{
			"total":     summary.Total,
			"allow":     summary.Allow,
			"log":       summary.Log,
			"block":     summary.Block,
			"challenge": summary.Challenge,
		},
		"by_action":   byAction,
		"by_country":  byCountry,
		"time_series": series,
		"from_ts":     fromTS,
		"to_ts":       toTS,
		"data_source": "waf_agent",
	}
	return c.JSON(out)
}

// byCountryFromAgentDecisions buckets decisions by client country; action is
// an optional dashboard-vocabulary filter ("" = every action).
func (h *DashboardHandler) byCountryFromAgentDecisions(ctx context.Context, projectID string, fromTS, toTS int64, action string) []dashboard.Bucket {
	ipCounts, err := h.Repo.WAF.DecisionsCountByRemoteAddr(ctx, projectID, fromTS, toTS, action)
	if err != nil || len(ipCounts) == 0 {
		return []dashboard.Bucket{} // JSON [], never null
	}
	totals := make(map[string]int)
	for addr, cnt := range ipCounts {
		ip := geo.ParseClientIP(addr)
		cc := ""
		if h.GeoEnricher != nil && ip != "" {
			_, cc, _, _, _ = h.GeoEnricher.Enrich(ip)
		}
		if cc == "" {
			cc = "—"
		}
		totals[cc] += cnt
	}
	out := make([]dashboard.Bucket, 0, len(totals))
	for k, v := range totals {
		out = append(out, dashboard.Bucket{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// Logs returns paginated log entries.
// Query: from_ts, to_ts, action (allow|log|block), limit, offset, search (substring in uri).
func (h *DashboardHandler) Logs(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 20)
	offset := c.QueryInt("offset", 0)
	action := c.Query("action")
	search := c.Query("search")
	ctx := c.UserContext()

	total, rows, err := h.Repo.WAF.DecisionsLogsPage(ctx, proj.ID, fromTS, toTS, action, search, limit, offset)
	if err != nil {
		log.Printf("dashboard Logs (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load logs.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	logs := make([]dashboard.LogEntry, 0, len(rows))
	for _, r := range rows {
		ip := geo.ParseClientIP(r.RemoteAddr)
		cc := ""
		if h.GeoEnricher != nil && ip != "" {
			_, cc, _, _, _ = h.GeoEnricher.Enrich(ip)
		}
		catStr := strings.Join(r.Categories, ",")
		logs = append(logs, dashboard.LogEntry{
			ID:                    r.ID,
			ProjectID:             proj.ID,
			Ts:                    r.EventTime.Unix(),
			Action:                repository.MapWAFActionToDashboard(r.RawAction),
			Score:                 r.Score,
			Strength:              r.Strength,
			Categories:            catStr,
			AnalyzeMethod:         r.AnalyzeMethod,
			MatchDetail:           r.MatchDetail,
			MatchSource:           r.MatchSource,
			Method:                r.Method,
			URI:                   r.URI,
			Host:                  r.Host,
			RemoteAddr:            r.RemoteAddr,
			CountryCode:           cc,
			UserAgent:             r.UserAgent,
			BodyInjectionFields:   "",
			HeaderInjectionFields: "",
		})
	}
	return c.JSON(&dashboard.LogsResult{Total: total, Logs: logs})
}

// Summary returns total and per-action counts.
func (h *DashboardHandler) Summary(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	ctx := c.UserContext()
	summary, _, _, _, err := h.Repo.WAF.DashboardOverviewFromDecisions(ctx, proj.ID, fromTS, toTS, 3600)
	if err != nil {
		log.Printf("dashboard Summary (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load summary.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(dashboard.Summary{
		Total:     summary.Total,
		Allow:     summary.Allow,
		Log:       summary.Log,
		Block:     summary.Block,
		Challenge: summary.Challenge,
	})
}

// ByAction returns count per action.
func (h *DashboardHandler) ByAction(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	ctx := c.UserContext()
	_, byAction, _, _, err := h.Repo.WAF.DashboardOverviewFromDecisions(ctx, proj.ID, fromTS, toTS, 3600)
	if err != nil {
		log.Printf("dashboard ByAction (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load stats.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"by_action": byAction})
}

// ByCategory returns count per category.
func (h *DashboardHandler) ByCategory(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	ctx := c.UserContext()
	limit := c.QueryInt("limit", 50)
	buckets, err := h.Repo.WAF.DecisionsByCategory(ctx, proj.ID, fromTS, toTS, limit)
	if err != nil {
		log.Printf("dashboard ByCategory (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load stats.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"by_category": buckets})
}

// ByAnalyzeMethod returns count per analyze_method.
func (h *DashboardHandler) ByAnalyzeMethod(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	ctx := c.UserContext()
	rows, err := h.Repo.WAF.DecisionsByAnalyzeMethod(ctx, proj.ID, fromTS, toTS)
	if err != nil {
		log.Printf("dashboard ByAnalyzeMethod (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load stats.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	buckets := make([]dashboard.Bucket, 0, len(rows))
	for _, b := range rows {
		buckets = append(buckets, dashboard.Bucket{Key: b.Key, Count: b.Count})
	}
	return c.JSON(fiber.Map{"by_analyze_method": buckets})
}

// ByMethod returns count per HTTP method.
func (h *DashboardHandler) ByMethod(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	buckets, err := h.Repo.WAF.DecisionsByMethod(c.UserContext(), proj.ID, fromTS, toTS)
	if err != nil {
		log.Printf("dashboard ByMethod (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load stats.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"by_method": buckets})
}

// TimeSeries returns count per time bucket.
// Query: from_ts, to_ts, interval (seconds; default 3600 for hour, use 86400 for day).
func (h *DashboardHandler) TimeSeries(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	interval := 3600
	if s := c.Query("interval"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			interval = n
		}
	}
	ctx := c.UserContext()
	_, _, _, series, err := h.Repo.WAF.DashboardOverviewFromDecisions(ctx, proj.ID, fromTS, toTS, interval)
	if err != nil {
		log.Printf("dashboard TimeSeries (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load time series.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"time_series": series})
}

// TopURIs returns top URIs by count. Query: from_ts, to_ts, action (optional), limit (default 20).
func (h *DashboardHandler) TopURIs(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 20)
	action := c.Query("action")
	ctx := c.UserContext()
	buckets, err := h.Repo.WAF.DecisionsTopURIs(ctx, proj.ID, fromTS, toTS, action, limit)
	if err != nil {
		log.Printf("dashboard TopURIs (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load top URIs.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"top_uris": buckets})
}

// TopIPs returns top remote_addr by count. Query: from_ts, to_ts, action (optional), limit (default 20).
func (h *DashboardHandler) TopIPs(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 20)
	action := c.Query("action")
	ctx := c.UserContext()
	buckets, err := h.Repo.WAF.DecisionsTopIPs(ctx, proj.ID, fromTS, toTS, action, limit)
	if err != nil {
		log.Printf("dashboard TopIPs (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load top IPs.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	return c.JSON(fiber.Map{"top_ips": buckets})
}

// ByCountry returns count per country (negara asal IP). Query: from_ts, to_ts.
func (h *DashboardHandler) ByCountry(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	ctx := c.UserContext()
	buckets := h.byCountryFromAgentDecisions(ctx, proj.ID, fromTS, toTS, "")
	for i := range buckets {
		if buckets[i].Key == "" {
			buckets[i].Key = "—"
		}
	}
	return c.JSON(fiber.Map{"by_country": buckets})
}

// TopCountries returns top countries by request count. Query: from_ts, to_ts, action (optional), limit (default 20).
func (h *DashboardHandler) TopCountries(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 20)
	ctx := c.UserContext()
	// Country breakdown from agent decisions.
	all := h.byCountryFromAgentDecisions(ctx, proj.ID, fromTS, toTS, c.Query("action"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if len(all) > limit {
		all = all[:limit]
	}
	for i := range all {
		if all[i].Key == "" {
			all[i].Key = "—"
		}
	}
	return c.JSON(fiber.Map{"top_countries": all})
}

// GeoLocations returns distinct (remote_addr, country_code) with count for geo map.
// Optionally enriches with city, lat, lon, ISP when GeoEnricher is set.
// Query: from_ts, to_ts, limit (default 500, max 1000).
func (h *DashboardHandler) GeoLocations(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 500)
	if limit <= 0 {
		limit = 500
	}
	if limit > 1000 {
		limit = 1000
	}

	return h.geoLocationsFromAgentDecisions(c, proj.ID, fromTS, toTS, limit)
}

func (h *DashboardHandler) geoLocationsFromAgentDecisions(c *fiber.Ctx, projectID string, fromTS, toTS int64, limit int) error {
	ctx := c.UserContext()
	rows, err := h.Repo.WAF.DecisionsGeoAggregates(ctx, projectID, fromTS, toTS)
	if err != nil {
		log.Printf("dashboard GeoLocations (agent decisions): %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load geo locations.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	type agg struct {
		allow, log, block int
	}
	byIP := make(map[string]*agg)
	for _, r := range rows {
		a := byIP[r.RemoteAddr]
		if a == nil {
			a = &agg{}
			byIP[r.RemoteAddr] = a
		}
		switch r.Action {
		case "allow", "challenge":
			// GeoLocation has no challenge column; a challenged request
			// counts with allow, as it did before challenge was mapped.
			a.allow += r.Count
		case "block":
			a.block += r.Count
		default:
			a.log += r.Count
		}
	}
	type scored struct {
		addr  string
		a     *agg
		total int
	}
	var list []scored
	for addr, a := range byIP {
		t := a.allow + a.log + a.block
		list = append(list, scored{addr: addr, a: a, total: t})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].total > list[j].total })
	if len(list) > limit {
		list = list[:limit]
	}
	locs := make([]dashboard.GeoLocation, 0, len(list))
	for _, it := range list {
		ip := geo.ParseClientIP(it.addr)
		city, cc, lat, lon, isp := "", "", 0.0, 0.0, ""
		if h.GeoEnricher != nil && ip != "" {
			city, cc, lat, lon, isp = h.GeoEnricher.Enrich(ip)
		}
		if cc == "" {
			cc = "—"
		}
		locs = append(locs, dashboard.GeoLocation{
			RemoteAddr:  it.addr,
			CountryCode: cc,
			Count:       it.total,
			Allow:       it.a.allow,
			Log:         it.a.log,
			Block:       it.a.block,
			City:        city,
			Lat:         lat,
			Lon:         lon,
			ISP:         isp,
		})
	}
	for i := range locs {
		locs[i].CountryName = geo.CountryName(locs[i].CountryCode)
	}
	summary, _, _, _, err := h.Repo.WAF.DashboardOverviewFromDecisions(ctx, projectID, fromTS, toTS, 3600)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to load geo locations.",
			"code":  "DASHBOARD_ERROR",
		})
	}
	total := 0
	for _, loc := range locs {
		total += loc.Count
	}
	return c.JSON(fiber.Map{
		"locations":       locs,
		"total_requests":  total,
		"total_locations": len(locs),
		"total_allow":     summary.Allow,
		"total_log":       summary.Log,
		"total_block":     summary.Block,
	})
}

// AppGeoLocations is the app-scoped version of GeoLocations, filtered by :appId.
// Query params: from_ts, to_ts, limit (default 500, max 1000).
func (h *DashboardHandler) AppGeoLocations(c *fiber.Ctx) error {
	proj := h.ensureProject(c)
	if proj == nil {
		return nil
	}
	appID := c.Params("appId")
	if appID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "appId required"})
	}
	fromTS, toTS := parseTimeRange(c)
	limit := c.QueryInt("limit", 500)
	if limit <= 0 {
		limit = 500
	}
	if limit > 1000 {
		limit = 1000
	}
	ctx := c.UserContext()

	// Query via WAFRepo (PostgreSQL/TimescaleDB).
	rows, ferr := h.Repo.WAF.DecisionsGeoAggregatesForApp(ctx, proj.ID, appID, fromTS, toTS, limit)
	if ferr != nil {
		log.Printf("AppGeoLocations: %v", ferr)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "Failed to load geo locations.", "code": "DASHBOARD_ERROR"})
	}
	locs := make([]dashboard.GeoLocation, 0, len(rows))
	for _, row := range rows {
		ip := geo.ParseClientIP(row.RemoteAddr)
		city, cc, lat, lon, isp := "", "", 0.0, 0.0, ""
		if h.GeoEnricher != nil && ip != "" {
			city, cc, lat, lon, isp = h.GeoEnricher.Enrich(ip)
		}
		if cc == "" {
			cc = "—"
		}
		locs = append(locs, dashboard.GeoLocation{
			RemoteAddr:  row.RemoteAddr,
			CountryCode: cc,
			Count:       row.Count,
			Allow:       row.Allow,
			Log:         row.Log,
			Block:       row.Block,
			City:        city,
			Lat:         lat,
			Lon:         lon,
			ISP:         isp,
		})
	}

	for i := range locs {
		locs[i].CountryName = geo.CountryName(locs[i].CountryCode)
	}

	total := 0
	for _, loc := range locs {
		total += loc.Count
	}
	return c.JSON(fiber.Map{
		"locations":       locs,
		"total_requests":  total,
		"total_locations": len(locs),
	})
}
