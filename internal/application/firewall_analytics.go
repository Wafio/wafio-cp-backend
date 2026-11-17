package application

// FirewallAnalytics computes and caches the Firewall dashboard analytics and
// keeps them warm (moved from HostPolicyHandler in
// internal/adapter/http/handlers/host_policy.go).

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/geo"
	"golang.org/x/sync/singleflight"
)

// FirewallAnalytics owns the analytics and top-IP caches of the Firewall
// page. Store and PortPolicies are required; Geo is optional (no GeoIP
// enrichment without it). One value serves the whole process.
type FirewallAnalytics struct {
	Store        domain.FirewallAnalyticsStore
	Geo          domain.GeoEnricher
	PortPolicies domain.FirewallPortPolicyCounter

	analyticsCache sync.Map // key: string → firewallAnalyticsCacheEntry
	topIPsCache    sync.Map // key: string → firewallTopIPsCacheEntry
	topIPsGroup    singleflight.Group
	// viewed records when a project's firewall analytics were last
	// requested; the warmer only warms projects seen within
	// firewallWarmViewedWithin.
	viewed sync.Map // key: projectID → time.Time
}

// TopIPs returns the cached or freshly computed top source IPs JSON for the
// agents in a range (GET /api/projects/:id/host/firewall/top-ips).
func (s *FirewallAnalytics) TopIPs(ctx context.Context, projectID string, agentIDs []string, window FirewallRangeWindow, limit int) ([]byte, error) {
	key := firewallTopIPsCacheKey(projectID, agentIDs, window.Range, limit)
	return s.cachedFirewallTopIPs(ctx, key, firewallAnalyticsCacheTTL(window.Range), func(ctx context.Context) ([]byte, error) {
		return s.computeFirewallTopIPs(ctx, agentIDs, window, limit)
	})
}

// Analytics returns the cached or freshly computed analytics JSON for the
// agents in a range (GET /api/projects/:id/host/firewall/analytics). A
// computed result is cached for the range's TTL; an error is not cached.
func (s *FirewallAnalytics) Analytics(ctx context.Context, projectID string, agents []domain.EBPFAgent, window FirewallRangeWindow) ([]byte, error) {
	agentIDs := make([]string, len(agents))
	for i, agent := range agents {
		agentIDs[i] = agent.ID
	}
	sortedIDs := make([]string, len(agentIDs))
	copy(sortedIDs, agentIDs)
	sort.Strings(sortedIDs)
	cacheKey := projectID + ":" + strings.Join(sortedIDs, ",") + ":" + window.Range
	if v, ok := s.analyticsCache.Load(cacheKey); ok {
		entry := v.(firewallAnalyticsCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.data, nil
		}
	}

	jsonBytes, _, _, err := s.computeFirewallAnalytics(ctx, projectID, agents, window)
	if err != nil {
		return nil, err
	}

	s.analyticsCache.Store(cacheKey, firewallAnalyticsCacheEntry{
		data:      jsonBytes,
		expiresAt: time.Now().Add(firewallAnalyticsCacheTTL(window.Range)),
	})
	return jsonBytes, nil
}

// firewallWarmViewedWithin: a project nobody opened for this long is not
// pre-computed any more; its next view computes on demand.
const firewallWarmViewedWithin = time.Hour

// NoteViewed marks a project as recently viewed for the warmer.
func (s *FirewallAnalytics) NoteViewed(projectID string) {
	if projectID != "" {
		s.viewed.Store(projectID, time.Now())
	}
}

// recentlyViewedProjects returns projects viewed within the window and
// forgets the others.
func (s *FirewallAnalytics) recentlyViewedProjects(now time.Time) []string {
	var out []string
	s.viewed.Range(func(k, v any) bool {
		if now.Sub(v.(time.Time)) <= firewallWarmViewedWithin {
			out = append(out, k.(string))
		} else {
			s.viewed.Delete(k)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// evictExpiredFirewallCache drops expired analytics and top-IP entries. The
// caches used to keep every key ever computed -- one per project, agent set,
// range and limit -- for the life of the process.
func (s *FirewallAnalytics) evictExpiredFirewallCache(now time.Time) {
	s.analyticsCache.Range(func(k, v any) bool {
		if !now.Before(v.(firewallAnalyticsCacheEntry).expiresAt) {
			s.analyticsCache.Delete(k)
		}
		return true
	})
	s.topIPsCache.Range(func(k, v any) bool {
		if !now.Before(v.(firewallTopIPsCacheEntry).expiresAt) {
			s.topIPsCache.Delete(k)
		}
		return true
	})
}

type firewallAnalyticsCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type firewallTopIPsCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// Warm-range entries live for 10-45 minutes; shorter ranges expire sooner.
func firewallAnalyticsCacheTTL(rangeKey string) time.Duration {
	switch rangeKey {
	case "5m":
		return 2 * time.Minute
	case "15m":
		return 3 * time.Minute
	case "1h":
		return 5 * time.Minute
	case "24h":
		return 10 * time.Minute
	case "7d":
		return 20 * time.Minute
	case "30d":
		return 30 * time.Minute
	default: // "all"
		return 45 * time.Minute
	}
}

// FirewallRangeWindow is a parsed ?range= of the Firewall analytics routes:
// the current window start and the previous window of equal length.
type FirewallRangeWindow struct {
	Range        string
	SinceTs      int64
	PrevSinceTs  int64
	PrevBeforeTs int64
}

// ParseFirewallRange maps a ?range= value (5m, 15m, 1h, 24h, 7d, 30d; any
// other value is "all") to its window, relative to now.
func ParseFirewallRange(rangeStr string, now time.Time) FirewallRangeWindow {
	window := FirewallRangeWindow{Range: "all"}
	switch rangeStr {
	case "5m":
		window.Range = "5m"
		window.SinceTs = now.Add(-5 * time.Minute).Unix()
		window.PrevSinceTs = now.Add(-10 * time.Minute).Unix()
		window.PrevBeforeTs = window.SinceTs
	case "15m":
		window.Range = "15m"
		window.SinceTs = now.Add(-15 * time.Minute).Unix()
		window.PrevSinceTs = now.Add(-30 * time.Minute).Unix()
		window.PrevBeforeTs = window.SinceTs
	case "1h":
		window.Range = "1h"
		window.SinceTs = now.Add(-time.Hour).Unix()
		window.PrevSinceTs = now.Add(-2 * time.Hour).Unix()
		window.PrevBeforeTs = window.SinceTs
	case "24h":
		window.Range = "24h"
		window.SinceTs = now.Add(-24 * time.Hour).Unix()
		window.PrevSinceTs = now.Add(-48 * time.Hour).Unix()
		window.PrevBeforeTs = window.SinceTs
	case "7d":
		window.Range = "7d"
		window.SinceTs = now.Add(-7 * 24 * time.Hour).Unix()
		window.PrevSinceTs = now.Add(-14 * 24 * time.Hour).Unix()
		window.PrevBeforeTs = window.SinceTs
	case "30d":
		window.Range = "30d"
		window.SinceTs = now.Add(-30 * 24 * time.Hour).Unix()
		window.PrevSinceTs = now.Add(-60 * 24 * time.Hour).Unix()
		window.PrevBeforeTs = window.SinceTs
	}
	return window
}

// ZeroFirewallDropsSummary is the drops-per-reason map with every reason at 0.
func ZeroFirewallDropsSummary() map[string]int64 {
	return map[string]int64{
		"blocklist":   0,
		"syn_flood":   0,
		"rate_limit":  0,
		"geo_block":   0,
		"port_scan":   0,
		"port_policy": 0,
		"egress":      0,
		"other":       0,
	}
}

// MergeFirewallDropsSummary is ZeroFirewallDropsSummary with counts added
// in, so every reason the API documents is present whatever the store
// returned (an empty map without a host event store, a partial one from an
// older store). A reason outside the eight is counted as "other".
func MergeFirewallDropsSummary(counts map[string]int64) map[string]int64 {
	out := ZeroFirewallDropsSummary()
	for reason, n := range counts {
		if _, known := out[reason]; known {
			out[reason] += n
		} else {
			out["other"] += n
		}
	}
	return out
}

func firewallTopIPsCacheKey(projectID string, agentIDs []string, rangeKey string, limit int) string {
	sortedIDs := append([]string(nil), agentIDs...)
	sort.Strings(sortedIDs)
	return projectID + ":" + strings.Join(sortedIDs, ",") + ":" + rangeKey + ":" + strconv.Itoa(limit)
}

func (s *FirewallAnalytics) cachedFirewallTopIPs(ctx context.Context, key string, ttl time.Duration, compute func(context.Context) ([]byte, error)) ([]byte, error) {
	if v, ok := s.topIPsCache.Load(key); ok {
		entry := v.(firewallTopIPsCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.data, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := s.topIPsGroup.DoChan(key, func() (any, error) {
		if v, ok := s.topIPsCache.Load(key); ok {
			entry := v.(firewallTopIPsCacheEntry)
			if time.Now().Before(entry.expiresAt) {
				return entry.data, nil
			}
		}
		// The shared query must outlive the first caller when other callers wait.
		workCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		data, err := compute(workCtx)
		if err != nil {
			return nil, err
		}
		s.topIPsCache.Store(key, firewallTopIPsCacheEntry{data: data, expiresAt: time.Now().Add(ttl)})
		return data, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.([]byte), nil
	}
}

// computeFirewallTopIPs fetches and geo-enriches top attacker IPs.
func (s *FirewallAnalytics) computeFirewallTopIPs(ctx context.Context, agentIDs []string, window FirewallRangeWindow, limit int) ([]byte, error) {
	rows, err := s.Store.FirewallTopIPsRange(ctx, agentIDs, window.SinceTs, limit)
	if err != nil {
		return nil, err
	}
	return s.marshalFirewallTopIPs(rows, limit)
}

func (s *FirewallAnalytics) marshalFirewallTopIPs(rows []domain.FirewallTopIPRow, limit int) ([]byte, error) {
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []domain.FirewallTopIPRow{}
	}
	if s.Geo != nil {
		for i := range rows {
			_, cc, _, _, _ := s.Geo.Enrich(rows[i].SrcIP)
			rows[i].CountryCode = cc
			rows[i].CountryName = geo.CountryName(cc)
		}
	}
	return json.Marshal(map[string]any{"ips": rows, "count": len(rows)})
}

// computeFirewallAnalytics runs all analytics queries in parallel for the given
// is suitable for direct caching and serving.
func (s *FirewallAnalytics) computeFirewallAnalytics(ctx context.Context, projectID string, agents []domain.EBPFAgent, window FirewallRangeWindow) ([]byte, []domain.FirewallTopIPRow, bool, error) {
	agentIDs := make([]string, len(agents))
	for i, a := range agents {
		agentIDs[i] = a.ID
	}

	var (
		dropsCurrent map[string]int64
		dropsPrev    map[string]int64
		uniqueIPs    int64
		peakHours    [24]int64
		rawTopIPs    []domain.FirewallTopIPRow
		topIPsLoaded bool
		activeRules  int
		mu           sync.Mutex
		wg           sync.WaitGroup
	)
	dropsCurrent = ZeroFirewallDropsSummary()
	dropsPrev = ZeroFirewallDropsSummary()

	if len(agentIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, e := s.Store.FirewallDropsSummaryRange(ctx, agentIDs, window.SinceTs, 0); e == nil {
				mu.Lock()
				dropsCurrent = MergeFirewallDropsSummary(r)
				mu.Unlock()
			}
		}()

		if window.Range != "all" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if r, e := s.Store.FirewallDropsSummaryRange(ctx, agentIDs, window.PrevSinceTs, window.PrevBeforeTs); e == nil {
					mu.Lock()
					dropsPrev = MergeFirewallDropsSummary(r)
					mu.Unlock()
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, e := s.Store.FirewallUniqueIPCount(ctx, agentIDs, window.SinceTs); e == nil {
				mu.Lock()
				uniqueIPs = v
				mu.Unlock()
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, e := s.Store.FirewallPeakHours(ctx, agentIDs, window.SinceTs); e == nil {
				mu.Lock()
				peakHours = v
				mu.Unlock()
			}
		}()

		if s.Geo != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ips, e := s.Store.FirewallTopIPsRange(ctx, agentIDs, window.SinceTs, 100); e == nil {
					mu.Lock()
					rawTopIPs = ips
					topIPsLoaded = ips != nil
					mu.Unlock()
				}
			}()
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		total := 0
		var innerWg sync.WaitGroup
		var innerMu sync.Mutex
		for _, agent := range agents {
			innerWg.Add(1)
			go func(id string) {
				defer innerWg.Done()
				if n, e := s.PortPolicies.PortPolicyCount(ctx, id); e == nil {
					innerMu.Lock()
					total += n
					innerMu.Unlock()
				}
			}(agent.ID)
		}
		innerWg.Wait()
		mu.Lock()
		activeRules = total
		mu.Unlock()
	}()

	wg.Wait()

	var totalCurrent, totalPrev int64
	for _, v := range dropsCurrent {
		totalCurrent += v
	}
	for _, v := range dropsPrev {
		totalPrev += v
	}

	type countryEntry struct {
		Code  string  `json:"code"`
		Name  string  `json:"name"`
		Count int64   `json:"count"`
		Pct   float64 `json:"pct"`
	}
	attackOrigins := make([]countryEntry, 0)
	countriesCount := 0
	if len(rawTopIPs) > 0 {
		countryMap := make(map[string]int64)
		for _, ip := range rawTopIPs {
			_, cc, _, _, _ := s.Geo.Enrich(ip.SrcIP)
			if cc == "" {
				cc = "XX"
			}
			countryMap[cc] += int64(ip.Total)
		}
		for cc := range countryMap {
			if cc != "XX" && cc != "ZZ" && cc != "" {
				countriesCount++
			}
		}
		if countriesCount == 0 && len(countryMap) > 0 {
			countriesCount = len(countryMap)
		}
		for cc, cnt := range countryMap {
			pct := 0.0
			if totalCurrent > 0 {
				pct = float64(cnt) / float64(totalCurrent) * 100
			}
			name := geo.CountryName(cc)
			if name == "" {
				if cc == "XX" || cc == "ZZ" {
					name = "Unknown / Private"
				} else {
					name = cc
				}
			}
			attackOrigins = append(attackOrigins, countryEntry{
				Code:  cc,
				Name:  name,
				Count: cnt,
				Pct:   pct,
			})
		}
		sort.Slice(attackOrigins, func(i, j int) bool { return attackOrigins[i].Count > attackOrigins[j].Count })
		if len(attackOrigins) > 15 {
			attackOrigins = attackOrigins[:15]
		}
	}

	const livenessWindow = 90 * time.Second
	type agentInfo struct {
		ID           string     `json:"id"`
		Name         string     `json:"name"`
		Online       bool       `json:"online"`
		LastSeen     *time.Time `json:"last_seen"`
		RegisteredAt time.Time  `json:"registered_at"`
	}
	agentInfoList := make([]agentInfo, 0, len(agents))
	for _, agent := range agents {
		agentInfoList = append(agentInfoList, agentInfo{
			ID:           agent.ID,
			Name:         agent.Name,
			Online:       agent.LastSeen != nil && time.Since(*agent.LastSeen) <= livenessWindow,
			LastSeen:     agent.LastSeen,
			RegisteredAt: agent.CreatedAt,
		})
	}

	var sinceOut *time.Time
	if window.SinceTs > 0 {
		t := time.Unix(window.SinceTs, 0).UTC()
		sinceOut = &t
	}

	data, err := json.Marshal(map[string]any{
		"range":           window.Range,
		"since":           sinceOut,
		"drops_current":   dropsCurrent,
		"drops_previous":  dropsPrev,
		"total_current":   totalCurrent,
		"total_previous":  totalPrev,
		"unique_ips":      uniqueIPs,
		"countries_count": countriesCount,
		"active_rules":    activeRules,
		"attack_origins":  attackOrigins,
		"peak_hours":      peakHours,
		"agents":          agentInfoList,
	})
	return data, rawTopIPs, topIPsLoaded, err
}

// warmRanges are the ranges pre-computed by the cache warmer on startup.
var warmRanges = []string{"all", "24h", "7d"}

func refreshFirewallWarmRanges(ranges []string, refresh func(string)) {
	// The 24h and 7d TTLs expire together; concurrent refreshes overlap
	// costly top-IP scans and create a short CPU peak. Stagger each range.
	for i, rangeKey := range ranges {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		refresh(rangeKey)
	}
}

// StartFirewallCacheWarmer keeps the analytics cache warm for projects whose
// firewall page was opened within the last hour, refreshing before cached
// entries expire, and evicts expired entries. It used to recompute
// three ranges for every project in the database every five minutes.
func (s *FirewallAnalytics) StartFirewallCacheWarmer(ctx context.Context) {
	warm := func() {
		s.evictExpiredFirewallCache(time.Now())
		projects := s.recentlyViewedProjects(time.Now())
		if len(projects) == 0 {
			return
		}
		now := time.Now().UTC()
		for _, projectID := range projects {
			agents, err := s.Store.ListAgentsByProject(ctx, projectID)
			if err != nil || len(agents) == 0 {
				continue
			}
			agentIDs := make([]string, len(agents))
			for i, a := range agents {
				agentIDs[i] = a.ID
			}
			sort.Strings(agentIDs)
			keyPrefix := projectID + ":" + strings.Join(agentIDs, ",") + ":"

			refreshFirewallWarmRanges(warmRanges, func(rangeKey string) {
				cacheKey := keyPrefix + rangeKey
				// Skip if still warm.
				if v, ok := s.analyticsCache.Load(cacheKey); ok {
					if time.Now().Before(v.(firewallAnalyticsCacheEntry).expiresAt) {
						return
					}
				}
				window := ParseFirewallRange(rangeKey, now)
				jsonBytes, rawTopIPs, topIPsLoaded, err := s.computeFirewallAnalytics(ctx, projectID, agents, window)
				if err == nil {
					s.analyticsCache.Store(cacheKey, firewallAnalyticsCacheEntry{
						data:      jsonBytes,
						expiresAt: time.Now().Add(firewallAnalyticsCacheTTL(rangeKey)),
					})
				}
				// Reuse the analytics query for both the API default and UI limits.
				var missingLimits []int
				for _, limit := range []int{20, 50} {
					topKey := keyPrefix + rangeKey + ":" + strconv.Itoa(limit)
					if tv, ok := s.topIPsCache.Load(topKey); ok && time.Now().Before(tv.(firewallTopIPsCacheEntry).expiresAt) {
						continue
					}
					missingLimits = append(missingLimits, limit)
				}
				if len(missingLimits) == 0 {
					return
				}
				topRows := rawTopIPs
				if !topIPsLoaded {
					topRows, err = s.Store.FirewallTopIPsRange(ctx, agentIDs, window.SinceTs, 50)
					if err != nil {
						return
					}
				}
				for _, limit := range missingLimits {
					topKey := keyPrefix + rangeKey + ":" + strconv.Itoa(limit)
					topBytes, terr := s.marshalFirewallTopIPs(topRows, limit)
					if terr == nil {
						s.topIPsCache.Store(topKey, firewallTopIPsCacheEntry{
							data:      topBytes,
							expiresAt: time.Now().Add(firewallAnalyticsCacheTTL(rangeKey)),
						})
					}
				}
			})
		}
	}

	go func() {
		// Initial warm: wait a few seconds for server dependencies to settle.
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		warm()
		// Refresh at half the shortest warm-range TTL (24h = 10min → refresh every 5min).
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				warm()
			}
		}
	}()
}
