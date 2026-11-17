package application

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/fsstat"
)

// Database size monitoring: the size against an optional
// administrator budget, the filesystem holding the database where the
// control plane can read it, a growth estimate and a projection. A level
// that rises is logged and mailed to the system administrators (once per
// level per 24 h, only with a mail server in force).

const (
	defaultSizeCheckInterval = 10 * time.Minute
	// SizeWarningRatio and SizeCriticalRatio are the alert levels, of the
	// budget or of the filesystem.
	SizeWarningRatio  = 0.80
	SizeCriticalRatio = 0.95
	// alertMailEvery bounds the emails per level.
	alertMailEvery = 24 * time.Hour
	// The observed growth (no TimescaleDB) needs samples spanning
	// minObservedSpan; samples older than sampleWindow are dropped.
	minObservedSpan = 6 * time.Hour
	sampleWindow    = 24 * time.Hour
	// Budget bounds in bytes (0.1 GB – 1,000,000 GB).
	minBudgetBytes = 100_000_000
	maxBudgetBytes = 1_000_000 * 1_000_000_000
	// projectionHorizonDays caps "full in N days".
	projectionHorizonDays = 3650
)

// Size levels.
const (
	SizeLevelNone     = "none"
	SizeLevelOK       = "ok"
	SizeLevelWarning  = "warning"
	SizeLevelCritical = "critical"
)

// FilesystemStatus is the free space of the disk holding the database, when
// the control plane can read it.
type FilesystemStatus struct {
	Known      bool     `json:"known"`
	Path       string   `json:"path,omitempty"`
	FreeBytes  *int64   `json:"free_bytes"`
	TotalBytes *int64   `json:"total_bytes"`
	UsedRatio  *float64 `json:"used_ratio"`
	Reason     string   `json:"reason"`
}

// DBSizeStatus is the database size check.
type DBSizeStatus struct {
	SizeBytes          *int64           `json:"size_bytes"`
	BudgetBytes        *int64           `json:"budget_bytes"`
	UsedRatio          *float64         `json:"used_ratio"`
	Level              string           `json:"level"`
	LevelReason        string           `json:"level_reason"`
	WarningRatio       float64          `json:"warning_ratio"`
	CriticalRatio      float64          `json:"critical_ratio"`
	IngestBytesPerDay  *float64         `json:"ingest_bytes_per_day"`
	GrowthBytesPerDay  *float64         `json:"growth_bytes_per_day"`
	GrowthSource       string           `json:"growth_source"`
	ProjectedSizeBytes *int64           `json:"projected_size_bytes"`
	DaysUntilFull      *float64         `json:"days_until_full"`
	Projection         string           `json:"projection"`
	Filesystem         FilesystemStatus `json:"filesystem"`
	CheckedAt          *time.Time       `json:"checked_at"`
}

// SizeAlert is GET /api/admin/storage/alert (the cached last check).
type SizeAlert struct {
	Level               string     `json:"level"`
	LevelReason         string     `json:"level_reason"`
	SizeBytes           *int64     `json:"size_bytes"`
	BudgetBytes         *int64     `json:"budget_bytes"`
	UsedRatio           *float64   `json:"used_ratio"`
	FilesystemUsedRatio *float64   `json:"filesystem_used_ratio"`
	DaysUntilFull       *float64   `json:"days_until_full"`
	CheckedAt           *time.Time `json:"checked_at"`
}

type sizeSample struct {
	At    time.Time
	Bytes int64
}

type alertState struct {
	Level string `json:"level"`
	// Mailed is the highest level mailed in the current episode (reset
	// when the level falls below it).
	Mailed string               `json:"mailed,omitempty"`
	Sent   map[string]time.Time `json:"sent,omitempty"`
}

func levelRank(l string) int {
	switch l {
	case SizeLevelWarning:
		return 1
	case SizeLevelCritical:
		return 2
	}
	return 0
}

func ratioLevel(r float64) string {
	switch {
	case r >= SizeCriticalRatio:
		return SizeLevelCritical
	case r >= SizeWarningRatio:
		return SizeLevelWarning
	}
	return SizeLevelOK
}

// databaseIsLocal: a Unix socket path, an empty host (libpq's local
// default), localhost or a loopback address.
func databaseIsLocal(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" || strings.HasPrefix(h, "/") || strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// filesystem reads the free space of the database's data directory. It is
// reported only when every step holds: the database is on this host, its
// role may read data_directory (superuser or pg_read_all_settings), the
// control plane can statfs that path, and the filesystem is at least as
// large as the database (a same-named path on the wrong disk, e.g. a
// database in a container, is not reported).
func (s *Storage) filesystem(ctx context.Context, dbSize int64) FilesystemStatus {
	usage := s.FSUsage
	if usage == nil {
		if !fsstat.Supported {
			return FilesystemStatus{Reason: "Free disk space cannot be read on this platform."}
		}
		usage = fsstat.Usage
	}
	if !databaseIsLocal(s.DatabaseHost) {
		return FilesystemStatus{Reason: "The database runs on another host, so the control plane cannot see its disk. Watch that host's disk directly; the budget below still applies."}
	}
	dir, err := s.Store.DataDirectory(ctx)
	if err != nil || strings.TrimSpace(dir) == "" {
		return FilesystemStatus{Reason: "The database role may not read the data directory setting, so the disk holding the database is unknown. " +
			"Grant it pg_read_all_settings (GRANT pg_read_all_settings TO <role>) to show free disk space."}
	}
	free, total, err := usage(dir)
	if err != nil {
		return FilesystemStatus{Path: dir, Reason: "The data directory " + dir + " is not reachable from the control plane (another container, host or user), so free disk space is unknown."}
	}
	if total == 0 || total > math.MaxInt64 || free > total || int64(total) < dbSize {
		return FilesystemStatus{Path: dir, Reason: "The filesystem at " + dir + " on this host does not hold the database (it is smaller than the database), so free disk space is unknown."}
	}
	f, t := int64(free), int64(total)
	used := round4(float64(t-f) / float64(t))
	return FilesystemStatus{Known: true, Path: dir, FreeBytes: &f, TotalBytes: &t, UsedRatio: &used}
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }

// sizeStatus computes the database size status from the table rows and
// caches it (and the rows, for the metrics).
func (s *Storage) sizeStatus(ctx context.Context, tables []TableRetentionView, now time.Time, sample bool) (DBSizeStatus, error) {
	size, err := s.Store.DatabaseSize(ctx)
	if err != nil {
		return DBSizeStatus{}, err
	}
	budget, err := s.loadBudget(ctx)
	if err != nil {
		return DBSizeStatus{}, err
	}
	fs := s.filesystem(ctx, size)

	// Only the periodic check records a growth sample, so page reads do not
	// skew the observed growth.
	s.state.Lock()
	if sample {
		s.samples = appendSample(s.samples, sizeSample{At: now, Bytes: size}, now)
	}
	samples := append([]sizeSample(nil), s.samples...)
	s.state.Unlock()

	st := computeSizeStatus(size, budget, fs, tables, samples, now)
	s.state.Lock()
	s.last = &st
	s.tables = tables
	s.state.Unlock()
	return st, nil
}

func appendSample(samples []sizeSample, x sizeSample, now time.Time) []sizeSample {
	samples = append(samples, x)
	cut := 0
	for cut < len(samples) && now.Sub(samples[cut].At) > sampleWindow {
		cut++
	}
	return samples[cut:]
}

// computeSizeStatus is the pure part of the size check.
func computeSizeStatus(size, budget int64, fs FilesystemStatus, tables []TableRetentionView, samples []sizeSample, now time.Time) DBSizeStatus {
	at := now
	st := DBSizeStatus{
		SizeBytes: &size, Level: SizeLevelNone, WarningRatio: SizeWarningRatio, CriticalRatio: SizeCriticalRatio,
		GrowthSource: "unknown", Projection: "unknown", Filesystem: fs, CheckedAt: &at,
	}
	if budget > 0 {
		b := budget
		r := round4(float64(size) / float64(budget))
		st.BudgetBytes, st.UsedRatio = &b, &r
		st.Level, st.LevelReason = ratioLevel(r), "budget"
	}
	if fs.Known && fs.UsedRatio != nil {
		l := ratioLevel(*fs.UsedRatio)
		if st.Level == SizeLevelNone || levelRank(l) > levelRank(st.Level) {
			st.Level = l
			if levelRank(l) > 0 || st.LevelReason == "" {
				st.LevelReason = "filesystem"
			}
		}
	}
	if st.Level == SizeLevelOK {
		st.LevelReason = ""
	}

	// Growth from the hypertables' chunks: each table adds its daily
	// ingest until it spans its retention, then retention drops as much as
	// arrives.
	type part struct{ perDay, remaining float64 }
	var parts []part
	var ingest float64
	for _, t := range tables {
		if t.IngestBytesPerDay == nil {
			continue
		}
		parts = append(parts, part{*t.IngestBytesPerDay, t.remainingDays})
		ingest += *t.IngestBytesPerDay
	}
	capacity := float64(0)
	if budget > 0 {
		capacity = float64(budget)
	}
	if fs.Known && fs.FreeBytes != nil {
		// The disk fills when the free space is used up.
		if c := float64(size + *fs.FreeBytes); capacity == 0 || c < capacity {
			capacity = c
		}
	}

	if len(parts) > 0 {
		st.GrowthSource = "chunks"
		in := math.Round(ingest)
		st.IngestBytesPerDay = &in
		var growth float64
		projected := float64(size)
		unbounded := false
		for _, p := range parts {
			if p.remaining > 0 {
				growth += p.perDay
			}
			if math.IsInf(p.remaining, 1) {
				unbounded = unbounded || p.perDay > 0
			} else {
				projected += p.perDay * p.remaining
			}
		}
		g := math.Round(growth)
		st.GrowthBytesPerDay = &g
		if !unbounded {
			ps := int64(math.Round(projected))
			st.ProjectedSizeBytes = &ps
		}
		if capacity > 0 {
			st.Projection, st.DaysUntilFull = projectFull(float64(size), capacity, func(d float64) float64 {
				v := float64(size)
				for _, p := range parts {
					v += p.perDay * math.Min(d, p.remaining)
				}
				return v
			})
		}
		return st
	}

	// No chunks to estimate from (plain tables): the growth observed in
	// this process's samples, once they span minObservedSpan.
	if len(samples) >= 2 {
		first, last := samples[0], samples[len(samples)-1]
		if span := last.At.Sub(first.At); span >= minObservedSpan {
			g := math.Round(float64(last.Bytes-first.Bytes) / days(span))
			st.GrowthBytesPerDay, st.GrowthSource = &g, "observed"
			if capacity > 0 {
				st.Projection, st.DaysUntilFull = projectFull(float64(size), capacity, func(d float64) float64 {
					return float64(size) + g*d
				})
			}
		}
	}
	return st
}

// projectFull finds the first day the projected size reaches capacity
// (bisection over a non-decreasing projection; "stable" when it never does
// within the horizon).
func projectFull(size, capacity float64, at func(days float64) float64) (string, *float64) {
	if size >= capacity {
		z := 0.0
		return "fills", &z
	}
	if at(projectionHorizonDays) < capacity {
		return "stable", nil
	}
	lo, hi := 0.0, float64(projectionHorizonDays)
	for i := 0; i < 60 && hi-lo > 0.01; i++ {
		mid := (lo + hi) / 2
		if at(mid) >= capacity {
			hi = mid
		} else {
			lo = mid
		}
	}
	d := math.Round(hi*10) / 10
	return "fills", &d
}

// CheckSize runs the background size check: it refreshes the cached status
// and raises an alert when the level rises.
func (s *Storage) CheckSize(ctx context.Context) {
	ts, err := s.Store.TimescaleInfo(ctx)
	if err != nil {
		slog.Warn("database size check failed", "err", err)
		return
	}
	saved, err := s.loadRetention(ctx)
	if err != nil {
		slog.Warn("database size check failed", "err", err)
		return
	}
	now := s.now()
	var tables []TableRetentionView
	for _, t := range domain.RetentionTables {
		st, err := s.Store.TableStats(ctx, t, false)
		if err != nil {
			slog.Warn("database size check failed", "table", t.Name, "err", err)
			return
		}
		tables = append(tables, s.tableView(t, ts, st, saved.Tables, now))
	}
	status, err := s.sizeStatus(ctx, tables, now, true)
	if err != nil {
		slog.Warn("database size check failed", "err", err)
		return
	}
	s.raiseAlert(ctx, status)
}

// LastSize is the cached last size check (nil before the first).
func (s *Storage) LastSize() *DBSizeStatus {
	s.state.Lock()
	defer s.state.Unlock()
	if s.last == nil {
		return nil
	}
	c := *s.last
	return &c
}

// Alert is the cached alert summary.
func (s *Storage) Alert() SizeAlert {
	st := s.LastSize()
	if st == nil {
		return SizeAlert{Level: SizeLevelNone}
	}
	return SizeAlert{
		Level: st.Level, LevelReason: st.LevelReason, SizeBytes: st.SizeBytes, BudgetBytes: st.BudgetBytes,
		UsedRatio: st.UsedRatio, FilesystemUsedRatio: st.Filesystem.UsedRatio, DaysUntilFull: st.DaysUntilFull,
		CheckedAt: st.CheckedAt,
	}
}

// raiseAlert logs a level change and mails the system administrators when
// a warning or critical level is reached (see below). The state survives
// restarts (system_settings).
func (s *Storage) raiseAlert(ctx context.Context, st DBSizeStatus) {
	s.state.Lock()
	if !s.alertInit {
		var rec alertState
		if err := s.Settings.GetJSON(ctx, dbSizeAlertKey, &rec); err == nil {
			s.alert = rec
		}
		s.alertInit = true
	}
	prev, mailedLevel := s.alert.Level, s.alert.Mailed
	last, sent := s.alert.Sent[st.Level]
	s.state.Unlock()

	level := st.Level
	summary := sizeSummary(st)
	changed := levelRank(level) != levelRank(prev)
	switch {
	case levelRank(level) < levelRank(prev):
		slog.Info("database size alert lowered", "from", prev, "to", level, "detail", summary)
	case changed:
		slog.Warn("database size alert", "level", level, "reason", st.LevelReason, "detail", summary)
	}
	if levelRank(level) < levelRank(mailedLevel) {
		// The episode at the mailed level is over.
		mailedLevel, changed = level, true
	}
	// Mail a level above the one already mailed in this episode — also one
	// reached while no mail server was in force, once one is — at most once
	// per level per 24 h.
	if levelRank(level) > levelRank(mailedLevel) && (!sent || s.now().Sub(last) >= alertMailEvery) {
		if s.mailAlert(ctx, level, summary) {
			mailedLevel, changed = level, true
			s.state.Lock()
			if s.alert.Sent == nil {
				s.alert.Sent = map[string]time.Time{}
			}
			s.alert.Sent[level] = s.now()
			s.state.Unlock()
		}
	}
	if changed {
		s.saveAlert(ctx, level, mailedLevel)
	}
}

func (s *Storage) saveAlert(ctx context.Context, level, mailedLevel string) {
	s.state.Lock()
	s.alert.Level, s.alert.Mailed = level, mailedLevel
	rec := alertState{Level: level, Mailed: mailedLevel, Sent: map[string]time.Time{}}
	for k, v := range s.alert.Sent {
		rec.Sent[k] = v
	}
	s.state.Unlock()
	if err := s.Settings.SetJSON(ctx, dbSizeAlertKey, rec); err != nil {
		slog.Warn("database size alert: state not saved", "err", err)
	}
}

// mailAlert sends the alert to every system administrator; true when the
// attempt was made (a mail server is in force), whatever the delivery
// result, so a failing server is not retried every check.
func (s *Storage) mailAlert(ctx context.Context, level, summary string) bool {
	if s.Mail == nil {
		return false
	}
	state, err := s.Mail.Current(ctx)
	if err != nil || state.Server.Host == "" {
		slog.Info("database size alert: no mail server configured; email not sent", "level", level)
		return false
	}
	to, err := s.Store.AdminEmails(ctx)
	if err != nil || len(to) == 0 {
		slog.Warn("database size alert: no administrator address", "err", err)
		return false
	}
	subject := "Wafio: database size " + level
	body := "The Wafio control plane database has reached the " + strings.ToUpper(level) + " level.\n\n" + summary + "\n\n" +
		"Shorten the telemetry retention or raise the budget under Administration > Data retention"
	if state.BaseURL != "" {
		body += ":\n" + state.BaseURL + "/admin/retention"
	}
	body += "\n\nThis email is sent at most once per level a day.\n"
	mailer := s.Mail.Mailer()
	sort.Strings(to)
	for _, addr := range to {
		if err := mailer.Send(addr, subject, body); err != nil {
			slog.Warn("database size alert: email failed", "level", level, "err", err)
		}
	}
	return true
}

// sizeSummary is the alert text (log line and email).
func sizeSummary(st DBSizeStatus) string {
	var parts []string
	if st.SizeBytes != nil {
		parts = append(parts, "Database size: "+formatBytes(*st.SizeBytes))
	}
	if st.BudgetBytes != nil && st.UsedRatio != nil {
		parts = append(parts, fmt.Sprintf("Budget: %s (%.0f%% used)", formatBytes(*st.BudgetBytes), *st.UsedRatio*100))
	}
	if st.Filesystem.Known && st.Filesystem.FreeBytes != nil && st.Filesystem.UsedRatio != nil {
		parts = append(parts, fmt.Sprintf("Disk: %s free (%.0f%% used)", formatBytes(*st.Filesystem.FreeBytes), *st.Filesystem.UsedRatio*100))
	}
	if st.GrowthBytesPerDay != nil {
		parts = append(parts, "Growth: "+formatBytes(int64(*st.GrowthBytesPerDay))+" per day")
	}
	if st.DaysUntilFull != nil {
		parts = append(parts, fmt.Sprintf("Projected full in %.1f days", *st.DaysUntilFull))
	}
	return strings.Join(parts, "\n")
}

func formatBytes(n int64) string {
	const unit = 1000
	if n < 0 {
		return "-" + formatBytes(-n)
	}
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// BudgetUpdate is PUT /api/admin/storage/budget (null = no budget).
type BudgetUpdate struct {
	BudgetGB *float64 `json:"budget_gb"`
}

// UpdateBudget saves the database size budget and returns the old and new
// value in bytes (0 = none). The next size check uses it at once.
func (s *Storage) UpdateBudget(ctx context.Context, u BudgetUpdate) (oldBytes, newBytes int64, err error) {
	if u.BudgetGB != nil {
		gb := *u.BudgetGB
		// Range-check the float before converting (an out-of-range
		// float → int64 conversion is implementation-defined).
		if math.IsNaN(gb) || gb < 0.0999 || gb > 1_000_000 {
			return 0, 0, &StorageInvalid{Field: "budget_gb", Message: "Enter a size in GB from 0.1 to 1000000, or remove the budget."}
		}
		newBytes = int64(math.Round(gb * 1e9))
		if newBytes < minBudgetBytes || newBytes > maxBudgetBytes {
			return 0, 0, &StorageInvalid{Field: "budget_gb", Message: "Enter a size in GB from 0.1 to 1000000, or remove the budget."}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if oldBytes, err = s.loadBudget(ctx); err != nil {
		return 0, 0, ErrStorageUnavailable
	}
	if err := s.Settings.SetJSON(ctx, dbSizeBudgetKey, budgetRecord{BudgetBytes: newBytes}); err != nil {
		return 0, 0, ErrStorageUnavailable
	}
	return oldBytes, newBytes, nil
}
