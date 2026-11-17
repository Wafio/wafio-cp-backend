package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Telemetry data retention and database size monitoring, Administration › Data retention.
//
// Where retention runs:
//   - "policy": the table is a hypertable and TimescaleDB ≥ 2.0 runs under
//     its community license — a TimescaleDB retention policy (migrations
//     000048–000051 install the defaults) drops old chunks. A save replaces
//     the policy in one transaction with the saved value; boot and the
//     hourly pass re-apply a saved value the live policy no longer matches.
//   - "drop_chunks": a hypertable without retention policies (Apache-only
//     license, where add_retention_policy is refused): the control plane
//     calls drop_chunks hourly.
//   - "delete": a plain table (no TimescaleDB): the control plane deletes
//     rows older than the retention hourly, in bounded batches.
//
// Without a saved value the policy tables keep what the migrations (or an
// operator) installed, and the control-plane modes use the migration
// default, so no table grows forever unnoticed.
//
// A saved value is re-checked at every use (status, reconcile, pass): one
// outside the table's range (manual SQL, a restore, a bug) is never applied
// and never clamped — the table is skipped with a warning and shown as not
// active until a valid value is saved. Clamping would turn a corrupt 0 into
// the minimum and delete what a 3650-day setting meant to keep.
//
// Cutoffs are computed by the database (make_interval against its now()),
// never from the control-plane clock.
//
// The first control-plane pass of an installation waits retentionGrace after
// the first start of this version (persisted under dataRetentionGraceKey), so
// an operator upgrading onto plain PostgreSQL or Apache TimescaleDB can raise
// the retention before anything is deleted. Later starts do not restart the
// wait, so a restart loop cannot keep retention off.

const (
	dataRetentionKey = "data_retention"
	dbSizeBudgetKey  = "db_size_budget"
	dbSizeAlertKey   = "db_size_alert_state"
	// dataRetentionGraceKey holds when the first control-plane retention
	// pass may run ({"not_before": time}).
	dataRetentionGraceKey = "data_retention_first_pass"
)

// Retention modes.
const (
	RetentionModePolicy     = "policy"
	RetentionModeDropChunks = "drop_chunks"
	RetentionModeDelete     = "delete"
	RetentionModeNone       = "none"
)

const (
	// Control-plane retention pass: every hour, the first a minute after
	// boot (retentionGrace after the first start of this version); plain
	// tables lose at most deleteBatch × maxDeleteBatches rows per table and
	// pass.
	defaultRetentionInterval = time.Hour
	retentionFirstRun        = time.Minute
	retentionGrace           = time.Hour
	deleteBatch              = 5000
	maxDeleteBatches         = 100
	deleteBatchPause         = 50 * time.Millisecond
)

// ErrStorageUnavailable is a storage read or write that failed.
var ErrStorageUnavailable = errors.New("storage settings unavailable")

// StorageInvalid is a rejected setting (400). Code is VALIDATION_FAILED
// unless set.
type StorageInvalid struct {
	Field   string
	Message string
	Code    string
}

func (e *StorageInvalid) Error() string { return e.Field + ": " + e.Message }

// Storage serves Administration › Data retention and runs the retention and
// database size checks. Store and Settings are required; Mail may be nil.
type Storage struct {
	Store    domain.StorageStore
	Settings domain.SettingsStore
	// Mail sends the size alert to system administrators while a mail
	// server is in force (nil = no email).
	Mail StorageMailSource
	// DatabaseHost is database.host: free disk space is read only for a
	// database on this host.
	DatabaseHost string
	// FSUsage reads a filesystem's free and total bytes (nil = fsstat.Usage).
	FSUsage func(path string) (free, total uint64, err error)
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
	// CheckInterval is the size check period (0 = 10 min);
	// RetentionInterval the control-plane retention pass (0 = 1 h).
	CheckInterval     time.Duration
	RetentionInterval time.Duration

	// mu serializes saves and reconciliation; pass keeps one retention
	// pass at a time in this process (the advisory lock across processes).
	mu    sync.Mutex
	pass  sync.Mutex
	rerun atomic.Bool
	// state guards the cached status, samples, pass results and counters.
	state     sync.Mutex
	last      *DBSizeStatus
	tables    []TableRetentionView
	samples   []sizeSample
	passes    map[string]retentionPass
	deleted   map[string]uint64
	alert     alertState
	alertInit bool
	kick      chan struct{}
	kickOnce  sync.Once
	// notBefore: no control-plane pass is started before it (zero = no
	// wait).
	notBefore time.Time
}

// StorageMailSource is the live mail configuration (*MailSettings).
type StorageMailSource interface {
	Current(ctx context.Context) (MailState, error)
	Mailer() domain.Mailer
}

type retentionRecord struct {
	Tables map[string]int `json:"tables,omitempty"`
}

type budgetRecord struct {
	BudgetBytes int64 `json:"budget_bytes,omitempty"`
}

type graceRecord struct {
	NotBefore time.Time `json:"not_before"`
}

type retentionPass struct {
	At      time.Time
	Deleted int64
	Failed  bool
}

func (s *Storage) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Storage) kickChan() chan struct{} {
	s.kickOnce.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// TimescaleView is the TimescaleDB part of the status.
type TimescaleView struct {
	Installed         bool   `json:"installed"`
	Version           string `json:"version"`
	License           string `json:"license"`
	PoliciesSupported bool   `json:"policies_supported"`
	Note              string `json:"note"`
}

// CompressionView is a hypertable's compression state.
type CompressionView struct {
	Enabled           bool     `json:"enabled"`
	CompressAfterDays *float64 `json:"compress_after_days"`
	CompressedChunks  int      `json:"compressed_chunks"`
	TotalChunks       int      `json:"total_chunks"`
	BeforeBytes       *int64   `json:"before_bytes"`
	AfterBytes        *int64   `json:"after_bytes"`
	Ratio             *float64 `json:"ratio"`
}

// TableRetentionView is one table on the page.
type TableRetentionView struct {
	Table             string           `json:"table"`
	Label             string           `json:"label"`
	TimeColumn        string           `json:"time_column"`
	RetentionDays     int              `json:"retention_days"`
	DefaultDays       int              `json:"default_days"`
	MinDays           int              `json:"min_days"`
	MaxDays           int              `json:"max_days"`
	Saved             bool             `json:"saved"`
	LiveDays          *float64         `json:"live_days"`
	Mode              string           `json:"mode"`
	Active            bool             `json:"active"`
	InactiveReason    string           `json:"inactive_reason"`
	LastRunAt         *time.Time       `json:"last_run_at"`
	LastRunDeleted    *int64           `json:"last_run_deleted"`
	Hypertable        bool             `json:"hypertable"`
	TotalBytes        *int64           `json:"total_bytes"`
	Compression       *CompressionView `json:"compression"`
	ChunkCount        *int             `json:"chunk_count"`
	OldestAt          *time.Time       `json:"oldest_at"`
	OldestKind        string           `json:"oldest_kind"`
	IngestBytesPerDay *float64         `json:"ingest_bytes_per_day"`

	// remainingDays: days until the table spans its retention (+Inf when
	// retention does not run); internal to the projection.
	remainingDays float64
}

// StorageStatus is GET /api/admin/storage.
type StorageStatus struct {
	CheckedAt   time.Time            `json:"checked_at"`
	TimescaleDB TimescaleView        `json:"timescaledb"`
	Tables      []TableRetentionView `json:"tables"`
	Database    DBSizeStatus         `json:"database"`
}

// policiesSupported: add_retention_policy exists (TimescaleDB ≥ 2.0) and is
// allowed (community license; Apache-only builds refuse it).
func policiesSupported(ts domain.TimescaleInfo) bool {
	if !ts.Installed || ts.License != "timescale" {
		return false
	}
	v, ok := parseVersion(ts.Version)
	return ok && v[0] >= 2
}

// timescaleNote explains, for the page, where retention runs.
func timescaleNote(ts domain.TimescaleInfo) string {
	v, vok := parseVersion(ts.Version)
	switch {
	case !ts.Installed:
		return "TimescaleDB is not installed: the telemetry tables are plain PostgreSQL tables without chunks or compression. " +
			"No TimescaleDB retention policy can exist, so the control plane deletes rows older than the retention itself, every hour in bounded batches."
	case !vok || v[0] < 2:
		return fmt.Sprintf("TimescaleDB %s is older than 2.0: retention policies are not supported and retention is not active. Upgrade TimescaleDB.", ts.Version)
	case ts.License != "timescale":
		lic := ts.License
		if lic == "" {
			lic = "unknown"
		}
		return fmt.Sprintf("TimescaleDB runs under the %q license: retention policies and compression need the community (\"timescale\") license. "+
			"The control plane drops chunks older than the retention itself, every hour.", lic)
	}
	return ""
}

// retentionMode says where a table's retention runs, with a reason when it
// cannot run.
func retentionMode(ts domain.TimescaleInfo, st domain.TableStorageStats) (string, string) {
	switch {
	case !st.Exists:
		return RetentionModeNone, "The table does not exist (database migrations not applied)."
	case st.Hypertable && policiesSupported(ts):
		return RetentionModePolicy, ""
	case st.Hypertable:
		if v, ok := parseVersion(ts.Version); ok && v[0] >= 2 {
			return RetentionModeDropChunks, ""
		}
		return RetentionModeNone, "TimescaleDB older than 2.0 is not supported; retention is not active."
	default:
		return RetentionModeDelete, ""
	}
}

func days(d time.Duration) float64 { return d.Hours() / 24 }

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// validDays: a retention the table accepts (the range a save enforces).
func validDays(t domain.RetentionTable, d int) bool {
	return d >= t.MinDays && d <= domain.RetentionMaxDays
}

func invalidSavedReason(t domain.RetentionTable, d int) string {
	return fmt.Sprintf("The saved retention (%d days) is outside %d–%d days, so it is not applied and this table is skipped. Save a valid retention.",
		d, t.MinDays, domain.RetentionMaxDays)
}

func (s *Storage) loadRetention(ctx context.Context) (retentionRecord, error) {
	var rec retentionRecord
	if err := s.Settings.GetJSON(ctx, dataRetentionKey, &rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func (s *Storage) loadBudget(ctx context.Context) (int64, error) {
	var rec budgetRecord
	if err := s.Settings.GetJSON(ctx, dbSizeBudgetKey, &rec); err != nil {
		return 0, err
	}
	return rec.BudgetBytes, nil
}

// tableView builds one table's row from its statistics.
func (s *Storage) tableView(t domain.RetentionTable, ts domain.TimescaleInfo, st domain.TableStorageStats, saved map[string]int, now time.Time) TableRetentionView {
	v := TableRetentionView{
		Table: t.Name, Label: t.Label, TimeColumn: t.TimeColumn,
		DefaultDays: t.DefaultDays, MinDays: t.MinDays, MaxDays: domain.RetentionMaxDays,
		Hypertable: st.Hypertable,
	}
	v.Mode, v.InactiveReason = retentionMode(ts, st)
	savedDays, isSaved := saved[t.Name]
	v.Saved = isSaved
	badSaved := isSaved && !validDays(t, savedDays)
	if st.Exists {
		b := st.TotalBytes
		v.TotalBytes = &b
	}

	switch v.Mode {
	case RetentionModePolicy:
		pol := st.Retention
		if pol.Exists {
			ld := round2(days(pol.DropAfter))
			v.LiveDays = &ld
			v.LastRunAt = pol.LastSuccess
		}
		switch {
		case isSaved && !badSaved:
			v.RetentionDays = savedDays
		case pol.Exists:
			v.RetentionDays = int(math.Round(days(pol.DropAfter)))
		default:
			v.RetentionDays = t.DefaultDays
		}
		switch {
		case badSaved:
			v.InactiveReason = invalidSavedReason(t, savedDays)
		case !pol.Exists:
			v.InactiveReason = "No TimescaleDB retention policy exists on this table (removed outside Wafio). Save a retention to create one."
		case !pol.Scheduled:
			v.InactiveReason = "The TimescaleDB retention job is paused."
		case pol.LastStatus == "Failed":
			v.InactiveReason = "The last run of the TimescaleDB retention job failed; check the database log."
		case isSaved && pol.DropAfter != time.Duration(savedDays)*24*time.Hour:
			v.InactiveReason = fmt.Sprintf("The live policy (%g days) differs from the saved retention; it is re-applied within the hour.", round2(days(pol.DropAfter)))
		default:
			v.Active = true
		}
	case RetentionModeDropChunks, RetentionModeDelete:
		v.RetentionDays = t.DefaultDays
		if isSaved && !badSaved {
			v.RetentionDays = savedDays
		}
		v.Active = true
		s.state.Lock()
		p, ran := s.passes[t.Name]
		notBefore := s.notBefore
		s.state.Unlock()
		if ran {
			at, n := p.At, p.Deleted
			v.LastRunAt, v.LastRunDeleted = &at, &n
		}
		switch {
		case badSaved:
			v.Active = false
			v.InactiveReason = invalidSavedReason(t, savedDays)
		case ran && p.Failed:
			v.Active = false
			v.InactiveReason = "The last control-plane retention run failed; check the control-plane log."
		case !ran && now.Before(notBefore):
			v.Active = false
			v.InactiveReason = fmt.Sprintf("Retention starts at %s UTC: the first control-plane run waits an hour after the upgrade, so the retention can be raised before anything is deleted.",
				notBefore.UTC().Format("2006-01-02 15:04"))
		}
	default:
		v.RetentionDays = t.DefaultDays
		if isSaved && !badSaved {
			v.RetentionDays = savedDays
		}
	}

	if st.Hypertable {
		n := len(st.Chunks)
		v.ChunkCount = &n
		if n > 0 {
			o := st.Chunks[0].Start
			v.OldestAt, v.OldestKind = &o, "chunk"
		}
		if st.CompressionEnabled {
			cv := &CompressionView{Enabled: true, CompressedChunks: st.CompressedChunks, TotalChunks: n}
			if st.CompressAfter > 0 {
				d := round2(days(st.CompressAfter))
				cv.CompressAfterDays = &d
			}
			if st.BeforeBytes > 0 && st.AfterBytes > 0 {
				b, a := st.BeforeBytes, st.AfterBytes
				r := round2(float64(b) / float64(a))
				cv.BeforeBytes, cv.AfterBytes, cv.Ratio = &b, &a, &r
			}
			v.Compression = cv
		}
	} else if st.OldestRow != nil {
		o := *st.OldestRow
		v.OldestAt, v.OldestKind = &o, "row"
	}

	ingest, span := estimateIngest(st, now)
	v.IngestBytesPerDay = ingest
	switch {
	case !v.Active || v.Mode == RetentionModeNone:
		v.remainingDays = math.Inf(1)
	default:
		v.remainingDays = math.Max(0, float64(v.RetentionDays)-span)
	}
	return v
}

// estimateIngest estimates a hypertable's stored bytes per day from its
// complete chunks of the last seven days, each counted at its compressed
// size (an uncompressed chunk scaled by the table's measured compression
// ratio, since the compression policy shrinks it within a day), and returns
// the days the table spans. Plain tables: nil, 0.
func estimateIngest(st domain.TableStorageStats, now time.Time) (*float64, float64) {
	if !st.Hypertable || len(st.Chunks) == 0 {
		return nil, 0
	}
	span := math.Max(0, days(now.Sub(st.Chunks[0].Start)))
	ratio := 1.0
	if st.CompressionEnabled && st.BeforeBytes > 0 && st.AfterBytes > 0 {
		ratio = float64(st.AfterBytes) / float64(st.BeforeBytes)
	}
	// Divided by the calendar window the counted chunks span, so days
	// without a chunk (an agent outage) count as days without ingest.
	var bytes float64
	var first, last time.Time
	for _, c := range st.Chunks {
		if c.End.After(now) || c.End.Before(now.Add(-8*24*time.Hour)) || !c.End.After(c.Start) {
			continue
		}
		b := float64(c.Bytes)
		if !c.Compressed {
			b *= ratio
		}
		bytes += b
		if first.IsZero() || c.Start.Before(first) {
			first = c.Start
		}
		if c.End.After(last) {
			last = c.End
		}
	}
	covered := days(last.Sub(first))
	if first.IsZero() || covered <= 0 {
		return nil, span
	}
	per := math.Round(bytes / covered)
	return &per, span
}

// Status reads every table (with the bounded oldest-row query on plain
// tables) and the database size, refreshing the cached size status.
func (s *Storage) Status(ctx context.Context) (StorageStatus, error) {
	ts, err := s.Store.TimescaleInfo(ctx)
	if err != nil {
		return StorageStatus{}, ErrStorageUnavailable
	}
	saved, err := s.loadRetention(ctx)
	if err != nil {
		return StorageStatus{}, ErrStorageUnavailable
	}
	now := s.now()
	out := StorageStatus{
		CheckedAt: now,
		TimescaleDB: TimescaleView{
			Installed: ts.Installed, Version: ts.Version, License: ts.License,
			PoliciesSupported: policiesSupported(ts), Note: timescaleNote(ts),
		},
	}
	for _, t := range domain.RetentionTables {
		st, err := s.Store.TableStats(ctx, t, true)
		if err != nil {
			return StorageStatus{}, ErrStorageUnavailable
		}
		out.Tables = append(out.Tables, s.tableView(t, ts, st, saved.Tables, now))
	}
	db, err := s.sizeStatus(ctx, out.Tables, now, false)
	if err != nil {
		return StorageStatus{}, ErrStorageUnavailable
	}
	out.Database = db
	return out, nil
}

// RetentionUpdate is PUT /api/admin/storage/retention: days per table, null
// = back to the default.
type RetentionUpdate struct {
	Tables map[string]*int `json:"tables"`
}

// RetentionChange is one table's change, for the audit row.
type RetentionChange struct {
	Old   int    `json:"old"`
	New   int    `json:"new"`
	Reset bool   `json:"reset,omitempty"`
	Mode  string `json:"mode"`
}

// UpdateRetention validates and applies new retention values: policy
// tables get their policy replaced in the same transaction that saves the
// values; the control-plane modes use them from the next pass, which is
// started at once. A shortened policy table also drops its now-expired
// chunks at once instead of at the policy's next daily run.
func (s *Storage) UpdateRetention(ctx context.Context, u RetentionUpdate) (map[string]RetentionChange, error) {
	if len(u.Tables) == 0 {
		return nil, &StorageInvalid{Field: "tables", Message: "Change the retention of at least one table."}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.Store.TimescaleInfo(ctx)
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	rec, err := s.loadRetention(ctx)
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	if rec.Tables == nil {
		rec.Tables = map[string]int{}
	}
	now := s.now()
	names := make([]string, 0, len(u.Tables))
	for name := range u.Tables {
		names = append(names, name)
	}
	sort.Strings(names)

	changes := map[string]RetentionChange{}
	var apply []domain.RetentionApply
	var shortened []domain.RetentionApply
	for _, name := range names {
		field := "tables." + name
		t, ok := domain.RetentionTableByName(name)
		if !ok {
			return nil, &StorageInvalid{Field: field, Message: "Unknown table."}
		}
		newDays := t.DefaultDays
		reset := u.Tables[name] == nil
		if !reset {
			newDays = *u.Tables[name]
			if newDays < t.MinDays || newDays > domain.RetentionMaxDays {
				return nil, &StorageInvalid{Field: field, Message: fmt.Sprintf("Enter whole days from %d to %d.", t.MinDays, domain.RetentionMaxDays)}
			}
		}
		st, err := s.Store.TableStats(ctx, t, false)
		if err != nil {
			return nil, ErrStorageUnavailable
		}
		mode, reason := retentionMode(ts, st)
		if mode == RetentionModeNone {
			return nil, &StorageInvalid{Field: field, Message: "Retention cannot run on this table: " + reason, Code: "RETENTION_NOT_SUPPORTED"}
		}
		if st.CompressAfter > 0 && time.Duration(newDays)*24*time.Hour <= st.CompressAfter {
			return nil, &StorageInvalid{
				Field:   field,
				Message: fmt.Sprintf("The retention must be longer than the compression window (%g days).", round2(days(st.CompressAfter))),
				Code:    "RETENTION_BELOW_COMPRESSION",
			}
		}
		old := s.tableView(t, ts, st, rec.Tables, now).RetentionDays
		if reset {
			delete(rec.Tables, name)
		} else {
			rec.Tables[name] = newDays
		}
		if mode == RetentionModePolicy {
			pol := st.Retention
			want := time.Duration(newDays) * 24 * time.Hour
			if !pol.Exists || !pol.Scheduled || pol.DropAfter != want {
				apply = append(apply, domain.RetentionApply{Table: name, Days: newDays})
				if pol.Exists && want < pol.DropAfter {
					shortened = append(shortened, domain.RetentionApply{Table: name, Days: newDays})
				}
			}
		}
		changes[name] = RetentionChange{Old: old, New: newDays, Reset: reset, Mode: mode}
	}
	if err := s.Store.ApplyRetention(ctx, apply, dataRetentionKey, rec); err != nil {
		slog.Error("data retention: save failed", "err", err)
		return nil, ErrStorageUnavailable
	}
	for _, c := range apply {
		slog.Info("data retention: policy applied", "table", c.Table, "days", c.Days)
	}
	if len(shortened) > 0 {
		go s.dropNow(shortened)
	}
	select {
	case s.kickChan() <- struct{}{}:
	default:
	}
	return changes, nil
}

// dropNow drops the chunks a shortened policy no longer keeps (best effort;
// the policy job does it at its next run otherwise).
func (s *Storage) dropNow(tables []domain.RetentionApply) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, c := range tables {
		// A later save may have lengthened the retention again: drop
		// only while the saved value is still the one this run was for.
		s.mu.Lock()
		rec, err := s.loadRetention(ctx)
		s.mu.Unlock()
		t, _ := domain.RetentionTableByName(c.Table)
		current := t.DefaultDays
		if d, ok := rec.Tables[c.Table]; ok {
			current = d
		}
		if err != nil || current != c.Days {
			continue
		}
		n, err := s.Store.DropChunksOlderThan(ctx, c.Table, c.Days)
		if err != nil {
			slog.Warn("data retention: dropping expired chunks failed; the policy drops them at its next run", "table", c.Table, "err", err)
			continue
		}
		if n > 0 {
			slog.Info("data retention: expired chunks dropped", "table", c.Table, "chunks", n, "days", c.Days)
		}
	}
}

// Reconcile re-applies saved retention values a live TimescaleDB policy no
// longer matches (removed, paused or changed outside Wafio). Nothing saved
// = the migration defaults stay.
func (s *Storage) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.loadRetention(ctx)
	if err != nil {
		return err
	}
	if len(rec.Tables) == 0 {
		return nil
	}
	ts, err := s.Store.TimescaleInfo(ctx)
	if err != nil {
		return err
	}
	if !policiesSupported(ts) {
		return nil
	}
	var apply []domain.RetentionApply
	for _, t := range domain.RetentionTables {
		want, ok := rec.Tables[t.Name]
		if !ok {
			continue
		}
		if !validDays(t, want) {
			slog.Warn("data retention: saved retention out of range; not applied, live policy left as it is",
				"table", t.Name, "saved_days", want, "min_days", t.MinDays, "max_days", domain.RetentionMaxDays)
			continue
		}
		st, err := s.Store.TableStats(ctx, t, false)
		if err != nil {
			return err
		}
		if mode, _ := retentionMode(ts, st); mode != RetentionModePolicy {
			continue
		}
		pol := st.Retention
		if pol.Exists && pol.Scheduled && pol.DropAfter == time.Duration(want)*24*time.Hour {
			continue
		}
		slog.Warn("data retention: live policy differs from the saved retention; re-applying",
			"table", t.Name, "saved_days", want, "live_exists", pol.Exists, "live_days", round2(days(pol.DropAfter)), "scheduled", pol.Scheduled)
		apply = append(apply, domain.RetentionApply{Table: t.Name, Days: want})
	}
	if len(apply) == 0 {
		return nil
	}
	return s.Store.ApplyRetention(ctx, apply, "", nil)
}

// RunRetentionPass deletes expired telemetry in the control-plane modes
// (drop_chunks, delete). Policy tables are left to TimescaleDB.
//
// It does not hold mu while it deletes (a pass over large plain tables can
// take minutes and must not block a save); each table reads the saved
// retention right before its deletion, so a save that lengthens a
// retention is honoured by the tables the pass has not reached yet.
func (s *Storage) RunRetentionPass(ctx context.Context) {
	if s.inGrace() {
		// The upgrade grace: a save during it takes effect when it ends
		// (Run's timer starts the pass then).
		return
	}
	if !s.pass.TryLock() {
		// The running pass goes round once more (a save during it).
		s.rerun.Store(true)
		return
	}
	defer s.pass.Unlock()
	for {
		s.rerun.Store(false)
		s.retentionPass(ctx)
		if !s.rerun.Load() || ctx.Err() != nil {
			return
		}
	}
}

func (s *Storage) retentionPass(ctx context.Context) {
	ts, err := s.Store.TimescaleInfo(ctx)
	if err != nil {
		slog.Warn("data retention: pass skipped", "err", err)
		return
	}
	release, ok, err := s.Store.TryRetentionLock(ctx)
	if err != nil || !ok {
		if err != nil {
			slog.Warn("data retention: pass skipped", "err", err)
		}
		return
	}
	defer release()
	for _, t := range domain.RetentionTables {
		st, err := s.Store.TableStats(ctx, t, false)
		if err != nil {
			s.notePass(t.Name, 0, true)
			slog.Warn("data retention: table unreadable", "table", t.Name, "err", err)
			continue
		}
		mode, _ := retentionMode(ts, st)
		if mode != RetentionModeDropChunks && mode != RetentionModeDelete {
			continue
		}
		s.mu.Lock()
		rec, err := s.loadRetention(ctx)
		s.mu.Unlock()
		if err != nil {
			s.notePass(t.Name, 0, true)
			slog.Warn("data retention: saved retention unreadable; table skipped", "table", t.Name, "err", err)
			continue
		}
		keep := t.DefaultDays
		if d, ok := rec.Tables[t.Name]; ok {
			keep = d
		}
		if !validDays(t, keep) {
			// Never clamped: a corrupt 0 must not become "delete all
			// but the minimum" of a table meant to keep years.
			slog.Warn("data retention: saved retention out of range; table skipped",
				"table", t.Name, "saved_days", keep, "min_days", t.MinDays, "max_days", domain.RetentionMaxDays)
			continue
		}
		switch mode {
		case RetentionModeDropChunks:
			n, err := s.Store.DropChunksOlderThan(ctx, t.Name, keep)
			s.notePass(t.Name, int64(n), err != nil)
			if err != nil {
				slog.Warn("data retention: drop_chunks failed", "table", t.Name, "err", err)
			} else if n > 0 {
				slog.Info("data retention: chunks dropped", "table", t.Name, "chunks", n, "days", keep)
			}
		case RetentionModeDelete:
			n, err := s.deleteExpired(ctx, t, keep)
			s.notePass(t.Name, n, err != nil)
			if err != nil {
				slog.Warn("data retention: delete failed", "table", t.Name, "deleted", n, "err", err)
			} else if n > 0 {
				slog.Info("data retention: rows deleted", "table", t.Name, "rows", n, "days", keep)
			}
		}
	}
}

// deleteExpired deletes rows older than keep days (cutoff on the database
// clock) in batches, at most maxDeleteBatches per pass (the rest goes in the
// next pass).
func (s *Storage) deleteExpired(ctx context.Context, t domain.RetentionTable, keep int) (int64, error) {
	var total int64
	for i := 0; i < maxDeleteBatches; i++ {
		n, err := s.Store.DeleteOlderThan(ctx, t, keep, deleteBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n < deleteBatch {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(deleteBatchPause):
		}
	}
	return total, nil
}

func (s *Storage) notePass(table string, n int64, failed bool) {
	s.state.Lock()
	defer s.state.Unlock()
	if s.passes == nil {
		s.passes = map[string]retentionPass{}
		s.deleted = map[string]uint64{}
	}
	s.passes[table] = retentionPass{At: s.now(), Deleted: n, Failed: failed}
	if n > 0 {
		s.deleted[table] += uint64(n)
	}
}

// RetentionMetrics is the per-table state for the OpenMetrics series.
type RetentionMetrics struct {
	Table         string
	Days          int
	Active        bool
	DeletedByPass uint64
}

// MetricsTables returns the last known retention state per table (from the
// latest status read or size check).
func (s *Storage) MetricsTables() []RetentionMetrics {
	s.state.Lock()
	defer s.state.Unlock()
	out := make([]RetentionMetrics, 0, len(s.tables))
	for _, v := range s.tables {
		out = append(out, RetentionMetrics{Table: v.Table, Days: v.RetentionDays, Active: v.Active, DeletedByPass: s.deleted[v.Table]})
	}
	return out
}

// Run reconciles the saved retention at boot, then checks the database size
// every CheckInterval and runs the retention pass (and reconciliation)
// every RetentionInterval, until ctx ends.
func (s *Storage) Run(ctx context.Context) {
	if err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("data retention: reconcile at boot failed", "err", err)
	}
	s.CheckSize(ctx)
	checkEvery := s.CheckInterval
	if checkEvery <= 0 {
		checkEvery = defaultSizeCheckInterval
	}
	passEvery := s.RetentionInterval
	if passEvery <= 0 {
		passEvery = defaultRetentionInterval
	}
	check := time.NewTicker(checkEvery)
	defer check.Stop()
	pass := time.NewTimer(s.firstPassDelay(ctx))
	defer pass.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			s.CheckSize(ctx)
		case <-s.kickChan():
			// In its own goroutine: a long pass must not delay the size
			// check (a pass already running makes this one a no-op).
			go s.RunRetentionPass(ctx)
		case <-pass.C:
			if err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("data retention: reconcile failed", "err", err)
			}
			// The timer ran out the grace (wall-clock jitter must not
			// make this pass a no-op).
			s.endGrace()
			go s.RunRetentionPass(ctx)
			pass.Reset(passEvery)
		}
	}
}

// firstPassDelay is the wait before the first control-plane pass: the rest
// of the installation's grace (recorded at the first start of this version
// and never more than retentionGrace from now, so a clock that was ahead at
// that start cannot postpone retention), at least retentionFirstRun. An
// unreadable record waits the full grace from now (the safe direction; the
// next start reads it again).
func (s *Storage) firstPassDelay(ctx context.Context) time.Duration {
	now := s.now()
	var rec graceRecord
	err := s.Settings.GetJSON(ctx, dataRetentionGraceKey, &rec)
	switch {
	case err != nil:
		slog.Warn("data retention: grace record unreadable; first pass in an hour", "err", err)
		rec.NotBefore = now.Add(retentionGrace)
	case rec.NotBefore.IsZero():
		rec.NotBefore = now.Add(retentionGrace)
		if err := s.Settings.SetJSON(ctx, dataRetentionGraceKey, rec); err != nil {
			slog.Warn("data retention: grace record not saved", "err", err)
		}
		slog.Info("data retention: first control-plane retention pass waits for the upgrade grace", "not_before", rec.NotBefore)
	}
	if limit := now.Add(retentionGrace); rec.NotBefore.After(limit) {
		rec.NotBefore = limit
	}
	s.state.Lock()
	s.notBefore = rec.NotBefore
	s.state.Unlock()
	if d := rec.NotBefore.Sub(now); d > retentionFirstRun {
		return d
	}
	return retentionFirstRun
}

// inGrace: the first control-plane pass is still waiting for the grace.
func (s *Storage) inGrace() bool {
	s.state.Lock()
	nb := s.notBefore
	s.state.Unlock()
	return s.now().Before(nb)
}

func (s *Storage) endGrace() {
	s.state.Lock()
	s.notBefore = time.Time{}
	s.state.Unlock()
}
