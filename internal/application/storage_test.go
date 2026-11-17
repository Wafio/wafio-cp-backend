package application

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type fakeSettings struct {
	mu   sync.Mutex
	data map[string][]byte
	fail bool
}

func (f *fakeSettings) GetJSON(_ context.Context, key string, dst any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("settings down")
	}
	raw, ok := f.data[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func (f *fakeSettings) SetJSON(_ context.Context, key string, v any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("settings down")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if f.data == nil {
		f.data = map[string][]byte{}
	}
	f.data[key] = raw
	return nil
}

type deleteCall struct {
	table string
	days  int
	limit int
}

type fakeStorageStore struct {
	mu       sync.Mutex
	ts       domain.TimescaleInfo
	stats    map[string]domain.TableStorageStats
	settings *fakeSettings
	applied  [][]domain.RetentionApply
	applyErr error
	dropped  map[string]int
	deletes  []deleteCall
	// rowsOld is how many rows older than any cutoff each plain table holds.
	rowsOld    map[string]int64
	dbSize     int64
	dataDir    string
	dataDirErr error
	admins     []string
	lockBusy   bool
}

func (f *fakeStorageStore) TimescaleInfo(context.Context) (domain.TimescaleInfo, error) {
	return f.ts, nil
}

func (f *fakeStorageStore) TableStats(_ context.Context, t domain.RetentionTable, _ bool) (domain.TableStorageStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.stats[t.Name]
	if !ok {
		return domain.TableStorageStats{Exists: true}, nil
	}
	return st, nil
}

func (f *fakeStorageStore) ApplyRetention(ctx context.Context, changes []domain.RetentionApply, key string, value any) error {
	f.mu.Lock()
	if f.applyErr != nil {
		f.mu.Unlock()
		return f.applyErr
	}
	f.applied = append(f.applied, append([]domain.RetentionApply(nil), changes...))
	for _, c := range changes {
		st := f.stats[c.Table]
		st.Retention = domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: time.Duration(c.Days) * 24 * time.Hour}
		f.stats[c.Table] = st
	}
	f.mu.Unlock()
	if key != "" {
		return f.settings.SetJSON(ctx, key, value)
	}
	return nil
}

func (f *fakeStorageStore) DropChunksOlderThan(_ context.Context, table string, days int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dropped == nil {
		f.dropped = map[string]int{}
	}
	f.dropped[table] = days
	return 2, nil
}

func (f *fakeStorageStore) DeleteOlderThan(_ context.Context, t domain.RetentionTable, days int, limit int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, deleteCall{t.Name, days, limit})
	n := f.rowsOld[t.Name]
	if n > int64(limit) {
		n = int64(limit)
	}
	f.rowsOld[t.Name] -= n
	return n, nil
}

func (f *fakeStorageStore) DatabaseSize(context.Context) (int64, error) { return f.dbSize, nil }
func (f *fakeStorageStore) DataDirectory(context.Context) (string, error) {
	return f.dataDir, f.dataDirErr
}
func (f *fakeStorageStore) AdminEmails(context.Context) ([]string, error) { return f.admins, nil }
func (f *fakeStorageStore) TryRetentionLock(context.Context) (func(), bool, error) {
	return func() {}, !f.lockBusy, nil
}

var tsCommunity = domain.TimescaleInfo{Installed: true, Version: "2.30.1", License: "timescale"}

func policyStats(days int, compressAfter time.Duration) domain.TableStorageStats {
	return domain.TableStorageStats{
		Exists: true, Hypertable: true, CompressionEnabled: compressAfter > 0, CompressAfter: compressAfter,
		Retention: domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: time.Duration(days) * 24 * time.Hour},
	}
}

// newPolicyStore: every table a hypertable under the migration defaults.
func newPolicyStore() (*fakeStorageStore, *fakeSettings) {
	set := &fakeSettings{}
	st := &fakeStorageStore{ts: tsCommunity, settings: set, stats: map[string]domain.TableStorageStats{}, rowsOld: map[string]int64{}}
	for _, t := range domain.RetentionTables {
		st.stats[t.Name] = policyStats(t.DefaultDays, 24*time.Hour)
	}
	return st, set
}

func intp(v int) *int { return &v }

func TestRetentionModeByEnvironment(t *testing.T) {
	hyper := domain.TableStorageStats{Exists: true, Hypertable: true}
	plain := domain.TableStorageStats{Exists: true}
	cases := []struct {
		name string
		ts   domain.TimescaleInfo
		st   domain.TableStorageStats
		want string
	}{
		{"community", tsCommunity, hyper, RetentionModePolicy},
		{"apache", domain.TimescaleInfo{Installed: true, Version: "2.14.2", License: "apache"}, hyper, RetentionModeDropChunks},
		{"license unknown", domain.TimescaleInfo{Installed: true, Version: "2.14.2"}, hyper, RetentionModeDropChunks},
		{"too old", domain.TimescaleInfo{Installed: true, Version: "1.7.5", License: "timescale"}, hyper, RetentionModeNone},
		{"no timescaledb", domain.TimescaleInfo{}, plain, RetentionModeDelete},
		{"plain table beside timescaledb", tsCommunity, plain, RetentionModeDelete},
		{"missing table", tsCommunity, domain.TableStorageStats{}, RetentionModeNone},
	}
	for _, tc := range cases {
		if got, _ := retentionMode(tc.ts, tc.st); got != tc.want {
			t.Errorf("%s: mode %q, want %q", tc.name, got, tc.want)
		}
	}
	if timescaleNote(tsCommunity) != "" {
		t.Error("community TimescaleDB needs no note")
	}
	for _, ts := range []domain.TimescaleInfo{{}, {Installed: true, Version: "2.14.2", License: "apache"}, {Installed: true, Version: "1.7.5", License: "timescale"}} {
		if timescaleNote(ts) == "" {
			t.Errorf("%+v: the page must say why retention policies are unavailable", ts)
		}
	}
}

func TestUpdateRetentionValidation(t *testing.T) {
	store, set := newPolicyStore()
	s := &Storage{Store: store, Settings: set}
	ctx := context.Background()
	cases := []struct {
		name  string
		u     RetentionUpdate
		field string
		code  string
	}{
		{"empty", RetentionUpdate{}, "tables", ""},
		{"unknown table", RetentionUpdate{Tables: map[string]*int{"users": intp(30)}}, "tables.users", ""},
		{"below minimum", RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(6)}}, "tables.waf_decisions", ""},
		{"zero", RetentionUpdate{Tables: map[string]*int{"host_security_events": intp(0)}}, "tables.host_security_events", ""},
		{"above maximum", RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(3651)}}, "tables.waf_decisions", ""},
	}
	for _, tc := range cases {
		_, err := s.UpdateRetention(ctx, tc.u)
		var inv *StorageInvalid
		if !errors.As(err, &inv) || inv.Field != tc.field || inv.Code != tc.code {
			t.Errorf("%s: err %v, want field %q", tc.name, err, tc.field)
		}
	}
	if len(store.applied) != 0 || len(set.data) != 0 {
		t.Fatal("a rejected update must change nothing")
	}

	// Bounds are inclusive.
	if _, err := s.UpdateRetention(ctx, RetentionUpdate{Tables: map[string]*int{"host_security_events": intp(2), "waf_decisions": intp(3650)}}); err != nil {
		t.Fatalf("bounds: %v", err)
	}
}

func TestUpdateRetentionBelowCompressionWindow(t *testing.T) {
	store, set := newPolicyStore()
	st := store.stats["waf_decisions"]
	st.CompressAfter = 7 * 24 * time.Hour
	store.stats["waf_decisions"] = st
	s := &Storage{Store: store, Settings: set}
	_, err := s.UpdateRetention(context.Background(), RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(7)}})
	var inv *StorageInvalid
	if !errors.As(err, &inv) || inv.Code != "RETENTION_BELOW_COMPRESSION" {
		t.Fatalf("err %v, want RETENTION_BELOW_COMPRESSION", err)
	}
	if _, err := s.UpdateRetention(context.Background(), RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(8)}}); err != nil {
		t.Fatalf("8 days > 7-day window: %v", err)
	}
}

func TestUpdateRetentionAppliesPolicyAndSaves(t *testing.T) {
	store, set := newPolicyStore()
	s := &Storage{Store: store, Settings: set}
	ctx := context.Background()
	changes, err := s.UpdateRetention(ctx, RetentionUpdate{Tables: map[string]*int{
		"waf_decisions":        intp(14),
		"host_security_events": intp(7), // same as live: saved, no policy change
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := changes["waf_decisions"]; got.Old != 30 || got.New != 14 || got.Mode != RetentionModePolicy {
		t.Fatalf("change %+v", got)
	}
	if got := changes["host_security_events"]; got.Old != 7 || got.New != 7 {
		t.Fatalf("change %+v", got)
	}
	if len(store.applied) != 1 || len(store.applied[0]) != 1 || store.applied[0][0] != (domain.RetentionApply{Table: "waf_decisions", Days: 14}) {
		t.Fatalf("applied %+v", store.applied)
	}
	var rec retentionRecord
	_ = set.GetJSON(ctx, dataRetentionKey, &rec)
	if rec.Tables["waf_decisions"] != 14 || rec.Tables["host_security_events"] != 7 || len(rec.Tables) != 2 {
		t.Fatalf("saved %+v", rec)
	}

	// The shortened table's expired chunks are dropped at once.
	deadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		d, ok := store.dropped["waf_decisions"]
		store.mu.Unlock()
		if ok {
			if d != 14 {
				t.Fatalf("dropped older than %d days", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired chunks not dropped after shortening")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// null = back to the default: the saved value goes, the policy returns
	// to 30 days.
	changes, err = s.UpdateRetention(ctx, RetentionUpdate{Tables: map[string]*int{"waf_decisions": nil}})
	if err != nil {
		t.Fatal(err)
	}
	if got := changes["waf_decisions"]; got.Old != 14 || got.New != 30 || !got.Reset {
		t.Fatalf("reset change %+v", got)
	}
	rec = retentionRecord{}
	_ = set.GetJSON(ctx, dataRetentionKey, &rec)
	if _, ok := rec.Tables["waf_decisions"]; ok {
		t.Fatalf("reset must remove the saved value: %+v", rec)
	}
	if last := store.applied[len(store.applied)-1]; len(last) != 1 || last[0].Days != 30 {
		t.Fatalf("reset applied %+v", last)
	}
}

func TestUpdateRetentionFailureSavesNothing(t *testing.T) {
	store, set := newPolicyStore()
	store.applyErr = errors.New("tx failed")
	s := &Storage{Store: store, Settings: set}
	if _, err := s.UpdateRetention(context.Background(), RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(10)}}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("err %v", err)
	}
	if len(set.data) != 0 {
		t.Fatal("settings saved although the policy transaction failed")
	}
}

func TestUpdateRetentionRefusesUnsupportedTable(t *testing.T) {
	store, set := newPolicyStore()
	store.ts = domain.TimescaleInfo{Installed: true, Version: "1.7.5", License: "timescale"}
	s := &Storage{Store: store, Settings: set}
	_, err := s.UpdateRetention(context.Background(), RetentionUpdate{Tables: map[string]*int{"waf_decisions": intp(10)}})
	var inv *StorageInvalid
	if !errors.As(err, &inv) || inv.Code != "RETENTION_NOT_SUPPORTED" {
		t.Fatalf("err %v", err)
	}
}

func TestReconcileReappliesSavedValues(t *testing.T) {
	store, set := newPolicyStore()
	s := &Storage{Store: store, Settings: set}
	ctx := context.Background()

	// Nothing saved: the migration defaults stay, even when they differ.
	st := store.stats["waf_decisions"]
	st.Retention.DropAfter = 90 * 24 * time.Hour
	store.stats["waf_decisions"] = st
	if err := s.Reconcile(ctx); err != nil || len(store.applied) != 0 {
		t.Fatalf("nothing saved: err %v applied %+v", err, store.applied)
	}

	_ = set.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: map[string]int{"waf_decisions": 14, "host_fw_features": 30, "host_sec_features": 20}})
	// host_sec_features: the job was removed outside Wafio.
	st = store.stats["host_sec_features"]
	st.Retention = domain.RetentionPolicy{}
	store.stats["host_sec_features"] = st
	if err := s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(store.applied) != 1 {
		t.Fatalf("applied %+v", store.applied)
	}
	got := store.applied[0]
	if len(got) != 2 || got[0] != (domain.RetentionApply{Table: "waf_decisions", Days: 14}) || got[1] != (domain.RetentionApply{Table: "host_sec_features", Days: 20}) {
		t.Fatalf("applied %+v", got)
	}
	// Second run: everything matches.
	if err := s.Reconcile(ctx); err != nil || len(store.applied) != 1 {
		t.Fatalf("second reconcile: err %v applied %d", err, len(store.applied))
	}

	// Without policies (Apache) nothing is applied.
	store.ts.License = "apache"
	st = store.stats["waf_decisions"]
	st.Retention = domain.RetentionPolicy{}
	store.stats["waf_decisions"] = st
	if err := s.Reconcile(ctx); err != nil || len(store.applied) != 1 {
		t.Fatalf("apache reconcile: err %v applied %d", err, len(store.applied))
	}
}

// Without TimescaleDB the control plane deletes old rows itself, in bounded
// batches, with the saved retention or the migration default.
func TestRetentionPassDeletesPlainTables(t *testing.T) {
	set := &fakeSettings{}
	store := &fakeStorageStore{settings: set, stats: map[string]domain.TableStorageStats{}, rowsOld: map[string]int64{
		"waf_decisions":        12_000,
		"host_security_events": int64(deleteBatch) * (maxDeleteBatches + 3),
	}}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s := &Storage{Store: store, Settings: set, Now: func() time.Time { return now }}
	ctx := context.Background()
	_ = set.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: map[string]int{"waf_decisions": 14}})
	s.RunRetentionPass(ctx)

	var waf, sec []deleteCall
	for _, d := range store.deletes {
		switch d.table {
		case "waf_decisions":
			waf = append(waf, d)
		case "host_security_events":
			sec = append(sec, d)
		}
		if d.limit != deleteBatch {
			t.Fatalf("batch %d", d.limit)
		}
	}
	// The cutoff is passed as days: the database computes it on its own
	// clock, never from the control-plane clock (s.Now).
	if len(waf) != 3 || waf[0].days != 14 {
		t.Fatalf("waf_decisions: %d batches, days %d", len(waf), waf[0].days)
	}
	if len(sec) != maxDeleteBatches || sec[0].days != 7 {
		t.Fatalf("host_security_events: %d batches (cap %d), days %d", len(sec), maxDeleteBatches, sec[0].days)
	}
	if store.rowsOld["host_security_events"] != int64(deleteBatch)*3 {
		t.Fatalf("left for the next pass: %d", store.rowsOld["host_security_events"])
	}

	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range st.Tables {
		if v.Mode != RetentionModeDelete || !v.Active || v.LastRunAt == nil {
			t.Fatalf("%s: mode %s active %v last run %v", v.Table, v.Mode, v.Active, v.LastRunAt)
		}
		if v.Table == "waf_decisions" && (*v.LastRunDeleted != 12_000 || v.RetentionDays != 14 || !v.Saved) {
			t.Fatalf("waf_decisions view %+v", v)
		}
	}
	if st.TimescaleDB.Installed || st.TimescaleDB.Note == "" {
		t.Fatalf("timescaledb view %+v", st.TimescaleDB)
	}
	m := s.MetricsTables()
	if len(m) != len(domain.RetentionTables) || m[0].DeletedByPass != 12_000 {
		t.Fatalf("metrics %+v", m)
	}

	// Another process holds the lock: nothing runs.
	store.deletes, store.lockBusy = nil, true
	store.rowsOld["waf_decisions"] = 10
	s.RunRetentionPass(ctx)
	if len(store.deletes) != 0 {
		t.Fatal("pass ran without the lock")
	}
}

func TestRetentionPassDropChunksWithoutPolicies(t *testing.T) {
	store, set := newPolicyStore()
	store.ts.License = "apache"
	s := &Storage{Store: store, Settings: set}
	s.RunRetentionPass(context.Background())
	for _, tb := range domain.RetentionTables {
		if store.dropped[tb.Name] != tb.DefaultDays {
			t.Fatalf("%s dropped older than %d, want %d", tb.Name, store.dropped[tb.Name], tb.DefaultDays)
		}
	}
	// With policies the pass leaves the tables to TimescaleDB.
	store2, set2 := newPolicyStore()
	(&Storage{Store: store2, Settings: set2}).RunRetentionPass(context.Background())
	if len(store2.dropped) != 0 || len(store2.deletes) != 0 {
		t.Fatal("policy tables must be left to TimescaleDB")
	}
}

func TestPolicyTableInactiveReasons(t *testing.T) {
	now := time.Now().UTC()
	tb := domain.RetentionTables[0]
	s := &Storage{}
	cases := []struct {
		name   string
		pol    domain.RetentionPolicy
		saved  map[string]int
		active bool
		days   int
	}{
		{"default policy", domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: 30 * 24 * time.Hour}, nil, true, 30},
		{"operator policy", domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: 45 * 24 * time.Hour}, nil, true, 45},
		{"missing", domain.RetentionPolicy{}, nil, false, 30},
		{"paused", domain.RetentionPolicy{Exists: true, DropAfter: 30 * 24 * time.Hour}, nil, false, 30},
		{"failed", domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: 30 * 24 * time.Hour, LastStatus: "Failed"}, nil, false, 30},
		{"drift", domain.RetentionPolicy{Exists: true, Scheduled: true, DropAfter: 30 * 24 * time.Hour}, map[string]int{tb.Name: 14}, false, 14},
	}
	for _, tc := range cases {
		v := s.tableView(tb, tsCommunity, domain.TableStorageStats{Exists: true, Hypertable: true, Retention: tc.pol}, tc.saved, now)
		if v.Active != tc.active || v.RetentionDays != tc.days || (!v.Active && v.InactiveReason == "") {
			t.Errorf("%s: active %v days %d reason %q", tc.name, v.Active, v.RetentionDays, v.InactiveReason)
		}
	}
}

func TestEstimateIngest(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	day := func(d int) time.Time { return time.Date(2026, 10, 17-d, 0, 0, 0, 0, time.UTC) }
	st := domain.TableStorageStats{
		Hypertable: true, CompressionEnabled: true, BeforeBytes: 600, AfterBytes: 100,
		Chunks: []domain.StorageChunk{
			{Start: day(20), End: day(19), Compressed: true, Bytes: 999}, // older than 8 days: ignored
			{Start: day(3), End: day(2), Compressed: true, Bytes: 100},
			{Start: day(2), End: day(1), Compressed: true, Bytes: 100},
			{Start: day(1), End: day(0), Compressed: false, Bytes: 600},  // yesterday, compresses to ~100
			{Start: day(0), End: day(-1), Compressed: false, Bytes: 300}, // today: incomplete
		},
	}
	per, span := estimateIngest(st, now)
	if per == nil || *per != 100 {
		t.Fatalf("ingest %v", per)
	}
	if math.Abs(span-20.5) > 0.01 {
		t.Fatalf("span %v", span)
	}
	if per, _ := estimateIngest(domain.TableStorageStats{Exists: true}, now); per != nil {
		t.Fatal("plain tables have no chunk estimate")
	}
}

func TestComputeSizeStatusLevelsAndProjection(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	const gb = int64(1_000_000_000)
	unknownFS := FilesystemStatus{Reason: "unknown"}
	cases := []struct {
		size, budget int64
		want         string
	}{
		{79 * gb, 100 * gb, SizeLevelOK},
		{80 * gb, 100 * gb, SizeLevelWarning},
		{94 * gb, 100 * gb, SizeLevelWarning},
		{95 * gb, 100 * gb, SizeLevelCritical},
		{120 * gb, 100 * gb, SizeLevelCritical},
		{50 * gb, 0, SizeLevelNone},
	}
	for _, tc := range cases {
		st := computeSizeStatus(tc.size, tc.budget, unknownFS, nil, nil, now)
		if st.Level != tc.want {
			t.Errorf("%d/%d: level %s, want %s", tc.size, tc.budget, st.Level, tc.want)
		}
	}

	// The filesystem raises the level above the budget's.
	free, total := 4*gb, 100*gb
	used := 0.96
	fs := FilesystemStatus{Known: true, FreeBytes: &free, TotalBytes: &total, UsedRatio: &used}
	st := computeSizeStatus(10*gb, 100*gb, fs, nil, nil, now)
	if st.Level != SizeLevelCritical || st.LevelReason != "filesystem" {
		t.Fatalf("filesystem level %s/%s", st.Level, st.LevelReason)
	}

	// Two tables at 1 GB/day: one at its retention (no net growth), one
	// with 10 days to go — 10 GB more, then stable.
	in := 1.0 * float64(gb)
	tables := []TableRetentionView{
		{IngestBytesPerDay: &in, remainingDays: 0},
		{IngestBytesPerDay: &in, remainingDays: 10},
	}
	st = computeSizeStatus(50*gb, 100*gb, unknownFS, tables, nil, now)
	if st.GrowthSource != "chunks" || *st.IngestBytesPerDay != 2*in || *st.GrowthBytesPerDay != in {
		t.Fatalf("growth %+v", st)
	}
	if *st.ProjectedSizeBytes != 60*gb || st.Projection != "stable" || st.DaysUntilFull != nil {
		t.Fatalf("projection %v %s %v", *st.ProjectedSizeBytes, st.Projection, st.DaysUntilFull)
	}
	st = computeSizeStatus(50*gb, 55*gb, unknownFS, tables, nil, now)
	if st.Projection != "fills" || st.DaysUntilFull == nil || math.Abs(*st.DaysUntilFull-5) > 0.1 {
		t.Fatalf("fills in %v", st.DaysUntilFull)
	}
	// A table whose retention does not run grows without bound.
	tables[0].remainingDays = math.Inf(1)
	st = computeSizeStatus(50*gb, 100*gb, unknownFS, tables, nil, now)
	if st.ProjectedSizeBytes != nil || st.Projection != "fills" || st.DaysUntilFull == nil || math.Abs(*st.DaysUntilFull-40) > 0.2 {
		t.Fatalf("unbounded: projected %v, full in %v", st.ProjectedSizeBytes, st.DaysUntilFull)
	}

	// Plain tables: growth observed from samples once they span 6 h.
	samples := []sizeSample{{now.Add(-5 * time.Hour), 10 * gb}, {now, 11 * gb}}
	if st := computeSizeStatus(11*gb, 20*gb, unknownFS, nil, samples, now); st.GrowthSource != "unknown" {
		t.Fatalf("5 h of samples: %s", st.GrowthSource)
	}
	samples[0].At = now.Add(-12 * time.Hour)
	st = computeSizeStatus(11*gb, 20*gb, unknownFS, nil, samples, now)
	if st.GrowthSource != "observed" || *st.GrowthBytesPerDay != float64(2*gb) || math.Abs(*st.DaysUntilFull-4.5) > 0.1 {
		t.Fatalf("observed %+v", st)
	}
}

func TestFilesystemDetection(t *testing.T) {
	ctx := context.Background()
	const gb = uint64(1_000_000_000)
	ok := func(string) (uint64, uint64, error) { return 40 * gb, 100 * gb, nil }
	cases := []struct {
		name   string
		host   string
		dir    string
		dirErr error
		usage  func(string) (uint64, uint64, error)
		known  bool
		reason string
	}{
		{"local socket", "/var/run/postgresql", "/var/lib/postgresql/17/main", nil, ok, true, ""},
		{"loopback", "127.0.0.1", "/data", nil, ok, true, ""},
		{"remote", "db.internal", "/data", nil, ok, false, "another host"},
		{"no pg_read_all_settings", "localhost", "", errors.New("permission denied"), ok, false, "pg_read_all_settings"},
		{"not reachable", "localhost", "/data", nil, func(string) (uint64, uint64, error) { return 0, 0, errors.New("EACCES") }, false, "not reachable"},
		{"wrong disk", "localhost", "/data", nil, func(string) (uint64, uint64, error) { return 1, 2 * gb, nil }, false, "does not hold"},
	}
	for _, tc := range cases {
		s := &Storage{Store: &fakeStorageStore{dataDir: tc.dir, dataDirErr: tc.dirErr}, DatabaseHost: tc.host, FSUsage: tc.usage}
		fs := s.filesystem(ctx, int64(5*gb))
		if fs.Known != tc.known || (tc.reason != "" && !strings.Contains(fs.Reason, tc.reason)) {
			t.Errorf("%s: known %v reason %q", tc.name, fs.Known, fs.Reason)
		}
		if fs.Known && (*fs.FreeBytes != int64(40*gb) || *fs.UsedRatio != 0.6) {
			t.Errorf("%s: %+v", tc.name, fs)
		}
	}
}

type fakeMail struct {
	host string
	mu   sync.Mutex
	sent []string
}

func (m *fakeMail) Current(context.Context) (MailState, error) {
	var st MailState
	st.Server.Host = m.host
	st.BaseURL = "https://dash.example.test"
	return st, nil
}
func (m *fakeMail) Mailer() domain.Mailer { return sizeAlertMailer{m} }

type sizeAlertMailer struct{ m *fakeMail }

func (f sizeAlertMailer) Send(to, subject, body string) error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.sent = append(f.m.sent, to+"|"+subject+"|"+body)
	return nil
}

func TestSizeAlertMailsOncePerLevelPerDay(t *testing.T) {
	const gb = int64(1_000_000_000)
	store, set := newPolicyStore()
	store.admins = []string{"b@example.test", "a@example.test"}
	store.dbSize = 50 * gb
	store.dataDirErr = errors.New("denied")
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	mail := &fakeMail{host: "smtp.example.test"}
	s := &Storage{Store: store, Settings: set, Mail: mail, Now: func() time.Time { return now }, DatabaseHost: "localhost"}
	ctx := context.Background()
	if _, _, err := s.UpdateBudget(ctx, BudgetUpdate{BudgetGB: ptrF(100)}); err != nil {
		t.Fatal(err)
	}

	s.CheckSize(ctx)
	if len(mail.sent) != 0 || s.Alert().Level != SizeLevelOK {
		t.Fatalf("ok: level %s, %d mails", s.Alert().Level, len(mail.sent))
	}
	store.dbSize = 85 * gb
	s.CheckSize(ctx)
	if s.Alert().Level != SizeLevelWarning || len(mail.sent) != 2 {
		t.Fatalf("warning: level %s, %d mails", s.Alert().Level, len(mail.sent))
	}
	if !strings.HasPrefix(mail.sent[0], "a@example.test|Wafio: database size warning|") || !strings.Contains(mail.sent[0], "https://dash.example.test/admin/retention") {
		t.Fatalf("mail %q", mail.sent[0])
	}
	// Same level: nothing new.
	s.CheckSize(ctx)
	// Down and up again within 24 h: no second warning mail.
	store.dbSize = 50 * gb
	s.CheckSize(ctx)
	store.dbSize = 85 * gb
	s.CheckSize(ctx)
	if len(mail.sent) != 2 {
		t.Fatalf("warning re-mailed within 24 h: %d", len(mail.sent))
	}
	// Critical is its own level.
	store.dbSize = 96 * gb
	s.CheckSize(ctx)
	if len(mail.sent) != 4 || !strings.Contains(mail.sent[2], "critical") {
		t.Fatalf("critical: %d mails", len(mail.sent))
	}
	// A restart keeps the state: no repeat.
	s2 := &Storage{Store: store, Settings: set, Mail: mail, Now: func() time.Time { return now.Add(time.Hour) }}
	s2.CheckSize(ctx)
	if len(mail.sent) != 4 {
		t.Fatalf("restart re-mailed: %d", len(mail.sent))
	}
	// After 24 h a new crossing mails again.
	store.dbSize = 50 * gb
	s2.CheckSize(ctx)
	s2.Now = func() time.Time { return now.Add(25 * time.Hour) }
	store.dbSize = 85 * gb
	s2.CheckSize(ctx)
	if len(mail.sent) != 6 {
		t.Fatalf("after 24 h: %d mails", len(mail.sent))
	}

	// No mail server: nothing sent, nothing recorded as sent.
	store3, set3 := newPolicyStore()
	store3.admins, store3.dbSize, store3.dataDirErr = []string{"a@example.test"}, 90*gb, errors.New("denied")
	m3 := &fakeMail{}
	s3 := &Storage{Store: store3, Settings: set3, Mail: m3}
	_, _, _ = s3.UpdateBudget(ctx, BudgetUpdate{BudgetGB: ptrF(100)})
	s3.CheckSize(ctx)
	if len(m3.sent) != 0 || s3.Alert().Level != SizeLevelWarning {
		t.Fatalf("no server: %d mails, level %s", len(m3.sent), s3.Alert().Level)
	}
	var rec alertState
	_ = set3.GetJSON(ctx, dbSizeAlertKey, &rec)
	if rec.Level != SizeLevelWarning || len(rec.Sent) != 0 {
		t.Fatalf("state %+v", rec)
	}
}

func ptrF(f float64) *float64 { return &f }

func TestUpdateBudgetBounds(t *testing.T) {
	_, set := newPolicyStore()
	s := &Storage{Settings: set}
	ctx := context.Background()
	for _, gb := range []float64{0, 0.09, -1, 1_000_001, math.NaN(), math.Inf(1)} {
		if _, _, err := s.UpdateBudget(ctx, BudgetUpdate{BudgetGB: ptrF(gb)}); err == nil {
			t.Errorf("%v GB accepted", gb)
		}
	}
	old, nw, err := s.UpdateBudget(ctx, BudgetUpdate{BudgetGB: ptrF(0.5)})
	if err != nil || old != 0 || nw != 500_000_000 {
		t.Fatalf("0.5 GB: %d → %d, %v", old, nw, err)
	}
	old, nw, err = s.UpdateBudget(ctx, BudgetUpdate{})
	if err != nil || old != 500_000_000 || nw != 0 {
		t.Fatalf("remove: %d → %d, %v", old, nw, err)
	}
}

func TestDatabaseIsLocal(t *testing.T) {
	for host, want := range map[string]bool{
		"": true, "localhost": true, "127.0.0.1": true, "::1": true, "[::1]": true, "/tmp": true,
		"10.0.0.5": false, "db.example.test": false,
	} {
		if databaseIsLocal(host) != want {
			t.Errorf("%q: want %v", host, want)
		}
	}
}

// A stored value out of range (manual SQL, a restore, a bug) is never
// applied or clamped: the table is skipped and shown as not active.
func TestCorruptSavedRetentionSkipsTable(t *testing.T) {
	ctx := context.Background()
	corrupt := map[string]int{
		"waf_decisions":           0,
		"host_security_events":    -3,
		"host_enforcement_events": 1, // below the table's minimum
		"host_fw_features":        domain.RetentionMaxDays + 1,
	}

	// Plain tables (delete mode).
	set := &fakeSettings{}
	store := &fakeStorageStore{settings: set, stats: map[string]domain.TableStorageStats{}, rowsOld: map[string]int64{}}
	for _, tb := range domain.RetentionTables {
		store.rowsOld[tb.Name] = 10
	}
	s := &Storage{Store: store, Settings: set}
	_ = set.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: corrupt})
	s.RunRetentionPass(ctx)
	for _, d := range store.deletes {
		if _, bad := corrupt[d.table]; bad {
			t.Fatalf("delete on %s with a corrupt retention (%d days)", d.table, d.days)
		}
	}
	if len(store.deletes) != 1 || store.deletes[0].table != "host_sec_features" || store.deletes[0].days != 30 {
		t.Fatalf("deletes %+v", store.deletes)
	}
	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range st.Tables {
		_, bad := corrupt[v.Table]
		if bad != !v.Active || (bad && (!strings.Contains(v.InactiveReason, "outside") || v.RetentionDays != v.DefaultDays)) {
			t.Fatalf("%s: active %v days %d reason %q", v.Table, v.Active, v.RetentionDays, v.InactiveReason)
		}
	}

	// Hypertables without policies (drop_chunks mode).
	store2, set2 := newPolicyStore()
	store2.ts.License = "apache"
	_ = set2.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: corrupt})
	(&Storage{Store: store2, Settings: set2}).RunRetentionPass(ctx)
	if len(store2.dropped) != 1 || store2.dropped["host_sec_features"] != 30 {
		t.Fatalf("dropped %+v", store2.dropped)
	}

	// Policy tables: reconcile leaves the live policy alone.
	store3, set3 := newPolicyStore()
	_ = set3.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: corrupt})
	s3 := &Storage{Store: store3, Settings: set3}
	if err := s3.Reconcile(ctx); err != nil || len(store3.applied) != 0 {
		t.Fatalf("reconcile: err %v applied %+v", err, store3.applied)
	}
	tb := domain.RetentionTables[0]
	v := s3.tableView(tb, tsCommunity, store3.stats[tb.Name], corrupt, time.Now())
	if v.Active || v.RetentionDays != 30 || !strings.Contains(v.InactiveReason, "outside") {
		t.Fatalf("policy view: active %v days %d reason %q", v.Active, v.RetentionDays, v.InactiveReason)
	}
}

// The first control-plane pass waits an hour after the first start of this
// version; later starts do not restart the wait.
func TestFirstPassWaitsForUpgradeGrace(t *testing.T) {
	ctx := context.Background()
	set := &fakeSettings{}
	store := &fakeStorageStore{settings: set, stats: map[string]domain.TableStorageStats{}, rowsOld: map[string]int64{"waf_decisions": 10}}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := &Storage{Store: store, Settings: set, Now: clock}

	if d := s.firstPassDelay(ctx); d != retentionGrace {
		t.Fatalf("first start: delay %v", d)
	}
	var rec graceRecord
	if err := set.GetJSON(ctx, dataRetentionGraceKey, &rec); err != nil || !rec.NotBefore.Equal(now.Add(retentionGrace)) {
		t.Fatalf("grace record %+v, %v", rec, err)
	}
	// A save's kick during the grace deletes nothing.
	s.RunRetentionPass(ctx)
	if len(store.deletes) != 0 {
		t.Fatal("pass ran during the grace")
	}
	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range st.Tables {
		if v.Active || !strings.Contains(v.InactiveReason, "Retention starts at 2026-10-17 13:00 UTC") {
			t.Fatalf("%s during grace: active %v reason %q", v.Table, v.Active, v.InactiveReason)
		}
	}

	// A restart 40 minutes later waits only the rest.
	now = now.Add(40 * time.Minute)
	s2 := &Storage{Store: store, Settings: set, Now: clock}
	if d := s2.firstPassDelay(ctx); d != 20*time.Minute {
		t.Fatalf("restart in grace: delay %v", d)
	}
	// After the grace: the usual minute.
	now = now.Add(2 * time.Hour)
	s3 := &Storage{Store: store, Settings: set, Now: clock}
	if d := s3.firstPassDelay(ctx); d != retentionFirstRun {
		t.Fatalf("after grace: delay %v", d)
	}
	s3.RunRetentionPass(ctx)
	if len(store.deletes) == 0 {
		t.Fatal("no pass after the grace")
	}

	// A record written by a clock that was far ahead waits at most the grace.
	_ = set.SetJSON(ctx, dataRetentionGraceKey, graceRecord{NotBefore: now.Add(365 * 24 * time.Hour)})
	if d := (&Storage{Store: store, Settings: set, Now: clock}).firstPassDelay(ctx); d != retentionGrace {
		t.Fatalf("future record: delay %v", d)
	}
	// Unreadable record: the full grace.
	bad := &fakeSettings{fail: true}
	if d := (&Storage{Store: store, Settings: bad, Now: clock}).firstPassDelay(ctx); d != retentionGrace {
		t.Fatalf("unreadable record: delay %v", d)
	}

	// The timer ending the grace clears it even if the wall clock lags.
	s4 := &Storage{Store: store, Settings: &fakeSettings{}, Now: clock}
	_ = s4.firstPassDelay(ctx)
	s4.endGrace()
	if s4.inGrace() {
		t.Fatal("grace not ended")
	}
}
