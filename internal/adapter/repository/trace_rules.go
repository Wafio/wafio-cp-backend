package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/lru"
)

// DetectionRulesRepo handles CRUD for per-host trace detection rules.
// Rules are cached in memory for 30s to avoid per-event DB round-trips.
type DetectionRulesRepo struct {
	pool *pgxpool.Pool
	// cache maps "projectID:hostID" → (rules, fetchedAt). Bounded:
	// it used to be a plain map that the REST list filled for any ?host_id=
	// a caller named, and nothing ever removed an entry.
	cache *lru.Cache[rulesCache]
	// onChange: SetChangeHook.
	onChange atomic.Pointer[func(projectID, hostID string)]
}

type rulesCache struct {
	rules     []domain.DetectionRule
	fetchedAt time.Time
}

const rulesCacheTTL = 30 * time.Second

// rulesCacheMax bounds the cached rule sets: one per host whose telemetry
// was ingested in the last 30 s is what the cache is for.
const rulesCacheMax = 16384

func NewDetectionRulesRepo(pool *pgxpool.Pool) *DetectionRulesRepo {
	return &DetectionRulesRepo{
		pool:  pool,
		cache: lru.New[rulesCache](rulesCacheMax),
	}
}

func cacheKey(projectID, hostID string) string { return projectID + ":" + hostID }

// ListRules returns all detection rules for a host, sorted by priority asc.
// Results are cached for 30s.
func (r *DetectionRulesRepo) ListRules(ctx context.Context, projectID, hostID string) ([]domain.DetectionRule, error) {
	key := cacheKey(projectID, hostID)
	var cached rulesCache
	if r.cache.Get(key, func(v *rulesCache) { cached = *v }) && time.Since(cached.fetchedAt) < rulesCacheTTL {
		return cached.rules, nil
	}

	rules, err := r.fetchRules(ctx, projectID, hostID)
	if err != nil {
		return nil, err
	}

	r.cache.Update(key, func(v *rulesCache, _ bool) { *v = rulesCache{rules: rules, fetchedAt: time.Now()} })
	return rules, nil
}

// ListRulesUncached bypasses the cache — used in the REST API to always show
// current data. It does not fill the cache: the REST caller names the host,
// and the ingest path (ListRules) caches what it needs.
func (r *DetectionRulesRepo) ListRulesUncached(ctx context.Context, projectID, hostID string) ([]domain.DetectionRule, error) {
	return r.fetchRules(ctx, projectID, hostID)
}

func (r *DetectionRulesRepo) fetchRules(ctx context.Context, projectID, hostID string) ([]domain.DetectionRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, project_id, host_id, name, description, enabled, built_in, action,
		        conditions, severity_override, priority, tags,
		        hit_count, last_hit_at, created_at, updated_at
		 FROM trace_detection_rules
		 WHERE project_id = $1 AND host_id = $2
		 ORDER BY priority ASC, created_at ASC`,
		projectID, hostID,
	)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	rules := []domain.DetectionRule{}
	for rows.Next() {
		dr, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, dr)
	}
	return rules, rows.Err()
}

// GetRule returns a single rule by ID, scoped to the project and host.
func (r *DetectionRulesRepo) GetRule(ctx context.Context, id, projectID, hostID string) (domain.DetectionRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, project_id, host_id, name, description, enabled, built_in, action,
		        conditions, severity_override, priority, tags,
		        hit_count, last_hit_at, created_at, updated_at
		 FROM trace_detection_rules
		 WHERE id = $1 AND project_id = $2 AND host_id = $3`,
		id, projectID, hostID,
	)
	if err != nil {
		return domain.DetectionRule{}, fmt.Errorf("get rule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		// A read error also ends Next(); report it, not "not found".
		if err := rows.Err(); err != nil {
			return domain.DetectionRule{}, fmt.Errorf("get rule: %w", err)
		}
		return domain.DetectionRule{}, fmt.Errorf("rule not found")
	}
	return scanRule(rows)
}

// CreateRule inserts a new detection rule and invalidates the cache.
func (r *DetectionRulesRepo) CreateRule(ctx context.Context, dr domain.DetectionRule) (domain.DetectionRule, error) {
	conds, err := json.Marshal(dr.Conditions)
	if err != nil {
		return domain.DetectionRule{}, fmt.Errorf("marshal conditions: %w", err)
	}

	tags := dr.Tags
	if tags == nil {
		tags = []string{}
	}

	var created domain.DetectionRule
	var condJSON []byte
	err = r.pool.QueryRow(ctx,
		`INSERT INTO trace_detection_rules
		   (project_id, host_id, name, description, enabled, built_in, action,
		    conditions, severity_override, priority, tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id, project_id, host_id, name, description, enabled, built_in, action,
		           conditions, severity_override, priority, tags,
		           hit_count, last_hit_at, created_at, updated_at`,
		dr.ProjectID, dr.HostID, dr.Name, dr.Description, dr.Enabled, dr.BuiltIn, dr.Action,
		conds, dr.SeverityOverride, dr.Priority, tags,
	).Scan(
		&created.ID, &created.ProjectID, &created.HostID, &created.Name, &created.Description,
		&created.Enabled, &created.BuiltIn, &created.Action,
		&condJSON, &created.SeverityOverride, &created.Priority, &created.Tags,
		&created.HitCount, &created.LastHitAt, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return domain.DetectionRule{}, fmt.Errorf("create rule: %w", err)
	}
	if err := json.Unmarshal(condJSON, &created.Conditions); err != nil {
		return domain.DetectionRule{}, fmt.Errorf("unmarshal conditions: %w", err)
	}

	r.rulesChanged(ctx, dr.ProjectID, dr.HostID)
	return created, nil
}

// UpdateRule updates a rule's mutable fields. Built-in rules allow toggling
// enabled/disabled only; other fields are ignored for built-in rules.
func (r *DetectionRulesRepo) UpdateRule(ctx context.Context, dr domain.DetectionRule) (domain.DetectionRule, error) {
	conds, err := json.Marshal(dr.Conditions)
	if err != nil {
		return domain.DetectionRule{}, fmt.Errorf("marshal conditions: %w", err)
	}

	tags := dr.Tags
	if tags == nil {
		tags = []string{}
	}

	var updated domain.DetectionRule
	var condJSON []byte
	err = r.pool.QueryRow(ctx,
		`UPDATE trace_detection_rules SET
		   name             = CASE WHEN built_in THEN name             ELSE $4  END,
		   description      = CASE WHEN built_in THEN description      ELSE $5  END,
		   enabled          = $6,
		   action           = CASE WHEN built_in THEN action           ELSE $7  END,
		   conditions       = CASE WHEN built_in THEN conditions       ELSE $8  END,
		   severity_override= CASE WHEN built_in THEN severity_override ELSE $9 END,
		   priority         = CASE WHEN built_in THEN priority         ELSE $10 END,
		   tags             = CASE WHEN built_in THEN tags             ELSE $11 END,
		   updated_at       = NOW()
		 WHERE id = $1 AND project_id = $2 AND host_id = $3
		 RETURNING id, project_id, host_id, name, description, enabled, built_in, action,
		           conditions, severity_override, priority, tags,
		           hit_count, last_hit_at, created_at, updated_at`,
		dr.ID, dr.ProjectID, dr.HostID,
		dr.Name, dr.Description, dr.Enabled,
		dr.Action, conds, dr.SeverityOverride, dr.Priority, tags,
	).Scan(
		&updated.ID, &updated.ProjectID, &updated.HostID, &updated.Name, &updated.Description,
		&updated.Enabled, &updated.BuiltIn, &updated.Action,
		&condJSON, &updated.SeverityOverride, &updated.Priority, &updated.Tags,
		&updated.HitCount, &updated.LastHitAt, &updated.CreatedAt, &updated.UpdatedAt,
	)
	if err != nil {
		return domain.DetectionRule{}, fmt.Errorf("update rule: %w", err)
	}
	if err := json.Unmarshal(condJSON, &updated.Conditions); err != nil {
		return domain.DetectionRule{}, fmt.Errorf("unmarshal conditions: %w", err)
	}

	r.rulesChanged(ctx, dr.ProjectID, dr.HostID)
	return updated, nil
}

// DeleteRule deletes a user-created rule. Returns an error if the rule is built-in.
func (r *DetectionRulesRepo) DeleteRule(ctx context.Context, id, projectID, hostID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM trace_detection_rules
		 WHERE id = $1 AND project_id = $2 AND host_id = $3 AND built_in = false`,
		id, projectID, hostID,
	)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rule not found or is built-in")
	}
	r.rulesChanged(ctx, projectID, hostID)
	return nil
}

// IncrementHitCounts records all hits from one admitted telemetry batch.
func (r *DetectionRulesRepo) IncrementHitCounts(ctx context.Context, projectID string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	body, _ := json.Marshal(counts)
	_, _ = r.pool.Exec(ctx,
		`UPDATE trace_detection_rules AS rule
		 SET hit_count = rule.hit_count + hits.value::bigint, last_hit_at = NOW()
		 FROM jsonb_each_text($1::jsonb) AS hits(key, value)
		 WHERE rule.id = hits.key::uuid AND rule.project_id = $2`,
		string(body), projectID,
	)
}

// SeedBuiltinRules inserts the built-in detection rule library for a host.
// Existing built-ins, including disabled rules, are preserved on repeated calls.
func (r *DetectionRulesRepo) SeedBuiltinRules(ctx context.Context, projectID, hostID string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin seed built-in rules: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// No unique constraint covers built-in names. Serialize seeders per host,
	// then use a fresh READ COMMITTED snapshot to see the preceding seed's inserts.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "trace-rule-seed:"+projectID+":"+hostID); err != nil {
		return fmt.Errorf("lock seed built-in rules: %w", err)
	}
	for _, rule := range builtinRules(projectID, hostID) {
		conds, err := json.Marshal(rule.Conditions)
		if err != nil {
			return fmt.Errorf("marshal built-in rule %q: %w", rule.Name, err)
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO trace_detection_rules
			   (project_id, host_id, name, description, enabled, built_in, action,
			    conditions, severity_override, priority, tags)
			 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
			 WHERE NOT EXISTS (
			   SELECT 1 FROM trace_detection_rules
			   WHERE project_id = $1 AND host_id = $2 AND name = $3 AND built_in
			 )`,
			projectID, hostID, rule.Name, rule.Description, rule.Enabled, true, rule.Action,
			conds, rule.SeverityOverride, rule.Priority, rule.Tags,
		)
		if err != nil {
			return fmt.Errorf("seed built-in rule %q: %w", rule.Name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit seed built-in rules: %w", err)
	}
	r.rulesChanged(ctx, projectID, hostID)
	return nil
}

// EnsureBuiltinRules seeds the built-in library for a host that has none yet
// (a host that predates per-host seeding). A host that already has built-ins
// is left alone, so a disabled or migrated built-in is never re-inserted.
// Called before the first rule write for a host; reads never seed.
func (r *DetectionRulesRepo) EnsureBuiltinRules(ctx context.Context, projectID, hostID string) error {
	var seeded bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM trace_detection_rules
		                WHERE project_id = $1 AND host_id = $2 AND built_in)`,
		projectID, hostID,
	).Scan(&seeded)
	if err != nil {
		return fmt.Errorf("check built-in rules: %w", err)
	}
	if seeded {
		return nil
	}
	return r.SeedBuiltinRules(ctx, projectID, hostID)
}

// SeedUnseededHosts seeds the built-in library for every host that has no
// built-in rule yet, and returns how many hosts it seeded. It runs once at
// control-plane startup: seeding used to happen inside
// GET /host/trace/rules, which made a viewer's read perform writes.
func (r *DetectionRulesRepo) SeedUnseededHosts(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT h.id::text, h.project_id::text
		   FROM hosts h
		  WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r
		                     WHERE r.host_id = h.id AND r.project_id = h.project_id AND r.built_in)`)
	if err != nil {
		return 0, fmt.Errorf("list unseeded hosts: %w", err)
	}
	type hostRef struct{ id, projectID string }
	hosts := []hostRef{}
	for rows.Next() {
		var h hostRef
		if err := rows.Scan(&h.id, &h.projectID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan unseeded host: %w", err)
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("list unseeded hosts: %w", err)
	}
	seeded := 0
	for _, h := range hosts {
		if err := r.SeedBuiltinRules(ctx, h.projectID, h.id); err != nil {
			return seeded, err
		}
		seeded++
	}
	return seeded, nil
}

// SetChangeHook installs fn, called after every committed write to a host's
// rules (create, update, toggle, delete, built-in seeding) once the cache
// entry is gone, so the next ListRules reads the new set. The control plane
// sends trace forwarding filters through it. fn must not
// block; nil removes the hook.
func (r *DetectionRulesRepo) SetChangeHook(fn func(projectID, hostID string)) {
	if fn == nil {
		r.onChange.Store(nil)
		return
	}
	r.onChange.Store(&fn)
}

// rulesChanged drops the host's cached rules and tells the change hook, or,
// for a write under DeferChangeHook's context, records the host for its
// flush.
func (r *DetectionRulesRepo) rulesChanged(ctx context.Context, projectID, hostID string) {
	r.cache.Delete(cacheKey(projectID, hostID))
	if d, ok := ctx.Value(deferredRuleChangesKey{}).(*deferredRuleChanges); ok && d.repo == r {
		d.add(projectID, hostID)
		return
	}
	if fn := r.onChange.Load(); fn != nil {
		(*fn)(projectID, hostID)
	}
}

// DeferChangeHook returns a context whose rule writes (through r) call the
// change hook not after each commit but once per host when flush runs, in
// first-write order. A bulk apply writes many rules per host; each would
// otherwise queue a forwarding-filter refresh. The cache is
// still dropped at each write. flush is idempotent; writes after it call
// the hook at once again.
func (r *DetectionRulesRepo) DeferChangeHook(ctx context.Context) (context.Context, func()) {
	d := &deferredRuleChanges{repo: r}
	return context.WithValue(ctx, deferredRuleChangesKey{}, d), d.flush
}

type deferredRuleChangesKey struct{}

type deferredRuleChanges struct {
	repo    *DetectionRulesRepo
	mu      sync.Mutex
	flushed bool
	seen    map[[2]string]struct{}
	order   [][2]string
}

func (d *deferredRuleChanges) add(projectID, hostID string) {
	k := [2]string{projectID, hostID}
	d.mu.Lock()
	if d.flushed {
		d.mu.Unlock()
		if fn := d.repo.onChange.Load(); fn != nil {
			(*fn)(projectID, hostID)
		}
		return
	}
	if _, ok := d.seen[k]; !ok {
		if d.seen == nil {
			d.seen = make(map[[2]string]struct{})
		}
		d.seen[k] = struct{}{}
		d.order = append(d.order, k)
	}
	d.mu.Unlock()
}

func (d *deferredRuleChanges) flush() {
	d.mu.Lock()
	order := d.order
	d.flushed, d.order, d.seen = true, nil, nil
	d.mu.Unlock()
	fn := d.repo.onChange.Load()
	if fn == nil {
		return
	}
	for _, k := range order {
		(*fn)(k[0], k[1])
	}
}

// scanRule reads one DetectionRule from a pgx Rows cursor.
func scanRule(rows interface {
	Scan(...any) error
}) (domain.DetectionRule, error) {
	var dr domain.DetectionRule
	var condJSON []byte
	if err := rows.Scan(
		&dr.ID, &dr.ProjectID, &dr.HostID, &dr.Name, &dr.Description,
		&dr.Enabled, &dr.BuiltIn, &dr.Action,
		&condJSON, &dr.SeverityOverride, &dr.Priority, &dr.Tags,
		&dr.HitCount, &dr.LastHitAt, &dr.CreatedAt, &dr.UpdatedAt,
	); err != nil {
		return domain.DetectionRule{}, fmt.Errorf("scan rule: %w", err)
	}
	if err := json.Unmarshal(condJSON, &dr.Conditions); err != nil {
		return domain.DetectionRule{}, fmt.Errorf("unmarshal conditions: %w", err)
	}
	if dr.Tags == nil {
		dr.Tags = []string{}
	}
	return dr, nil
}
