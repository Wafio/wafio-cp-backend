package repository

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
	"github.com/wafio/wafio-cp-backend/internal/lru"
)

// Host is defined in domain; the alias keeps this package's API.
type Host = domain.Host

// HostRepo is the CRUD + key-auth repository for hosts.
type HostRepo struct{ pool *pgxpool.Pool }

// ErrHostKeyInvalid is returned when verification fails (unknown prefix, no
// match, revoked). Handlers should treat this as 401 Unauthorized. It is
// domain.ErrHostKeyInvalid, so either matches with errors.Is.
var ErrHostKeyInvalid = domain.ErrHostKeyInvalid

// MaxHostsPerProject bounds the hosts of one project. The host list
// and fleet pages load a project's hosts whole, and a credential holder could
// otherwise create rows without end.
const MaxHostsPerProject = 10000

// hostsPerProjectLimit is the cap Create uses (tests lower it).
var hostsPerProjectLimit = MaxHostsPerProject

// ErrHostLimit is returned by Create when the project already has
// MaxHostsPerProject hosts.
var ErrHostLimit = errors.New("host limit reached for the project")

// Create inserts a new host and returns the freshly minted raw host key
// ONCE. Caller MUST surface the key to the user immediately — it cannot be
// recovered later. Returns ErrHostLimit when the project is full.
func (r *HostRepo) Create(ctx context.Context, userID, projectID, name string, labels map[string]string) (*Host, string, error) {
	raw, short, hash, err := keyauth.Generate(keyauth.KindHost)
	if err != nil {
		return nil, "", err
	}
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, _ := json.Marshal(labels)
	h := &Host{}
	// The count and the insert are one statement; two concurrent creates
	// can each pass the count, so the cap may be exceeded by the number of
	// creates racing at the limit, never more.
	// The new key opens an enrollment window (migration 000108).
	err = r.pool.QueryRow(ctx, `
		INSERT INTO hosts (user_id, project_id, name, labels, host_key_prefix, host_key_hash, host_key_lookup, enroll_expires_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(secs => $9)
		 WHERE (SELECT count(*) FROM hosts WHERE project_id = $2) < $8
		RETURNING id, user_id, project_id, name, host_key_prefix, status, created_at, enroll_expires_at`,
		userID, projectID, name, labelsJSON, short, hash, keyauth.LookupID(raw), hostsPerProjectLimit,
		domain.HostEnrollWindow.Seconds(),
	).Scan(&h.ID, &h.UserID, &h.ProjectID, &h.Name, &h.HostKeyPrefix, &h.Status, &h.CreatedAt, &h.EnrollExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrHostLimit
	}
	if err != nil {
		return nil, "", err
	}
	h.Labels = labels
	return h, raw, nil
}

// HostKeyGracePeriod is how long the previous Host Key remains valid after
// rotation so agents get a chance to reload their config without an outage.
// 10 minutes matches the plan's recommendation and is long enough for a
// scripted rollout across a small fleet.
const HostKeyGracePeriod = 10 * time.Minute

// ErrHostNotRotatable is returned by RotateKey for a host that is revoked,
// gone or of another project.
var ErrHostNotRotatable = errors.New("host not found or revoked")

// RotateKey mints a new Host Key while keeping the previous hash valid for
// HostKeyGracePeriod. Returns the new raw key (show once) and the end of the
// enrollment window the new key opens (domain.HostEnrollWindow).
//
// Old agents that still present the previous key continue to authenticate
// until the grace window elapses, at which point the next VerifyKey call
// will reject them (and a periodic sweeper will clear the columns). The
// previous key never enrolls (VerifyCurrentKey).
func (r *HostRepo) RotateKey(ctx context.Context, projectID, hostID string) (string, time.Time, error) {
	raw, short, hash, err := keyauth.Generate(keyauth.KindHost)
	if err != nil {
		return "", time.Time{}, err
	}
	// Scoped by project_id as the mandatory second isolation layer.
	var enrollUntil time.Time
	err = r.pool.QueryRow(ctx, `
		UPDATE hosts
		   SET prev_host_key_prefix     = host_key_prefix,
		       prev_host_key_hash       = host_key_hash,
		       prev_host_key_lookup     = host_key_lookup,
		       prev_host_key_expires_at = NOW() + make_interval(secs => $4),
		       host_key_prefix          = $2,
		       host_key_hash            = $3,
		       host_key_lookup          = $6,
		       enroll_expires_at        = NOW() + make_interval(secs => $7),
		       status                   = 'pending'
		 WHERE id = $1 AND revoked_at IS NULL AND project_id = $5
		RETURNING enroll_expires_at`,
		hostID, short, hash, HostKeyGracePeriod.Seconds(), projectID, keyauth.LookupID(raw),
		domain.HostEnrollWindow.Seconds(),
	).Scan(&enrollUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrHostNotRotatable
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, enrollUntil, nil
}

// PurgeExpiredPrevKeys clears any previous host keys whose grace window has
// elapsed. Intended to be called periodically by a background sweeper; it
// is also safe to call opportunistically.
func (r *HostRepo) PurgeExpiredPrevKeys(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE hosts
		   SET prev_host_key_prefix     = NULL,
		       prev_host_key_hash       = NULL,
		       prev_host_key_lookup     = NULL,
		       prev_host_key_expires_at = NULL
		 WHERE prev_host_key_expires_at IS NOT NULL
		   AND prev_host_key_expires_at <= NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Revoke marks the host (and its hash) as unusable without deleting the row,
// and closes its enrollment window. It leaves the host's enrolled
// credentials alone: the revoke endpoint uses RevokeWithCredentials.
// Scoped by project_id as the mandatory second isolation layer.
func (r *HostRepo) Revoke(ctx context.Context, projectID, hostID string) error {
	_, err := r.pool.Exec(ctx, revokeHostSQL, hostID, projectID)
	return err
}

const revokeHostSQL = `UPDATE hosts SET status = 'revoked', revoked_at = NOW(), enroll_expires_at = NULL
                        WHERE id = $1 AND project_id = $2`

// HostCredentialAudit builds the audit row of one enrolled credential a host
// revoke or delete removes.
type HostCredentialAudit func(cred MTLSCredential) AuditEvent

// RevokeWithCredentials revokes the host and deletes every mTLS credential
// enrolled for it (host_id = the host), one audit row per credential, in one
// transaction. The caller closes the returned credentials' streams.
// Project-wide credentials (host_id NULL) are not touched: they are not tied
// to one machine. An enrollment racing the revoke either commits first (its
// credential is deleted here) or waits on the host row lock and then finds
// the host revoked.
func (r *HostRepo) RevokeWithCredentials(ctx context.Context, projectID, hostID string, audit HostCredentialAudit) ([]MTLSCredential, error) {
	var removed []MTLSCredential
	err := inTx(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, revokeHostSQL, hostID, projectID); err != nil {
			return err
		}
		var err error
		removed, err = deleteHostCredentialsInTx(ctx, tx, projectID, hostID, audit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// DeleteWithCredentials deletes the host after deleting, with one audit row
// each, the credentials enrolled for it (the foreign key would cascade them
// away unaudited). Same transaction and same caller duty as
// RevokeWithCredentials.
func (r *HostRepo) DeleteWithCredentials(ctx context.Context, projectID, hostID string, audit HostCredentialAudit) ([]MTLSCredential, error) {
	var removed []MTLSCredential
	err := inTx(ctx, r.pool, func(tx pgx.Tx) error {
		// Lock the row first so an enrollment cannot add a credential
		// between the credential delete and the host delete.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM hosts WHERE id = $1 AND project_id = $2 FOR UPDATE`, hostID, projectID); err != nil {
			return err
		}
		var err error
		removed, err = deleteHostCredentialsInTx(ctx, tx, projectID, hostID, audit)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM hosts WHERE id = $1 AND project_id = $2`, hostID, projectID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// deleteHostCredentialsInTx deletes the credentials bound to hostID of
// projectID and audits each removal (a failed audit write does not block a
// revoke, auditRemovalEventInTx).
func deleteHostCredentialsInTx(ctx context.Context, tx pgx.Tx, projectID, hostID string, audit HostCredentialAudit) ([]MTLSCredential, error) {
	rows, err := tx.Query(ctx, `
		DELETE FROM mtls_credentials
		 WHERE project_id = $1 AND host_id = $2 AND purpose = 'agent_grpc'
		RETURNING `+credentialColumns, projectID, hostID)
	if err != nil {
		return nil, err
	}
	removed, err := scanCredentials(rows)
	if err != nil {
		return nil, err
	}
	if audit != nil {
		for _, c := range removed {
			if err := auditRemovalEventInTx(ctx, tx, audit(c)); err != nil {
				return nil, err
			}
		}
	}
	return removed, nil
}

// HostRevoked reports whether host hostID of projectID is revoked, or gone
// (deleted, or never of this project) -- either way its agents must not be
// served.
func (r *HostRepo) HostRevoked(ctx context.Context, projectID, hostID string) (bool, error) {
	var revoked bool
	err := r.pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM hosts WHERE id = $1 AND project_id = $2`,
		hostID, projectID).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	return revoked, err
}

// RevokedHostNamed reports whether projectID has a revoked host whose name,
// or reported hostname, is name: an agent of that machine connecting
// without a host key is refused instead of registering afresh.
func (r *HostRepo) RevokedHostNamed(ctx context.Context, projectID, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	var found bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM hosts
		                WHERE project_id = $1 AND revoked_at IS NOT NULL
		                  AND (name = $2 OR host_info->>'hostname' = $2))`,
		projectID, name).Scan(&found)
	return found, err
}

// Delete removes the host entirely (cascade wipes any dangling agents).
// Scoped by project_id as the mandatory second isolation layer.
func (r *HostRepo) Delete(ctx context.Context, projectID, hostID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM hosts WHERE id = $1 AND project_id = $2`, hostID, projectID)
	return err
}

// maxKeyCandidates bounds the rows one VerifyKey call reads, and
// maxKeyVerifications the argon2id runs it pays for them (64 MiB and ~50 ms
// each). A key with a lookup id matches one row; only rows stored before
// migration 000105 are matched by the 20-bit display prefix, and those few
// leave the prefix path at their first successful verification.
const (
	maxKeyCandidates    = 4
	maxKeyVerifications = 4
)

// keyCandidate is one hosts row VerifyKey may verify the presented key
// against.
type keyCandidate struct {
	host               Host
	labels             []byte
	hash, prevHash     string
	lookup, prevLookup string
	prefix, prevPrefix string
	// prevValid: the previous key is within its grace window.
	prevValid bool
}

// VerifyKey finds the hosts the presented raw key may belong to, then
// validates via argon2id. Returns the matched (non-revoked) host on success.
//
// Rows are found by host_key_lookup (keyauth.LookupID: 128 bits of SHA-256
// over the whole key, migration 000105), current or previous within its
// grace window, so a key names one row and a wrong key costs no argon2id at
// all. Rows created before the lookup existed are still found by the 9-
// character display prefix; it is not unique (with two hosts sharing
// it, reading one row refused the other's correct key), so every candidate
// is verified, up to maxKeyVerifications, and the first successful
// verification stores the row's lookup id.
func (r *HostRepo) VerifyKey(ctx context.Context, raw string) (*Host, error) {
	return r.verifyKey(ctx, raw, true)
}

// VerifyCurrentKey is VerifyKey without the previous key of a rotation: a
// host key enrolls certificates only while it is the host's current key, so
// the key a rotation retired (often because it leaked) cannot mint one
// during its grace period. The host row carries EnrollExpiresAt.
func (r *HostRepo) VerifyCurrentKey(ctx context.Context, raw string) (*Host, error) {
	return r.verifyKey(ctx, raw, false)
}

func (r *HostRepo) verifyKey(ctx context.Context, raw string, allowPrev bool) (*Host, error) {
	if !keyauth.ValidateFormat(raw) {
		return nil, ErrHostKeyInvalid
	}
	short := keyauth.ShortPrefix(raw)
	lookup := keyauth.LookupID(raw)
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, project_id, name, labels,
		       host_key_hash, COALESCE(prev_host_key_hash, ''),
		       COALESCE(host_key_lookup, ''), COALESCE(prev_host_key_lookup, ''),
		       host_key_prefix, COALESCE(prev_host_key_prefix, ''),
		       COALESCE(prev_host_key_expires_at > NOW(), false),
		       status, last_seen, created_at, enroll_expires_at
		  FROM hosts
		 WHERE revoked_at IS NULL
		   AND (host_key_lookup = $1
		        OR (prev_host_key_lookup = $1 AND prev_host_key_expires_at > NOW())
		        OR (host_key_lookup IS NULL AND host_key_prefix = $2)
		        OR (prev_host_key_lookup IS NULL AND prev_host_key_prefix = $2
		            AND prev_host_key_expires_at > NOW()))
		 ORDER BY (COALESCE(host_key_lookup = $1, false) OR COALESCE(prev_host_key_lookup = $1, false)) DESC,
		          random()
		 LIMIT $3`,
		lookup, short, maxKeyCandidates)
	if err != nil {
		return nil, err
	}
	var candidates []keyCandidate
	for rows.Next() {
		var c keyCandidate
		if err := rows.Scan(&c.host.ID, &c.host.UserID, &c.host.ProjectID, &c.host.Name, &c.labels,
			&c.hash, &c.prevHash, &c.lookup, &c.prevLookup, &c.prefix, &c.prevPrefix,
			&c.prevValid,
			&c.host.Status, &c.host.LastSeen, &c.host.CreatedAt, &c.host.EnrollExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		c.host.HostKeyPrefix = c.prefix
		if !allowPrev {
			c.prevValid = false
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	digest := keyauth.Digest(raw)
	var verifiedHash string
	verifiedKeys.Get(digest, func(v *string) { verifiedHash = *v })
	budget := maxKeyVerifications
	// verify checks raw against one stored hash: free when this exact key
	// already verified against this exact hash (a rotation changes the
	// hash; a revoke removes the row from the query), else one argon2id run
	// -- in the small legacy pool for a row matched by prefix only.
	verify := func(stored string, legacy bool) (bool, error) {
		if stored == "" {
			return false, nil
		}
		if verifiedHash != "" && subtle.ConstantTimeCompare([]byte(verifiedHash), []byte(stored)) == 1 {
			return true, nil
		}
		if budget == 0 {
			return false, nil
		}
		budget--
		var ok bool
		var err error
		if legacy {
			ok, err = keyauth.VerifyLegacyContext(ctx, raw, stored)
		} else {
			ok, err = keyauth.VerifyContext(ctx, raw, stored)
		}
		if ok {
			verifiedKeys.Update(digest, func(v *string, _ bool) { *v = stored })
		}
		return ok, err
	}
	for i := range candidates {
		c := &candidates[i]
		// Current key: by lookup id, or by prefix on a row that has none.
		if c.lookup == lookup || (c.lookup == "" && c.prefix == short) {
			ok, err := verify(c.hash, c.lookup == "")
			if err != nil {
				return nil, err
			}
			if ok {
				if c.lookup == "" {
					r.backfillLookup(ctx, c.host.ID, false, lookup, c.hash)
				}
				return c.found(), nil
			}
		}
		// Previous key during its grace window, likewise.
		if c.prevValid && (c.prevLookup == lookup || (c.prevLookup == "" && c.prevPrefix == short)) {
			ok, err := verify(c.prevHash, c.prevLookup == "")
			if err != nil {
				return nil, err
			}
			if ok {
				if c.prevLookup == "" {
					r.backfillLookup(ctx, c.host.ID, true, lookup, c.prevHash)
				}
				return c.found(), nil
			}
		}
	}
	return nil, ErrHostKeyInvalid
}

// verifiedKeys remembers, per exact raw key (full SHA-256), the stored hash
// it last verified against, so an agent re-authenticating -- every Hello and
// every host-key ingest request -- costs a hash compare instead of an
// argon2id run (64 MiB, ~50 ms). A cache hit still needs the row to
// match by lookup id, be unrevoked and carry that same hash, so rotation and
// revocation take effect at once. Bounded LRU; a miss only costs the
// argon2id run.
var verifiedKeys = lru.New[string](16384)

func (c *keyCandidate) found() *Host {
	h := c.host
	_ = json.Unmarshal(c.labels, &h.Labels)
	return &h
}

// backfillLookup stores the lookup id of a key verified by prefix (the
// current key, or the previous one when prev), so the row leaves the prefix
// path. Only the slot whose hash was verified is written: a rotation in
// between leaves it alone. Best effort: a failure only means the next
// verification takes the prefix path again.
func (r *HostRepo) backfillLookup(ctx context.Context, hostID string, prev bool, lookup, hash string) {
	q := `UPDATE hosts SET host_key_lookup = $1 WHERE id = $2 AND host_key_lookup IS NULL AND host_key_hash = $3`
	if prev {
		q = `UPDATE hosts SET prev_host_key_lookup = $1 WHERE id = $2 AND prev_host_key_lookup IS NULL AND prev_host_key_hash = $3`
	}
	if _, err := r.pool.Exec(ctx, q, lookup, hostID, hash); err != nil {
		log.Printf("[hosts] store host key lookup for host %s: %v", hostID, err)
	}
}

// HostOfflineThreshold is the window after which a host is considered offline
// if no heartbeat has landed. Agents heartbeat roughly every 3 seconds; a 90s
// window is ~30 missed beats, enough slack to ride out a brief network hiccup
// without thrashing the status column.
const HostOfflineThreshold = 90 * time.Second

// MarkOfflineStale flips any non-revoked host that hasn't been seen within
// HostOfflineThreshold into `offline`. Intended to be called periodically by
// a background sweeper; returns the number of rows transitioned so callers
// can emit a structured log / notification.
func (r *HostRepo) MarkOfflineStale(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE hosts
		   SET status = 'offline'
		 WHERE status   = 'online'
		   AND revoked_at IS NULL
		   AND (last_seen IS NULL OR last_seen < NOW() - make_interval(secs => $1))`,
		HostOfflineThreshold.Seconds(),
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetAgentHostLastSeen returns the last_seen of the host linked to an agent.
// Used for lightweight liveness cross-checks when the gRPC stream is briefly
// down but the HTTP host-agent heartbeat is still active.
func (r *HostRepo) GetAgentHostLastSeen(ctx context.Context, agentID string) (*time.Time, error) {
	var lastSeen *time.Time
	// Self-scoping join: agent and host must share project_id, so a caller that
	// already owns the agent cannot read another tenant's host last_seen.
	err := r.pool.QueryRow(ctx, `
		SELECT h.last_seen
		  FROM hosts h
		  JOIN agents a ON a.host_id = h.id AND a.project_id = h.project_id AND a.deleted_at IS NULL
		 WHERE a.id = $1`, agentID).Scan(&lastSeen)
	if err != nil {
		return nil, err
	}
	return lastSeen, nil
}

// TouchHeartbeat marks the host as "online" and updates last_seen.
// Scoped by project_id as the mandatory second isolation layer.
func (r *HostRepo) TouchHeartbeat(ctx context.Context, projectID, hostID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE hosts
		   SET last_seen = NOW(),
		       status = CASE WHEN status = 'pending' OR status = 'offline' THEN 'online' ELSE status END
		 WHERE id = $1 AND project_id = $2`, hostID, projectID)
	return err
}

// UpdateHostInfo persists a fresh host_info snapshot. Structured columns are
// denormalised so the UI can filter without parsing JSON.
func (r *HostRepo) UpdateHostInfo(ctx context.Context, projectID, hostID string, h AgentHostInfoRow) error {
	var bootTS *time.Time
	if h.BootUnix > 0 {
		t := time.Unix(h.BootUnix, 0).UTC()
		bootTS = &t
	}
	// Scoped by project_id as the mandatory second isolation layer.
	_, err := r.pool.Exec(ctx, `
		UPDATE hosts
		   SET host_info       = $2::jsonb,
		       host_os         = NULLIF($3,''),
		       host_os_version = NULLIF($4,''),
		       host_kernel     = NULLIF($5,''),
		       host_arch       = NULLIF($6,''),
		       host_cpu_count  = NULLIF($7::int,0),
		       host_memory     = NULLIF($8::bigint,0),
		       host_virt       = NULLIF($9,''),
		       host_boot_time  = $10,
		       last_seen       = NOW(),
		       status          = CASE WHEN status = 'pending' OR status = 'offline' THEN 'online' ELSE status END
		 WHERE id = $1 AND project_id = $11`,
		hostID, string(h.Raw), h.OS, h.OSVersion, h.Kernel, h.Arch,
		h.CPUCount, h.MemoryTotal, h.VirtType, bootTS, projectID,
	)
	return err
}

// ListByProject returns all hosts that belong to a given project, newest first.
func (r *HostRepo) ListByProject(ctx context.Context, projectID string) ([]Host, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, project_id, name, COALESCE(labels,'{}'::jsonb),
		       host_key_prefix, status,
		       host_info, COALESCE(host_os,''), COALESCE(host_os_version,''),
		       COALESCE(host_kernel,''), COALESCE(host_arch,''),
		       COALESCE(host_cpu_count,0), COALESCE(host_memory,0),
		       COALESCE(host_virt,''), host_boot_time,
		       last_seen, created_at, revoked_at, enroll_expires_at
		  FROM hosts
		 WHERE project_id = $1
		 ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		var h Host
		var labels []byte
		if err := rows.Scan(
			&h.ID, &h.UserID, &h.ProjectID, &h.Name, &labels,
			&h.HostKeyPrefix, &h.Status,
			&h.HostInfoRaw, &h.HostOS, &h.HostOSVer,
			&h.HostKernel, &h.HostArch,
			&h.HostCPUs, &h.HostMemory,
			&h.HostVirt, &h.HostBoot,
			&h.LastSeen, &h.CreatedAt, &h.RevokedAt, &h.EnrollExpiresAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(labels, &h.Labels)
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetByID returns a single host scoped to the owning project (defence in
// depth against IDOR — callers always supply the project_id from the session).
func (r *HostRepo) GetByID(ctx context.Context, projectID, hostID string) (*Host, error) {
	h := &Host{}
	var labels []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, project_id, name, COALESCE(labels,'{}'::jsonb),
		       host_key_prefix, status,
		       host_info, COALESCE(host_os,''), COALESCE(host_os_version,''),
		       COALESCE(host_kernel,''), COALESCE(host_arch,''),
		       COALESCE(host_cpu_count,0), COALESCE(host_memory,0),
		       COALESCE(host_virt,''), host_boot_time,
		       last_seen, created_at, revoked_at, enroll_expires_at
		  FROM hosts
		 WHERE id = $1 AND project_id = $2`,
		hostID, projectID,
	).Scan(
		&h.ID, &h.UserID, &h.ProjectID, &h.Name, &labels,
		&h.HostKeyPrefix, &h.Status,
		&h.HostInfoRaw, &h.HostOS, &h.HostOSVer,
		&h.HostKernel, &h.HostArch,
		&h.HostCPUs, &h.HostMemory,
		&h.HostVirt, &h.HostBoot,
		&h.LastSeen, &h.CreatedAt, &h.RevokedAt, &h.EnrollExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &h.Labels)
	return h, nil
}

// GetByName returns a non-revoked host in the given project whose name matches
// the supplied hostname string. Returns nil, nil when no row is found.
func (r *HostRepo) GetByName(ctx context.Context, projectID, name string) (*Host, error) {
	if projectID == "" || name == "" {
		return nil, nil
	}
	h := &Host{}
	var labels []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, project_id, name, COALESCE(labels,'{}'::jsonb),
		       host_key_prefix, status,
		       host_info, COALESCE(host_os,''), COALESCE(host_os_version,''),
		       COALESCE(host_kernel,''), COALESCE(host_arch,''),
		       COALESCE(host_cpu_count,0), COALESCE(host_memory,0),
		       COALESCE(host_virt,''), host_boot_time,
		       last_seen, created_at, revoked_at, enroll_expires_at
		  FROM hosts
		 WHERE project_id = $1 AND (name = $2 OR host_info->>'hostname' = $2) AND revoked_at IS NULL
		 LIMIT 1`,
		projectID, name,
	).Scan(
		&h.ID, &h.UserID, &h.ProjectID, &h.Name, &labels,
		&h.HostKeyPrefix, &h.Status,
		&h.HostInfoRaw, &h.HostOS, &h.HostOSVer,
		&h.HostKernel, &h.HostArch,
		&h.HostCPUs, &h.HostMemory,
		&h.HostVirt, &h.HostBoot,
		&h.LastSeen, &h.CreatedAt, &h.RevokedAt, &h.EnrollExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &h.Labels)
	return h, nil
}
