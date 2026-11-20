# Production acceptance and recovery

This runbook is a release gate. It does not deploy, migrate, restart a service, contact a SIEM receiver, or generate signing material. Run it from the exact tagged checkout whose artifacts will be released.

## Inputs owned by the operator

Before acceptance, configure a libpq service in a protected `pg_service.conf` for the target database. Keep the password in a protected password file; do not put a database URL or password on the command line. Record the expected schema from the highest numbered migration in the release. Select the protected release signing key through the custody process, and obtain the corresponding trusted public key from `internal/updater/verify.go`.

The release directory must contain all three Linux bundles and their detached `.sig` files. The frontend path must be the production artifact produced by the release build and contain `index.html`. This check only confirms presence; it does not build the frontend or prove browser behavior.

```bash
export PGSERVICEFILE=/etc/wafio/pg_service.conf
export WAFIO_RELEASE_PUBLIC_KEY='<base64 Ed25519 public key from the reviewed release source>'

./scripts/production_preflight.py \
  --config /etc/wafio/config.yaml \
  --frontend /opt/wafio/frontend \
  --database-service wafio-production \
  --expected-schema 118 \
  --release-version v2.0.0 \
  --release-public-key "$WAFIO_RELEASE_PUBLIC_KEY" \
  --signing-key-file /secure/release/wafio-release.key \
  --artifact dist/wafio-controlplane-v2.0.0-linux-amd64.tar.gz \
  --artifact dist/wafio-waf-agent-v2.0.0-linux-amd64.tar.gz \
  --artifact dist/wafio-host-agent-v2.0.0-linux-amd64.tar.gz
```

Exit zero and JSON `status: pass` are required. The command fails when `openssl`, `psql`, or `pg_isready` is absent; the named database service is unavailable; `schema_migrations` is dirty or differs from the requested version; configuration or frontend index is absent; signing material is missing, malformed, too broadly readable, or does not match the trusted public key; a component is absent; or any detached signature does not bind the exact artifact hash and version. It reads every input and uses a temporary directory for signature verification. It does not print key bytes or connection details.

Do not waive a failed check. Preserve the JSON report with the release evidence, correct the input or release artifact, and run the entire command again. A local pass does not establish production signing custody, customer workload capacity, supported kernel coverage, off-device backup, or agreed RPO/RTO.

The release scripts, which are in the wafio-release repository, apply the same fail-closed boundary. `scripts/release.sh` signs each bundle it builds when `WAFIO_RELEASE_KEY` names the protected private-key file, requires every adjacent `.sig`, and runs `wafio release verify` against the public key compiled into the updater before its first SSH or SCP command. It uploads each accepted signature beside its bundle and does not touch `latest.json`. `scripts/publish-release.sh` then checks that all three bundles exist, hold exactly the files listed in `deploy/BUNDLE.md` and carry a signature that verifies for the release version, and only then writes `latest.json`. The release key is never stored on GitHub. A mismatched key, bad signature, unexpected file or incomplete release set stops publication.

## Release and rollback

Take and verify the encrypted off-device backup described in `production-backup.md` before changing the database. Record current binary hashes, package version, schema version, agent connection state, telemetry loss counters, and the rollback artifact signature. Upgrade the control plane before agents because telemetry v2 process receipts depend on the control-plane contract. Apply migrations with `wafio migrate up`; never use `fresh` outside a disposable development database.

After each component, confirm `/health`, `/ready`, agent freshness, expected bundle generation, and a bounded benign/block smoke fixture. A successful `/health` response proves only process liveness. `/ready` proves bounded database availability, not traffic protection or downstream SIEM processing.

Rollback uses the previously accepted, signed artifact and the release-specific database procedure. Check the applied version first (`SELECT version, dirty FROM schema_migrations`). Use `wafio migrate down --steps 1` only when the reviewed down migration is compatible with the data written since release; otherwise restore the verified backup into a new database and switch using the operator-approved recovery procedure. Do not overwrite the only database or delete the failed environment during diagnosis. Roll agents back after the control plane is compatible, then repeat readiness and reconnect checks.

## Monitoring and incident response

During the rollout, watch control-plane readiness, agent `last_seen`, applied bundle generation, database write failures, transport rejected/dropped events and batches, pending batches, plus host kernel and userspace drop counters. Counters are process-local and reset on restart.

If an agent disconnects, stop the rollout, retain logs and process counters, and verify certificate validity, CA, SNI, endpoint reachability, then observe a fresh `last_seen` and applied generation after reconnect. Do not re-provision credentials until identity mismatch or expiry is established.

The control plane holds no SIEM sender: the webhook in `rules_json` (`siem.webhook_url`) is validated here and used by the WAF agent. This runbook does not send test notifications to third parties; use an explicitly authorized isolated receiver for fault exercises.

Reject any update with a missing or invalid signature, a signature for another version/hash, or a downgrade refusal. Keep the current process running, quarantine the artifact and its manifest, and investigate the release pipeline and signing custody. Never replace the trusted public key or generate a new production key merely to make a failing artifact pass.

For database unavailability, preserve `/health` liveness evidence and the `/ready` failure, stop release activity, and follow the database recovery procedure. Restore into a distinct target first and compare schema and representative tenant data before switching. The measured local schema-72 rehearsal is evidence for its small fixture only and is not a production RTO promise.

## Settings that must stay off

Never set `GRPC_BINARY_LOG_FILTER` in the environment of the control plane: grpc-go would then write whole messages to a file, and a certificate install carries a private key.

## Isolated verification evidence

The repository tests cover invalid/mismatched release signatures, missing trusted keys, downgrade refusal, telemetry retry retention, disconnect state, and reconnect/application retry. Run the bounded suites without external services:

```bash
go test ./internal/updater ./internal/agentserver
go test -race ./internal/updater ./internal/agentserver
python3 -m unittest scripts.tests.test_production_preflight -v
```

These tests use in-memory queues, local HTTP fixtures, temporary files, and fake dependency processes. They do not stop a database, fill a disk, or mutate a Linux service.
