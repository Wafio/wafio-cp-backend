# Encrypted control-plane backup and recovery

This runbook creates a PostgreSQL custom-format dump, packages explicitly selected control-plane files, and encrypts the package to an operator-managed GnuPG recipient. It writes the encrypted artifact atomically and publishes a SHA-256 manifest only after encryption succeeds. An optional S3-compatible destination is used only when explicitly configured; an upload or authenticated download verification failure is a failed backup run and leaves the complete local artifact and manifest intact.

The tool does not choose a production bucket, schedule, retention policy, RPO or RTO. Before enabling a timer, the operator must approve those values and possess both the recipient private key and working database credentials in separate recovery custody. GnuPG public-key encryption is described in the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html). The S3 transport uses the established AWS CLI `s3api` interface, which works with MinIO through an explicit endpoint URL. Its provider-chain and named-profile behavior is described in the [AWS CLI configuration documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

## Prepare protected configuration

Install `scripts/backup-controlplane.py` as `/usr/local/libexec/wafio/backup-controlplane.py`. Create an existing backup directory owned by root with mode `0700`. Store the source PostgreSQL URL in a root-owned `0600` file such as `/etc/wafio/backup-database-url`; the URL is read into the child process environment and is never placed in a command argument or result manifest. Explicit URL routing clears ambient `PGSERVICE`, `PGSERVICEFILE` and `PGHOSTADDR` values. The accepted URL query parameters are `sslmode`, `sslrootcert`, `sslcert`, `sslkey` and `connect_timeout`; unknown, empty or repeated parameters fail rather than being silently ignored.

Import the backup recipient's public key into a dedicated GnuPG home. GnuPG writes lock, trust-database and random-seed state even during encryption, so the systemd template creates writable `/var/lib/wafio-backup` with mode `0700`; place the public-only keyring under `/var/lib/wafio-backup/gnupg`. Do not place the example keyring below the read-only `/etc/wafio` sandbox. Use the full fingerprint as `gpg_recipient`, and keep the corresponding private key off the control-plane host. The dedicated home and JSON configuration must deny all group and other access.

Example `/etc/wafio/backup.json`, mode `0600`:

```json
{
  "database_url_file": "/etc/wafio/backup-database-url",
  "destination_directory": "/var/backups/wafio",
  "gpg_recipient": "FULL_RECIPIENT_FINGERPRINT",
  "gpg_homedir": "/var/lib/wafio-backup/gnupg",
  "include_paths": [
    "/etc/wafio/config.yaml",
    "/etc/wafio/certs"
  ],
  "retention_count": 14
}
```

Only add files the operator intends to recover. Symbolic links are rejected so an include cannot silently escape its named tree. The encrypted archive can contain configuration, CA material and other credentials; protect the recipient private key accordingly.

For an authorized MinIO destination, add an `s3` object. The endpoint and bucket are required together. `region` is optional and defaults to `us-east-1`, which is the normal SigV4 compatibility value when a MinIO deployment has no other region. The key prefix may be empty. This example uses a named AWS CLI profile and a protected settings file that explicitly selects path-style addressing:

```json
{
  "s3": {
    "endpoint_url": "https://minio.operator.example",
    "bucket": "OPERATOR_SELECTED_BUCKET",
    "key_prefix": "wafio/control-plane",
    "region": "us-east-1",
    "profile": "wafio-backup",
    "aws_config_file": "/etc/wafio/aws-config"
  }
}
```

The referenced AWS settings file can contain:

```ini
[profile wafio-backup]
region = us-east-1
s3 =
  addressing_style = path
```

Credentials come from the AWS CLI default provider chain. For file-backed credentials, point `AWS_SHARED_CREDENTIALS_FILE` at a root-owned mode-`0600` file through the service environment; for workload or instance identity, omit it. Access keys and secret keys never belong in `backup.json`, `endpoint_url`, service arguments or logs. The profile is optional when the default provider chain is sufficient. `aws_config_file` is optional, but it is the explicit place to configure `addressing_style = path`, `virtual` or `auto`; path style is the recommended MinIO baseline.

Omit the entire `s3` object until a real endpoint and bucket have been selected and tested. The tool uploads the encrypted artifact first using a create-only conditional and an explicit SHA-256 checksum. It then downloads the object through the authenticated S3 API and compares its bytes and SHA-256 to the local artifact. Only after that succeeds does it upload and verify the manifest in the same way. If any transfer or verification fails, the service exits nonzero and does not prune local backup generations. The tool never creates a bucket.

## Create and verify a backup

Run one manual backup before considering a schedule:

```bash
sudo /usr/local/libexec/wafio/backup-controlplane.py backup \
  --config /etc/wafio/backup.json
```

The command prints only the completed local artifact and manifest paths. A mode-`0600` `.wafio-backup.lock` file serializes writers in that destination and is intentionally retained between runs. Final artifact and manifest names are published with no-overwrite filesystem operations, so another process cannot replace a completed generation after the initial collision check. Confirm both result files are mode `0600`, transfer completion is visible at the approved destination, and monitoring treats any nonzero service result as failure. A verification run checks the manifest, decrypts with the available private key, and requires a nonempty regular `database.dump` plus valid, supported `backup-metadata.json` before reporting success:

```bash
sudo /usr/local/libexec/wafio/backup-controlplane.py verify \
  --config /etc/wafio/backup.json \
  --artifact /var/backups/wafio/wafio-controlplane-YYYYMMDDTHHMMSSZ.tar.gpg \
  --manifest /var/backups/wafio/wafio-controlplane-YYYYMMDDTHHMMSSZ.manifest.json
```

The checked-in service and timer are templates. Copy and inspect them, then edit `OnCalendar` to match the approved RPO. Do not enable the timer until its destination, retention, alerting and recovery-key custody are accepted. Installing the files alone does not activate a schedule.

`retention_count` counts only complete local artifact/manifest pairs whose filename, size and SHA-256 validate. Orphaned or invalid newer files do not consume retention slots and therefore cannot cause an older valid recovery point to be deleted. Pruning occurs only after encryption and all configured uploads plus verification downloads succeed. It does not delete S3 objects or set bucket retention; configure and audit the MinIO lifecycle separately. Omitting it keeps all local generations.

## Restore rehearsal

Create a new, empty recovery database without dropping or overwriting an existing database. Put its URL in a separate mode-`0600` file. Before creating the restore directory or changing the database, the tool rejects a normalized host/port/database identity matching the source and queries the target catalogs to require zero user relations. The restore then follows the Timescale logical restore sequence: create the extension, call `timescaledb_pre_restore()`, run `pg_restore` serially, then call `timescaledb_post_restore()`. Parallel restore is deliberately unsupported. See the [Timescale logical backup documentation](https://docs.timescale.com/self-hosted/latest/backup-and-restore/logical-backup/) and [PostgreSQL pg_restore documentation](https://www.postgresql.org/docs/current/app-pgrestore.html).

Choose a new path that does not exist. It receives the cleartext database dump and the recovered files, so place it on protected storage and remove it through the operator's approved cleanup procedure after validation.

```bash
sudo /usr/local/libexec/wafio/backup-controlplane.py restore \
  --config /etc/wafio/backup.json \
  --artifact /var/backups/wafio/wafio-controlplane-YYYYMMDDTHHMMSSZ.tar.gpg \
  --manifest /var/backups/wafio/wafio-controlplane-YYYYMMDDTHHMMSSZ.manifest.json \
  --target-database-url-file /etc/wafio/recovery-database-url \
  --restore-directory /var/lib/wafio-recovery/rehearsal-YYYYMMDD
```

After restore, verify the schema migration version, admin login, tenant/project access, agent credential inventory and representative event counts. Start only isolated recovery services against the restored database; do not point a production process at the rehearsal database. Record dump age, restore duration and data volume against the approved RPO/RTO. A small lab restore does not establish production recovery time.

If restore fails after `timescaledb_pre_restore()`, treat the target database as partial. Preserve the encrypted artifact and manifest, create another new empty target, correct the cause, and repeat. Never restore over the source or claim recovery from checksum/decryption alone.

## Local proof recorded on 2026-09-12

The native loopback lab on PostgreSQL 18.6 and TimescaleDB 2.27.1 completed a real recipient-encrypted backup, manifest verification, decryption and serial restore with GnuPG 2.5.21. The schema-72 encrypted artifact was 3,330,317 bytes and both it and its manifest were mode `0600`. After the source-identity and empty-target guards were added, a fresh restore into `wafio_backup_proof_guarded_20260912` again completed both Timescale pre/post calls and restored schema 72, 361,513 runtime rows, and the same 1 user, 1 project and 2 agents as the source. The live source had advanced after its logical snapshot, so runtime-row comparison against the later source is not a row-loss assertion. A smaller inactive schema-70 fixture also restored with exact table counts.

No MinIO bucket was supplied, so no external object was created or uploaded. The S3-compatible contract is covered by isolated process tests for endpoint, bucket, key prefix, optional profile and settings file, SigV4 region default, SHA-256 upload, authenticated download comparison, collision behavior and preservation after transfer failure. Production proof still requires the operator's actual endpoint, bucket, credentials, lifecycle and recovery-key custody.
