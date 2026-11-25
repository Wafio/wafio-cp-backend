# CLI contract: the `wafio` binary

The control plane binary `wafio`. Extracted from the `cobra.Command` definitions in `cmd/wafio/`. The WAF agent is built from wafio-agent-waf and the host agent from wafio-agent-host; their command lines and environment are documented there. The API of the portal is in the wafio-portal repository (`docs/portal-api.md`).

Output convention: the binary exits with code 0 on success and non-zero on failure. A configuration failure uses `log.Fatalf`, which exits with code 1.

## command: wafio serve

Runs the control plane: HTTP on port 9087, gRPC with mTLS on port 9090.

| Flag | Type | Rules |
|---|---|---|
| `--migrate` | bool | Default false. When true, migrations run before the server starts |
| `--migrations` | string | Default `migrations`. Path of the migrations directory; it must exist when `--migrate` is given |

Configuration is loaded in this order: `config/config.yaml`, then `WAFIO_*` environment variables, then command line flags. Every YAML key maps to one environment variable: `server.http_addr` becomes `WAFIO_SERVER_HTTP_ADDR`. A key that is no longer read is ignored.

Before the server starts, `Config.Validate` (`internal/config/validate.go`) checks the configuration and stops the boot with the list of all errors if any check fails. It checks, among other things: `jwt.secret` empty, still a shipped placeholder or example, or shorter than 32 characters; `jwt.expire_hours` not positive; `totp.enc_key` empty or not 32 bytes; `server.cors_allow_origins` holding `*` together with credentials; `server.http_addr` empty; an invalid trusted proxy; `log.level` other than debug, info, warn or error; `database.name` or `database.host` empty, `database.port` outside 1 to 65535; agent receive limits out of range.

After it has connected to the database, the server takes a shared advisory lock on the encryption key on a connection of its own and holds it until it exits, and it compares the id of `totp.enc_key` with the id the database holds (it stores its own on the first start). It refuses to start while `wafio rekey --apply` runs or when the ids differ, and it stops when a lock that was lost is taken again and the id is no longer its own; see `wafio rekey`.

While it runs, the server also fills the dashboard rollups of the WAF decisions once a minute, under a database advisory lock so that of several servers on one database one works, and trims them with the telemetry retention (README, "Dashboard rollups"). It needs no flag or key and does not touch ingest.

Security: authn=not-applicable-local-process; privilege=no-root-needed; secrets=read-from-config-or-env-never-from-argv; audit=startup-log; note=jwt.secret-placeholder-refused-at-boot

## command: wafio migrate

Subcommands: `up`, `down`, `down --steps N` and `fresh`. The version in force is in `SELECT version, dirty FROM schema_migrations`.

| Flag | Type | Rules |
|---|---|---|
| `--migrations` | string | Default empty, which means auto-detect from the project root. Applies to every subcommand |
| `--steps` | int | Only for `down`. Default 1. The number of migrations to roll back |

`up` applies every pending migration. `down` rolls back one migration, or N with `--steps`. `fresh` drops every object and applies everything again; it destroys data and is for development only.

Security: authn=shell-access-to-the-host; authz=database-credentials-from-config; destructive=fresh-deletes-all-data-development-only; audit=golang-migrate-version-history

## command: wafio admin

Manages instance administrators. Use it once after `wafio migrate up` to create the first login.

| Subcommand | Rules |
|---|---|
| `create` | Creates an administrator account. Flags: `--email` (required), `--name` (required), `--password`. The password is read from the terminal unless `--password` is given; a flag value is visible in `ps` and in the shell history |
| `list` | Lists the administrator accounts |

Both subcommands read the database settings from the configuration.

Security: authn=shell-access-to-the-host; authz=database-credentials-from-config; secrets=password-prompted-by-default

## command: wafio rekey

Re-encrypts every value that is sealed with `totp.enc_key`, from the old key to a new one: `users.totp_secret` and `users.totp_pending_secret`, the SMTP password and the MalwareBazaar key saved in `system_settings`, and the private keys of uploaded certificates (`app_certificate_keys`, sealed with the project and certificate they belong to). Run it after the operator changed `totp.enc_key`; the steps are in `docs/operations/rotate-encryption-key.md`.

| Flag | Type | Rules |
|---|---|---|
| `--apply` | bool | Default false. Without it the command prints the counts per kind of value (to rewrite, already under the new key, plain text, unreadable) and changes nothing; it takes no lock. With it, the values are rewritten in one transaction with a lock on every row it reads, together with the id of the new key and a `system_audit` row `admin.encryption_key_rotated` (the key ids and the counts, never a value). It refuses, and writes nothing, when a control plane or another rekey runs, when a value opens with neither key, and when a row stays locked by another transaction for more than 10 seconds |

The old key is read from the environment variable `WAFIO_OLD_TOTP_ENC_KEY`, which the command removes from its own environment as soon as it has read it, so that nothing it starts inherits it (the kernel copy in `/proc/<pid>/environ` and a core dump are not touched); give it on the command line of the one command, `WAFIO_OLD_TOTP_ENC_KEY="$old" wafio rekey --apply`, and not exported in the shell. It is the key that `totp.enc_key` had before, 64 hex characters or base64 of 32 bytes. The new key is `totp.enc_key` from `config/config.yaml` or `WAFIO_TOTP_ENC_KEY`, which the operator has already changed. The command refuses when either is empty or is no key, and when they are the same key in either spelling.

Every `wafio serve` holds a shared advisory lock on the key for as long as it runs, and `--apply` asks for it exclusively as the first statement of its transaction. So `--apply` refuses while any control plane runs, and a control plane refuses to start while an apply runs. The database also keeps the id of the key in force (`system_settings` row `totp_enc_key`: the first 8 hex characters of the SHA-256 of the key, not the key). A control plane stores it on its first start and refuses to start with a key of another id, which keeps one that was started with the new key before the rewrite from sealing secrets beside the old ones; `--apply` writes the id of the new key in the same transaction.

A value that already opens with the new key counts as done and is left alone, so the command can be run again. A value stored in plain text (a TOTP secret from before encryption was on) is left as it is. The command never prints a value or a key; a report names a row by user id, certificate id or setting name. Exit code 1 when a key is refused, when a lock is not free, when a value opens with neither key (the dry run included), or when the database fails.

Security: authn=shell-access-to-the-host; authz=database-credentials-from-config; secrets=old-key-from-environment-dropped-from-the-process-after-reading-new-key-from-config-values-never-printed; destructive=apply-rewrites-ciphertext-in-one-transaction-dry-run-by-default; audit=system_audit-row-in-the-same-transaction

## command: wafio fetch-data

Downloads third-party security data into `security-data/`: GeoIP databases, IP reputation lists, JA4 and JA3 fingerprints, the bot User-Agent list and the malware hash corpus. The files are not stored in the repository.

| Flag | Type | Rules |
|---|---|---|
| `--dir` | string | Default `security-data`. Target directory |
| `--maxmind-key` | string | MaxMind GeoLite2 license key. Overrides the config value `geo.maxmind_license_key`. Without a key the DB-IP free databases are used |
| `--force` | bool | Default false. Download again even if the file exists |
| `--only` | string | Comma-separated list of `geoip`, `geoip-country`, `geoip-city`, `geoip-asn`, `firehol`, `ja4`, `ja3`, `ua`, `malware`, `malware-hashes`. Overrides `--profile` |
| `--profile` | string | Default `all`. One of `all`, `control-plane`, `agent` |

The profiles: `all` is every component; `control-plane` is the three GeoIP databases, `ja4` and `ua`; `agent` is the three GeoIP databases, `firehol`, `ja4`, `ua` and `malware`.

The `malware` component needs a MalwareBazaar auth key: `WAFIO_MALWARE_AUTH_KEY`, or the key saved under Administration > Security data. Without one, a `--profile` run skips the component and keeps the current database; `--only malware` reports the missing key. The previous valid corpus is kept on an error, and the corpus is refreshed after one hour, or at once with `--force`.

Security: authn=not-applicable; egress=downloads-from-third-party-upstream-sources; integrity=no-signature-check-on-downloaded-files; secrets=maxmind-key-in-a-flag-is-visible-in-the-process-list

Note: a license key given with `--maxmind-key` is visible in `ps`. Setting `WAFIO_GEO_MAXMIND_LICENSE_KEY` is safer.

Note: the IP reputation lists are downloaded directly from their providers to protect this server and must not be redistributed. Sources, credits and licenses are in `NOTICES.txt`.

## command: wafio release

Release signing helpers. Agents verify the signatures with a public key compiled into their binary; until that key is set, self-update refuses to install anything.

| Subcommand | Rules |
|---|---|
| `keygen` | Generates an Ed25519 release signing key. Writes the private key to the path of `--out` (default `wafio-release.key`) and prints the public key. Run it on a machine that does the releasing, never on a server that runs WAFio: the private key must never reach a control plane |
| `sign <artefact>...` | Hashes each artefact, signs (version, hash) with the release key and writes a detached `<artefact>.sig` next to it. Flags: `--key` (default `wafio-release.key`), `--version` (required, for example `v2.0.0`) |
| `verify <artefact>...` | Verifies each `<artefact>.sig` against the public key compiled into the updater. Flag: `--version` (required). No artefact is published until this accepts the whole release set |

The scripts that call these commands (`scripts/release.sh`, `scripts/publish-release.sh`) are in the wafio-release repository.

Security: authn=possession-of-the-private-key-file; secrets=private-key-written-with-owner-only-permissions; audit=detached-signatures-bound-to-version-and-hash

## Build rules

Every binary goes to `build/`, never to the repository root or to `bin/`.

| Target | Command |
|---|---|
| Control plane binary for a release, in `dist/controlplane/` (the bundle is assembled and signed by `scripts/release.sh` in wafio-release) | `./scripts/build-dist.sh <version>` |
| For development and CI | `go build -trimpath -o build/ ./cmd/wafio` |

The release build is a plain `go build -trimpath`, without obfuscation: the source is open. `CGO_ENABLED=0` is needed for a static Linux binary.
