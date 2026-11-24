# wafio-cp-backend
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16869/badge)](https://www.bestpractices.dev/projects/16869) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Wafio/wafio-cp-backend/badge)](https://scorecard.dev/viewer/?uri=github.com/Wafio/wafio-cp-backend)

This repository is one part of [WAFio](https://github.com/Wafio/wafio). Start there to install WAFio, to see the releases, or to report a problem when you do not know which part it is in.

The Wafio control plane: the HTTP API and gRPC server that agents connect to, the PostgreSQL and TimescaleDB storage behind them, and the decision data the dashboard reads. This repository also holds the Go module `shared/` that both agents compile in and the database migrations. The installers and the release scripts are in wafio-release. The WAF agent is the Rust agent of wafio-agent-waf; this repository holds no WAF agent.

## Place in the platform

| Repo | Contents |
|---|---|
| **wafio-cp-backend (this repo)** | Go control plane, migrations, `shared/` module |
| wafio-cp-frontend | SvelteKit dashboard |
| wafio-agent-waf | Rust WAF agent |
| wafio-agent-host | Go host agent, BPF C |
| wafio-portal | wafio.cloud site and blog (SvelteKit), portal API (Go) (private) |
| uddin-lang-rs | Rust uddin interpreter |
| wafio-release | installers, release bundle layout, release and publish scripts (private) |
| wafio-docs | internal notes (private) |

## Requirements

- Go 1.26.0 (`go` line of `go.mod`) with the `go1.26.11` toolchain (`toolchain` line), which the `go` command fetches on first use.
- PostgreSQL with TimescaleDB for anything that touches the database. `docker-compose.yml` starts `timescale/timescaledb:2.17.2-pg17`.
- For the gates: `golangci-lint`, `gitleaks` 8.30.1, `python3` and `openssl`. A release needs nothing more here; `syft`, `gh` and the release signing key are needs of wafio-release. To regenerate the protocol code: `protoc` 36.2, `protoc-gen-go` 1.36.11, `protoc-gen-go-grpc` 1.6.1.
- Linux for the test suite.

## Build

```sh
go build -trimpath -o build/ ./cmd/wafio
```

Binaries go to `build/`, never to the repository root. The WAF agent is the Rust agent of wafio-agent-waf; this repository builds no WAF agent. See "Release" for the release build.

## Test

```sh
scripts/ci-local.sh
```

`scripts/ci-local.sh` is the full gate. It runs on Linux and covers: a check that no agent instruction files or review IDs are tracked, `gitleaks`, `golangci-lint`, `go build`, `go vet`, `go test`, the same three inside `shared/`, a check that `shared/` imports nothing from `internal/`, the Python tests of the backup and preflight tools in `scripts/tests/`, `go test -race ./...`, and `govulncheck`. The database tests run in addition when `TEST_DB_URL` points at a throwaway database; the migration round trip (`TestMigrationsRoundTrip`) needs `WAFIO_TEST_MIGRATIONS_DSN` pointing at an empty one.

`go test ./...` alone skips the database tests and needs no external service.

The timing tests of the dashboard readers (`TestRollup*Perf`) run only with `WAFIO_PERF_DSN` set, on a migrated database loaded with `internal/adapter/repository/testdata/rollup_perf.sql`: 33 million decisions of one app over 30 days. The comment of `TestRollupAppReadersPerf` says how to run them.

Hosted CI (`.github/workflows/ci.yml`) runs the whole gate of `scripts/ci-local.sh` on every push to `main`, on every pull request and on manual dispatch. The database tests run against a TimescaleDB service that lives for the job.

## Run locally

```sh
docker compose up -d db
cp config/config.example.yaml config/config.yaml
# set jwt.secret and totp.enc_key: openssl rand -hex 32 for each (boot refuses placeholders)
go run ./cmd/wafio serve --migrate     # HTTP :9087, agent gRPC :9090 (mTLS)
go run ./cmd/wafio admin create --email you@example.com --name "Your Name"
```

The dashboard comes from wafio-cp-frontend. Its dev server runs on `:5173` and proxies API calls to `:9087`. For a built copy, point `server.frontend_path` at the build directory.

Security data (GeoIP databases, IP lists) is not in the repository: `wafio fetch-data` downloads it into `security-data/` (only `security-data/ja4/` is tracked).

## Configuration

`config/config.example.yaml` documents every key. Order of precedence: `config/config.yaml`, then `WAFIO_*` environment variables (`server.http_addr` is `WAFIO_SERVER_HTTP_ADDR`), then command line flags. `Config.Validate()` in `internal/config/validate.go` stops the boot on an empty `database.name`, an empty `server.http_addr`, a `jwt.secret` that is empty, too short, a shipped placeholder or previously published, a non-positive `jwt.expire_hours`, wildcard CORS origins with credentials, an empty or malformed `totp.enc_key`, an invalid or too broad `server.trusted_proxies`, agent receive budgets out of range, and a `log.level` other than debug, info, warn or error. Never commit `config/config.yaml`.

## Release

```sh
scripts/build-dist.sh v2.0.0
```

`build-dist.sh` builds the control plane with `go build -trimpath` and writes `dist/controlplane/`: the binary `wafio` (linux/amd64, static), `migrations/`, `NOTICES.txt`, `VERSION` and `SHA256SUMS`. It signs and uploads nothing. The binary is not obfuscated: the source is open, and a plain build can be built again and compared.

The installers, the bundle layout (`deploy/BUNDLE.md`) and the scripts that pack, sign, upload and publish a release are in the wafio-release repository. Its `scripts/release.sh` takes `dist/controlplane/` with `--controlplane`, adds the dashboard build and the installer, and signs the bundle with `wafio release sign` of this repository, so it needs a checkout of this repository next to it. Release builds do not run on the bundle server.

The tests named `TestInstaller*` (in `cmd/wafio` and `internal/adapter/http/handlers`) run parts of the public installer against the CLI and the enrollment handler. They read `deploy/install.sh` from a wafio-release checkout next to this repository, or the file `WAFIO_INSTALLER` names, and are skipped without it; `scripts/ci-local.sh` then lists them as not run, and the gate of wafio-release runs them.

## Layout

```
cmd/wafio/                serve, migrate, admin, rekey, fetch-data, release
internal/                 adapter, agentserver, apicontract, application, certutil, config, conformance,
                          dashboard, domain, engine, fairshare, fsstat, installertest, keyauth, lru, otp,
                          setup, testutil, updater, validate (internal/README.md describes them)
shared/                   Go module github.com/wafio/wafio-cp-backend/shared (see below)
migrations/               000001 to 000126, up and down
api/openapi.yaml          HTTP contract
config/                   config.example.yaml
deploy/                   the backup units (systemd/) and an nginx example for the HTTP API
docs/                     agent-protocol.md, cli.md, operations/, releases/
scripts/                  ci-local.sh, build-dist.sh, gen-proto.sh, gen-notices.sh,
                          backup-controlplane.py, production_preflight.py,
                          tests/ (Python tests of the backup and preflight tools)
security-data/            JA4 lists
test/                     frontend-fixtures: JSON files the dashboard tests copy
Dockerfile                control plane image (`serve --migrate`, ports 9087 and 9090, runs as a user without root)
docker-compose.yml        services db (TimescaleDB) and api (the control plane image)
```

## Migrations

Files are `golang-migrate` pairs, `NNNNNN_name.up.sql` and `.down.sql`: 117 pairs, the latest is 000126, and 000066 to 000072, 000088 and 000092 are unused numbers. A new migration is numbered above every one already applied, or `golang-migrate` never runs it. `wafio migrate up`, `down [--steps N]` and `fresh` (development only, drops everything) run them; the applied version is in `SELECT version, dirty FROM schema_migrations`; `wafio serve --migrate` applies pending ones at boot. The migrations ship in the control plane bundle.

## Dashboard rollups

The app Monitoring tab and the project Overview answer from tables that the control plane fills from `waf_decisions` (migration 000126), not from the decisions themselves. `waf_rollup_minute` holds the counters of each agent, app and minute. `waf_rollup_addr_seen` holds the last time each client address was seen, which counts the distinct addresses of a window. `waf_rollup_hour` holds the busiest values of each agent, app and hour: 500 URIs, 500 user agents, 1000 client addresses, 1000 addresses of blocked, monitored, logged or challenged requests, 200 categories, 200 hosts and 50 methods, each keyed by the md5 of its full text, which is cut to 1024 characters. `waf_rollup_state` has one row: `covered_from`, the oldest instant the rollups hold; `minute_mark` and `hour_mark`, the first instant the minute rows and the hour rows do not hold yet; and `kept_from`, the whole hour at or before the retention cutoff, which readers apply. They are plain tables with or without TimescaleDB, with no project column and no foreign key: a read reaches the project through `agents`, as it does for the decisions.

`wafio serve` runs the job (`internal/application/waf_rollup.go`) next to the retention loop. A pass runs every minute under the advisory lock `wafiorol`, so of several control planes on one database one works. It fills minute and address rows for the decisions recorded up to two minutes ago on the database clock (at most an hour a pass), hour rows of the next complete hour (one hour a pass), and then older hours, newest first, until the pass has used 20 seconds, down to the oldest decision that retention keeps. Each unit is one transaction that moves its mark with its rows. A unit that fails is logged and tried again at the next pass, and until it succeeds a reader counts its range from the decisions. A control plane that was down catches up an hour a pass.

A reader takes the whole minutes (counters, timelines, distinct addresses) or the whole hours (top lists, map) of its window that lie between `covered_from` and the mark from the rollups, and the two ends of the window from `waf_decisions`, in one repeatable-read transaction, so that a unit that commits meanwhile cannot make it count a decision twice or not at all. A window without a whole bucket reads decisions only, as does a database the job has not run on yet. Decisions before `kept_from` are never counted. Counters, timeline buckets of whole minutes and the distinct addresses of a window that ends now are exact. Top lists, the map and the distinct hosts are approximate: an hour keeps only its busiest values, so a value is counted only in the hours where it was among them; its count can be well below the true one and it can drop out of the list. The OpenAPI description of each says so. The previous window of an Overview summary reports 0 distinct addresses.

On the timing set (33 million decisions over 30 days, 63,000 to 79,000 client addresses a day) the tables take about 2.4 GB with their indexes: hour rows 1.6 GB, address rows 0.8 GB, minute rows 30 MB, next to about 2.5 GB of compressed decisions. The hour rows are the large part; compressing them is possible on TimescaleDB and is not done.

The retention pass of `waf_decisions` raises `covered_from` to the first whole hour at or after the oldest decision it keeps and deletes the rollup rows below it, so client addresses, URIs and user agents leave the rollups with the decisions. Everything else that aggregates `waf_decisions` still reads the decisions: the feedback summary, the other dashboard routes, lists and logs. `rollupCounters` and `rollupDims` in `internal/adapter/repository/waf_rollup.go` say what the fill and the raw reads count, one definition each: a new counter goes there, an aggregate over `waf_decisions` for a dashboard window reads the rollups or says in a comment why it does not, and no request text goes into an index key.

## HTTP contract tests

`internal/apicontract` checks responses against `api/openapi.yaml` with kin-openapi. It is test-only: the `depguard` rule in `.golangci.yml` refuses it outside `_test.go` files, so release binaries do not link it. A handler change that alters a response, and every new route, updates the spec in the same change. `WAFIO_CONTRACT_REPORT=1 go test -v ./internal/adapter/http/...` lists the operations no test validated.

## The shared module

`shared/` is a nested Go module, `github.com/wafio/wafio-cp-backend/shared`, tagged `shared/vX.Y.Z`. It holds what the control plane and the agents must agree on: the agent protocol (`shared/proto`, generated Go in `shared/agentpb`), the firewall and trace policy model (`hostpolicy`), trace rule evaluation (`tracefilter`), code both agents run (`agentcore`), telemetry compression, the metrics writer, and the `email`, `geo`, `knownsecrets` and `utctime` packages that wafio-portal also uses. `shared/` imports nothing from `internal/`, and `ci-local.sh` checks it.

A protocol change starts here: edit `shared/proto/agent/v1/agent_control.proto`, run `scripts/gen-proto.sh` (never edit `shared/agentpb` by hand), tag `shared/vX.Y.Z`, then wafio-agent-host bumps its `go.mod` and wafio-agent-waf runs its `scripts/sync-proto.sh`. The root `go.mod` uses `shared` through a `replace` directive on `./shared`.

## Detection

This repository holds no detection code and no WAF agent. The agent of wafio-agent-waf inspects the requests. `internal/engine` here reads, validates and normalises the policy document (`rules_json`), checks custom and script rules when they are saved, and holds the default block and challenge pages and the bot lists. `internal/conformance/blackbox` starts any agent binary (`WAFIO_AGENT_BIN`) against a fake control plane.

## License

Copyright (C) 2026 Wafio. This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 only, as published by the Free Software Foundation. It comes without any warranty. The full text is in `LICENSE` (SPDX: `GPL-3.0-only`). Third-party notices are in `NOTICES.txt`, which `scripts/gen-notices.sh` regenerates.
