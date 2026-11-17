# internal/

The control plane follows the hexagonal pattern (ports and adapters): the domain and the use cases do not know about HTTP, gRPC or PostgreSQL.

## Layers

- `domain/` holds the core types, the port interfaces and the rules that need no framework.
- `application/` holds the use cases. They reach storage through the ports of `domain/`, never through `adapter/repository`.
- `adapter/http` (package `httpadapter`) is the Fiber HTTP API: routes in `fiber.go`, handlers in `handlers/`, JWT and stream tickets in `auth/`.
- `adapter/repository` is the PostgreSQL and TimescaleDB storage.
- `agentserver/` is the gRPC server that agents connect to over mTLS: bundles, decision and telemetry ingest, revocation.
- `cmd/wafio` wires them together.

## Other packages

- `engine/` reads, validates and normalises the policy document (`rules_json`), checks custom and script rules when they are saved, and holds the default block and challenge pages and the bot lists. It holds no detection code. `engine/bloom` builds the malware hash corpus.
- `config/` loads and validates the configuration.
- `setup/` downloads the security data (GeoIP databases, IP lists, JA3 and JA4 lists, malware hashes) for `wafio fetch-data`.
- `dashboard/` holds the response types of the log dashboard.
- `certutil/` generates the CA, server and client certificates for agent mTLS.
- `keyauth/` generates and verifies the host key that binds an agent to a host.
- `otp/` holds TOTP, backup codes and the second-factor failure limiter.
- `fairshare/` decides who gives up a slot when an in-memory pool shared by many tenants is full. `lru/` is a bounded, sharded LRU map.
- `fsstat/` reports the free space of the filesystem that holds the database.
- `updater/` verifies the signature and checksum of a release bundle.
- `validate/` holds request validation helpers.
- `apicontract/` checks HTTP responses against `api/openapi.yaml`. It is test-only.
- `conformance/blackbox` runs black-box suites against an agent binary (`WAFIO_AGENT_BIN`). It is test-only.
- `installertest/` and `testutil/` are test support.

## Dependency direction

1. `domain` imports no adapter and no application package (`depguard` in `.golangci.yml`).
2. `application` depends on `domain` and its ports.
3. `adapter/*` may depend on `application` and `domain`, not the other way round.
4. Wiring happens in `cmd/wafio`.
5. `shared/` imports nothing from `internal/` (`scripts/ci-local.sh` checks it).
