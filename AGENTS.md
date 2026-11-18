# AGENTS.md

Instructions for coding assistants that work on wafio-cp-backend. The rules for every contribution are in
`CONTRIBUTING.md`; this file is the short form.

## What this is

The Wafio control plane, in Go: the HTTP API, the gRPC server the agents connect to, the database migrations
(PostgreSQL with TimescaleDB), and `shared/`, a nested Go module both agents use. Linux for the tests.

## Commands

    go build -trimpath -o build/ ./cmd/wafio   # the binary, into build/
    go test ./...                              # the tests that need no database
    scripts/ci-local.sh                        # the gate: must pass before a pull request

The gate runs the secret scan, `golangci-lint`, build, vet, the tests with the race detector, `govulncheck`
and, with `TEST_DB_URL` set, the database tests. Fix what it reports; do not disable a check.

## Rules

- No detection code here. A change to what the WAF agent detects does not belong in this repository.
- A change to the agent protocol starts in `shared/proto/agent/v1/agent_control.proto`; then run
  `scripts/gen-proto.sh`.
- `shared/` imports nothing from `internal/`.
- A migration has an up and a down file, and the down file brings the schema back.
- A new or changed endpoint is also changed in `api/openapi.yaml`.
- A change comes with a test.
- A new dependency must be maintained and have a licence GPL-3.0 allows; run `scripts/gen-notices.sh`.

## Do not edit

- `shared/agentpb/`: generated from the proto file.
- A migration that is already released: add a new one.
- `LICENSE`, `CLA.md`.

## Writing

Comments, commit messages and documents are plain English. One topic per pull request.

## Security

Do not put a vulnerability in an issue, a pull request or a commit message. `SECURITY.md` says how to report it.

## The person, not the assistant

The person who opens the pull request has read the change, understands it and answers for it, and agrees to
`CLA.md`. A security
report must be reproduced before it is sent. `CONTRIBUTING.md`, "Work done with a coding assistant", says the same.
