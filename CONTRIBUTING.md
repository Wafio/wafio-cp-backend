# Contributing to wafio-cp-backend

Thank you for looking at the code. This file says what a change needs before it can be merged.

## Before you start

- For anything larger than a small fix, open an issue first and say what you want to change. It saves you work if the change does not fit.
- A security problem does not go into an issue: see `SECURITY.md`.

## Build and test

The requirements are in the README. The full gate runs on Linux:

```sh
scripts/ci-local.sh
```

`go test ./...` alone needs no database. The README sections "Test" and "Migrations" say what the database tests need.

## Rules of this repository

- A change to the agent protocol starts in `shared/proto/agent/v1/agent_control.proto`; run `scripts/gen-proto.sh` and never edit `shared/agentpb` by hand.
- `shared/` imports nothing from `internal/`.
- A migration has an up and a down file, and the down file brings the schema back.
- A new or changed endpoint is also changed in `api/openapi.yaml`.
- This repository holds no detection code. A change to what the WAF agent detects does not belong here.
- A new dependency must be maintained and have a licence that GPL-3.0 allows; run `scripts/gen-notices.sh` after adding one.

## Pull requests

- One topic per pull request, with tests for what it changes.
- Say what the change does and how you checked it.
- Commit messages and comments are plain English.
- Do not commit secrets, local configuration, certificates or keys.
- Do not add instruction files for coding assistants, or planning notes, to the repository. The gate refuses them.

## Licence of your contribution

The project is under the GNU General Public License, version 3 only (`LICENSE`). Before a contribution can be merged you must agree to the Wafio Contributor Licence Agreement in `CLA.md`. You keep your copyright; the agreement gives Wafio the right to publish your contribution in this project and in the products built from it. Section 5 of `CLA.md` says how to agree.

If part of a change comes from another project, say so in the pull request: the project, the copyright holder and the licence. Such code needs an entry in the third-party notices.
