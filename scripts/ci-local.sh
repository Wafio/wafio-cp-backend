#!/usr/bin/env bash
# Every gate of this repository, for when hosted CI cannot run. Runs all gates,
# keeps going after a failure, prints a summary and exits nonzero if any gate
# failed. It runs on Linux.
#
# Notes:
#   - it checks the working tree, uncommitted files included;
#   - the database tests run only with TEST_DB_URL set, pointing at a throwaway
#     database. The plain `go test` step runs without it, because a test that
#     leaves state behind breaks the next one on the same database.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

failed=()
notrun=()
step() {
  local name=$1 start=$SECONDS
  shift
  printf '\n== %s\n' "$name"
  if "$@"; then
    printf -- '-- ok: %s (%ds)\n' "$name" $((SECONDS - start))
  else
    printf -- '-- FAILED: %s (%ds)\n' "$name" $((SECONDS - start))
    failed+=("$name")
  fi
}

# Agent instruction files, tracker and finding IDs and planning-doc references must not live in
# this repository. The checks need a git checkout (git ls-files, git grep). Without one they would
# find nothing and pass, so the step fails instead.
ai_material() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -e .git ] || { echo 'ai check: needs a git checkout' >&2; return 1; }
  # Names are written with a bracket (PORTIN[G]) so that this file does not match its own patterns.
  local ai_files='(^|/)(AGENTS|CLAUDE|GEMINI)\.md$|(^|/)\.claude/|copilot-instructions|port-statu[s]|PORTIN[G]\.md'
  local ai_ids='(^|[^A-Za-z0-9_])(K-[0-9]{2,3}|[Ww]ave[- ]?[0-9]+|WP-[0-9]+|DEC-[0-9]+|FSD-[0-9]+|BR-[0-9]+|ADR-[0-9]+|CF-[0-9]+|SP-[0-9]+|TG-[0-9]+|OD-[0-9]+|CU-[0-9]+|RK-[0-9]+|POC-[A-Z]+|GAP-[A-Z]+-[0-9]+|F-[0-9]{2}|SEC-[0-9]{2}|REQ-[0-9]+|INV-[0-9]{1,2})([^0-9]|$)'
  local ai_docs='(^|[^A-Za-z0-9_])(PORTIN[G]|port-statu[s]|docs/(superpowers/)?plan[s]/|[Pp]lan §[0-9]|[Ss]pec §[0-9]|PRD §[0-9])'
  local ai_refs='(AGENT[S]|CLAUDE|GEMINI)\.md'
  local bad='ai check: pattern self-test failed'
  # No \b (macOS git grep -E matches nothing with it) and no grep -q after a pipe (SIGPIPE under pipefail).
  # The samples are built with printf so that this file does not match its own patterns.
  [ "$(printf 'x K-%s y\n' 12 | grep -cE "$ai_ids")" = 1 ] || { echo "$bad" >&2; return 1; }
  [ "$(printf 'x POC-%s y\n' FCGI | grep -cE "$ai_ids")" = 1 ] || { echo "$bad" >&2; return 1; }
  [ "$(printf 'x GAP-RT-%s y\n' 04 | grep -cE "$ai_ids")" = 1 ] || { echo "$bad" >&2; return 1; }
  [ "$(printf 'x F-%s y\n' 05 | grep -cE "$ai_ids")" = 1 ] || { echo "$bad" >&2; return 1; }
  [ "$(printf 'see %s/plans/x\n' docs | grep -cE "$ai_docs")" = 1 ] || { echo "$bad" >&2; return 1; }
  [ "$(printf 'see %s.md\n' AGENTS | grep -cE "$ai_refs")" = 1 ] || { echo "$bad" >&2; return 1; }
  if git ls-files | grep -E "$ai_files"; then echo 'ai check: agent files tracked' >&2; return 1; fi
  if git grep -nIE "$ai_ids" -- ':!*.md'; then echo 'ai check: IDs in code or strings' >&2; return 1; fi
  if git grep -nIE "$ai_docs" -- ':!*.md'; then echo 'ai check: planning docs referenced in code or strings' >&2; return 1; fi
  if git grep -nIE "$ai_refs" -- ':!*.md'; then echo 'ai check: agent files referenced in code or strings' >&2; return 1; fi
}

secrets() {
  command -v gitleaks >/dev/null || { echo "gitleaks not installed (pinned to 8.30.1)"; return 1; }
  gitleaks git --redact --verbose --exit-code 1 --config .gitleaks.toml .
}

# shared/ is a nested module; the root `./...` patterns skip it.
shared() (
  cd shared && go vet ./... && golangci-lint run -c ../.golangci.yml ./... && go test ./...
)

shared_race() (
  cd shared && go test -race -timeout 30m ./...
)

# shared/ must not import this repository's internal packages.
shared_isolated() (
  cd shared && ! go list -deps ./... | grep 'wafio-cp-backend/internal'
)

# The Python tests of the backup and preflight tools.
script_tests() {
  python3 -m unittest discover -s scripts/tests -p 'test_*.py'
}

dirty=$(git status --porcelain)
[ -z "$dirty" ] || echo "note: uncommitted changes are checked too"

step "agent material and IDs" ai_material
step "secret scan" secrets
step "golangci-lint" golangci-lint run ./...
step "go build" go build ./...
step "go vet" go vet ./...
step "go test" env -u TEST_DB_URL go test ./...
step "shared module (vet, lint, test)" shared
step "shared imports no internal package" shared_isolated
step "script tests" script_tests
step "race" env -u TEST_DB_URL go test -race -timeout 30m ./...
step "race (shared)" shared_race
step "govulncheck" go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
if [ -n "${TEST_DB_URL:-}" ]; then
  # -p 1: the packages share one database, and a migration test takes DDL locks
  # and can deadlock with another package's inserts when they run side by side.
  step "database integration" go test -count=1 -race -p 1 ./internal/adapter/... ./internal/domain/...
else
  notrun+=("database integration (set TEST_DB_URL)")
fi
# The tests named TestInstaller* run parts of the public installer against this repository. The installer is in
# wafio-release; without it they are skipped here, and the gate of wafio-release runs them.
if [ -z "${WAFIO_INSTALLER:-}" ] && [ ! -f ../wafio-release/deploy/install.sh ]; then
  notrun+=("installer tests (set WAFIO_INSTALLER or check out ../wafio-release; its gate runs them)")
fi

printf '\n== summary\n'
for n in "${notrun[@]+"${notrun[@]}"}"; do echo "not run: $n"; done
[ -z "$dirty" ] || echo "note: the working tree had uncommitted changes"
if [ ${#failed[@]} -gt 0 ]; then
  for n in "${failed[@]}"; do echo "FAILED: $n"; done
  exit 1
fi
echo "all gates passed"
