#!/usr/bin/env bash
# Build what a release takes from this repository: the control plane binary, the migrations and the notices.
#
#   scripts/build-dist.sh <version>
#
# Output, in dist/controlplane/:
#   wafio          the control plane, linux/amd64, static
#   migrations/    the database migrations
#   NOTICES.txt    the notices scripts/gen-notices.sh generates
#   VERSION        <version>
#   SHA256SUMS     the SHA-256 of every file above
# scripts/release.sh of wafio-release takes the directory (--controlplane), adds the dashboard build and the installer,
# packs the bundle and signs it. Nothing here is signed or uploaded.
#
# Needs: go.
set -euo pipefail

version=${1:?usage: scripts/build-dist.sh vX.Y.Z}
[ $# -eq 1 ] || { echo "usage: scripts/build-dist.sh vX.Y.Z" >&2; exit 2; }
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo "build-dist: the version must look like v1.11.0" >&2; exit 2; }

cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=dist/controlplane

echo "[1/3] notices"
bash scripts/gen-notices.sh

echo "[2/3] wafio $version (linux/amd64)"
rm -rf "$out"
mkdir -p "$out"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=$version" -o "$out/wafio" ./cmd/wafio

echo "[3/3] $out"
cp -R migrations "$out/migrations"
# gen-notices.sh leaves NOTICES.txt with the mode of its temporary file (0600); the notices are for everyone to read.
install -m 0644 NOTICES.txt "$out/NOTICES.txt"
printf '%s\n' "$version" > "$out/VERSION"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$out" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sha256 "$f"; done > SHA256SUMS)
echo "      $(wc -l < "$out/SHA256SUMS" | tr -d ' ') files, wafio sha256 $(awk '$2 == "wafio" {print $1}' "$out/SHA256SUMS")"
