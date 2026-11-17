#!/usr/bin/env bash
# Generate the Go code of the agent protocol from shared/proto into shared/agentpb.
#
# The committed files were made with protoc v36.2 (reported as v7.36.2),
# protoc-gen-go v1.36.11 and protoc-gen-go-grpc v1.6.1; the headers of the
# generated files name the versions. Use the same ones, or the diff is noise.
#
# Requires:
#   protoc               https://github.com/protocolbuffers/protobuf/releases
#   protoc-gen-go        go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
#   protoc-gen-go-grpc   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
set -euo pipefail

cd "$(dirname "$0")/.."

# Make sure the plugins are on PATH (handles a custom GOPATH).
export PATH="$(go env GOPATH)/bin:$PATH"

OUT_DIR="shared/agentpb"
mkdir -p "$OUT_DIR"

# module= strips the import path of the go_package option, so the files land
# directly in $OUT_DIR (package agentv1).
MODULE="github.com/wafio/wafio-cp-backend/shared/agentpb"
protoc \
  --proto_path=shared/proto \
  --go_out="$OUT_DIR" --go_opt=module="$MODULE" \
  --go-grpc_out="$OUT_DIR" --go-grpc_opt=module="$MODULE" \
  shared/proto/agent/v1/agent_control.proto

echo "generated: $OUT_DIR/*.go"
