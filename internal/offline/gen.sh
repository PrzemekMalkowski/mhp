#!/bin/sh
# Builds the WebAssembly half of the offline copy (cmd/mhpwasm) and copies the matching Go JS runtime glue.
# Run via `go generate ./internal/offline` before building mhp (the outputs are embedded).
set -e
cd "$(dirname "$0")"
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o mhp.wasm ../../cmd/mhpwasm
gzip -9f mhp.wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm_exec.js
