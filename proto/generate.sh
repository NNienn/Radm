#!/usr/bin/env bash
set -euo pipefail

# Find directory containing script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "Generating Python protobuf bindings..."
mkdir -p ../inference/src/proto
protoc --proto_path=. \
       --python_out=../inference/src/proto \
       --pyi_out=../inference/src/proto \
       radm.proto

echo "Bindings generated."
