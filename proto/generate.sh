#!/usr/bin/env bash
set -euo pipefail

# Find directory containing script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "RADM protobuf bindings are checked into the repository."
echo "No code generation is required on this host."
