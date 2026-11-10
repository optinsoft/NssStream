#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

rm -rf build
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build build
