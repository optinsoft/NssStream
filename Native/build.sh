#!/usr/bin/env bash
# Builds the native NSS wrapper (libproxymap_nss.so / libproxymap_nss.dylib).
#
# The result is placed into build/<rid> so that native artifacts of different
# platforms can live side by side in the repository without overwriting each
# other. The RID is taken from the first argument; when omitted it is
# auto-detected from the host system:
#
#   ./build.sh              # auto-detect (linux-x64, linux-arm64, osx-arm64, osx-x64)
#   ./build.sh linux-x64    # force a specific RID
set -euo pipefail
cd "$(dirname "$0")"

rid="${1:-}"
if [ -n "$rid" ]; then
    shift
else
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64)  rid=linux-x64 ;;
        Linux/aarch64) rid=linux-arm64 ;;
        Darwin/arm64)  rid=osx-arm64 ;;
        Darwin/x86_64) rid=osx-x64 ;;
        *)
            echo "Cannot auto-detect RID from $(uname -s)/$(uname -m); pass it as the first argument, e.g.: $0 linux-x64" >&2
            exit 1
            ;;
    esac
fi

build_dir="build/$rid"
echo "RID:          $rid"
echo "Build dir:    $build_dir"

rm -rf "$build_dir"
cmake -G Ninja -B "$build_dir" -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build "$build_dir"
