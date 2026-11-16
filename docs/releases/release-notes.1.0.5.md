# NssStream v1.0.5 — Linux ARM64 (aarch64) support

The NuGet package now ships a prebuilt native binary for **`linux-arm64`**
(`libproxymap_nss.so`) alongside `win-x64`, `linux-x64` and `osx-arm64` —
NuGet picks the right one automatically, no manual copying. The same managed
API, the same Firefox-accurate ClientHello, native HTTP/2 — now on 64-bit ARM
Linux out of the box (Raspberry Pi 4/5, Apple Silicon Linux VMs, AWS
Graviton, arm64 Docker images).

## Highlights

- **New prebuilt native binary: `linux-arm64`.** The package now includes
  `runtimes/linux-arm64/native/libproxymap_nss.so`; on an aarch64 Linux host
  NuGet selects it automatically. As on all Unix platforms, the binary links
  dynamically against the system NSS/NSPR libraries (`libnss3`, `libssl3`,
  `libnspr4`, ...) — the same libraries Firefox uses.
- **`Native/build.sh` on Linux/aarch64.** The script auto-detects
  `Linux/aarch64` → `linux-arm64` (or accepts it explicitly:
  `./build.sh linux-arm64`) and builds into `build/linux-arm64/`, so native
  artifacts of different platforms can live in the same repository without
  overwriting each other.
- **No managed API changes.** The managed assembly is unchanged since 1.0.4;
  existing code works unchanged on all four platforms.

## What changed

- `NssStream.csproj`: packs the Linux ARM64 binary under
  `runtimes/linux-arm64/native/` and auto-detects `linux-arm64` as the local
  native RID; the `EnsureNativeLibrary` warning mentions the new RID.
- Documentation: `linux-arm64` added to the platform list in the README.

## Install

```bash
dotnet add package NssStream
```

On Linux ARM64 the only runtime requirement is NSS/NSPR from the system
package manager, e.g.:

```bash
sudo apt install libnss3 libnspr4   # Debian/Ubuntu
sudo dnf install nss nspr           # Fedora/RHEL
```

## Notes

- No managed API changes; existing code works unchanged.
- Intel Macs are still not prebuilt: pass
  `dotnet pack -p:MacNativeRuntimeIdentifier=osx-x64` as before.
- Any other platform: build the native library from source with
  `Native/build.sh <rid>` and reference the project directly.

**Full Changelog:** https://github.com/optinsoft/NssStream/compare/v1.0.4...v1.0.5
