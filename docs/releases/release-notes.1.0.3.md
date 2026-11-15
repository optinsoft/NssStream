# NssStream v1.0.3 — macOS (Apple Silicon) support

NssStream now runs on **macOS (arm64)** in addition to Linux (x64) and Windows (x64). The same managed API, the same Firefox-accurate ClientHello, native HTTP/2 — now on your Mac.

## Highlights

- **New platform: macOS arm64 (Apple Silicon).** The NuGet package now ships a
  prebuilt native binary for `osx-arm64` (`libproxymap_nss.dylib`) alongside
  `win-x64` and `linux-x64` — NuGet picks the right one automatically, no manual
  copying. (Intel Macs: `dotnet pack -p:MacNativeRuntimeIdentifier=osx-x64`.)
- **Zero runtime dependencies to install beyond NSS itself.** On macOS the
  native library links dynamically against the Homebrew NSS/NSPR libraries —
  the same libraries Firefox uses. Getting started is just:
  `brew install nss && dotnet add package NssStream`.
- **Full Firefox fingerprint on macOS.** Homebrew tracks current NSS releases,
  so ML-KEM (X25519MLKEM768), RFC 8879 certificate compression
  (compress_certificate) and ECH GREASE are all available out of the box —
  unlike typical system NSS on Linux, which is often older than 3.101.
- **Build from source on macOS.** `Native/build.sh` now works on macOS
  unchanged: `cmake` + Ninja produce `build/libproxymap_nss.dylib`, linked via
  pkg-config against Homebrew NSS/NSPR.

## What changed

- Added macOS (arm64) native build of the C wrapper (`libproxymap_nss.dylib`).
- `NssStream.csproj` packs the macOS binary under `runtimes/osx-arm64/native/`;
  the RID is configurable via `-p:MacNativeRuntimeIdentifier` for Intel Macs.
- `Native/CMakeLists.txt` resolves NSS/NSPR via pkg-config on macOS
  (`nss.pc` / `nspr.pc` installed by Homebrew).
- Documentation: macOS prerequisites, build steps and runtime notes in the README.

## Install

```bash
brew install nss
dotnet add package NssStream
```

## Build from source (macOS)

```bash
git clone --recursive https://github.com/optinsoft/NssStream.git
cd NssStream
brew install nss cmake ninja
cd Native && ./build.sh && cd ..
dotnet run --project NssConsole
```

## Notes

- macOS is a dynamic-link platform like Linux: NSS/NSPR shared libraries come
  from Homebrew, nothing is bundled in the package.
- No API changes; existing code works unchanged on all three platforms.

**Full Changelog:** https://github.com/optinsoft/NssStream/compare/v1.0.2...v1.0.3
