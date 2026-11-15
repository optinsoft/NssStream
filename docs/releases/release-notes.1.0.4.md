# NssStream v1.0.4 — Brotli & zstd certificate compression, zero extra dependencies

The `compress_certificate` extension (RFC 8879) now offers all three Firefox
algorithms — **zlib(1), brotli(2), zstd(3)** — with the brotli and zstd codecs
**statically linked** into the native wrapper. No `libbrotli`, no `libzstd`, no
`zlib` to install: the ClientHello matches Firefox byte-for-byte and the
connection negotiates certificate compression out of the box on every platform.

## Highlights

- **Full Firefox `compress_certificate` set.** With the default
  `enableBrotli = FirefoxEnableBrotliPreset` the wrapper registers all three
  RFC 8879 algorithms in Firefox's exact preference order —
  zlib(1), brotli(2), zstd(3) — via `SSL_SetCertificateCompressionAlgorithm`
  (requires NSS 3.101+; silently skipped on older NSS or when the experimental
  API is unavailable).
- **Statically linked codecs — nothing to install.** brotli is built from the
  vendored sources in `brotli/`, zstd from the vendored sources in `zstd/`,
  and zlib from the copy NSS itself ships in `nss/lib/zlib`. The codecs are
  compiled into `proxymap_nss` as static libraries with hidden symbols, so
  they cannot interpose with (or be interposed by) the zlib copy NSS links
  into `nss3.dll` / `libnss3.so`. There is no runtime dependency on
  `libbrotlienc`/`libbrotlidec`/`libzstd`/`zlib` on any platform.
- **Opt-out preserved.** `-DNSW_STATIC_BROTLI=OFF` and `-DNSW_STATIC_ZSTD=OFF`
  fall back to the previous behaviour of resolving the codecs at runtime via
  `PR_LoadLibrary`.
- **New: raw TLS traffic dump.** Set `NSSW_DEBUG=<path>` to dump all
  record-layer traffic flowing through the queue layer (thread-safe, hex
  format) — handy for ClientHello fingerprint debugging:
  `NSSW_DEBUG=/tmp/nssw.log dotnet run --project NssConsole`.
- **Cross-platform native builds side by side.** `Native/build.sh` now accepts
  an explicit RID as its first argument (`./build.sh osx-x64`) in addition to
  auto-detection, and places artifacts into `build/<rid>/` — native artifacts
  of different platforms can live in the same repository without overwriting
  each other.

## What changed

- `Native/CMakeLists.txt`: vendored brotli added as static libraries
  (`brotlicommon`/`brotlienc`/`brotlidec`, no CLI/tests/install rules) behind
  the `NSW_STATIC_BROTLI` option; vendored zstd added as a static,
  single-threaded library behind `NSW_STATIC_ZSTD`; zlib built from
  `nss/lib/zlib` with hidden symbols and `verbose=-1` (matching NSS's own
  build).
- `Native/nss_wrapper.c`: brotli and zstd entry points
  (`BrotliEncoderCompress`/`BrotliDecoderDecompress`,
  `ZSTD_compress`/`ZSTD_decompress`) are linked statically; the
  `compress_certificate` registration offers zlib, brotli and zstd in
  Firefox's order; optional `NSSW_DEBUG` raw-traffic dump (guarded by a lock,
  flushed per record).
- `Native/build.sh`: optional RID argument, auto-detect for
  `linux-x64`/`linux-arm64`/`osx-arm64`/`osx-x64`, per-RID build directories.
- Documentation: codec linking details, `NSSW_DEBUG` usage and build.sh RID
  handling in the README.
- Verified against `tls.peet.ws`: certificate compression negotiated, the
  ClientHello still matches Firefox (ciphers, signature algorithms, extension
  order, `delegated_credentials`, `record_size_limit`, ALPN).

## Install

```bash
dotnet add package NssStream
```

No new runtime requirements: zlib/brotli/zstd travel inside the prebuilt
native binary. The platform prerequisites are unchanged — `libnss3` on Linux,
`brew install nss` on macOS, the NSS DLLs (plus `sqlite3.dll`) on Windows.

## Notes

- Certificate compression requires NSS 3.101+ (the
  `SSL_SetCertificateCompressionAlgorithm` experimental API); on older NSS the
  extension is silently skipped and the connection proceeds uncompressed.
- No managed API changes; existing code works unchanged.

**Full Changelog:** https://github.com/optinsoft/NssStream/compare/v1.0.3...v1.0.4
