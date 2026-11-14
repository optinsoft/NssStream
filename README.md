# NssStream

A .NET library that provides an `SslStream`-compatible TLS stream backed by
**Mozilla NSS** — the TLS library used by **Firefox** — with full control over
the ClientHello and native HTTP/2 support.

It is the NSS sibling of [BoringSslStream](https://github.com/optinsoft/BoringSslStream):
the managed API, the full-duplex architecture and the native C API are
identical — only the TLS engine underneath is different. All NSS native
read/write operations are routed through a managed .NET `NetworkStream` (or
any `Stream`) via a custom `PRFileDesc` queue layer:

```text
TcpClient
   |
NetworkStream  (innerStream)
   |
NssStream (C#): pumps bytes between the stream and the queues
   |
NSS SSL layer  (pure TLS state, no network)
   |
queue PRFileDesc layer (custom bottom layer of the fd stack)
```

NSS has no memory BIOs, so the wrapper (`Native/nss_wrapper.c`) pushes the NSS
SSL layer (`SSL_ImportFD`) on top of a custom `PRFileDesc` layer: everything
NSS sends is appended to an internal write queue, everything the application
feeds in via `pms_ssl_feed_read` is buffered in an internal read queue, and
the layer reports itself as non-blocking. `SSL_ForceHandshake()`,
`PR_Recv()` and `PR_Send()` therefore behave exactly like BoringSSL with
memory BIOs — they return `PR_WOULD_BLOCK_ERROR` and the managed pump moves
bytes in and out.

The repository also contains a **demo console application** (`NssConsole`)
that showcases the library by connecting to real HTTPS endpoints, and an
**xUnit test suite** (`NssStream.Tests`).

## Key Features

- **Full-Duplex Architecture:** Independent read/write and network
  synchronization locks (`_readLock`, `_writeLock`). The .NET application can
  read and write over TLS concurrently without risking memory corruption or
  race conditions within the native NSS `sslSocket` state machine.
- **Production-Grade Certificate Validation:** Built-in cryptographic chain
  validation (`X509Chain`) utilizing the host operating system's trusted root
  certificate store. It natively enforces online revocation checks
  (`X509RevocationMode.Online`).
- **Secure Hostname & Wildcard Matching:** Uses the modern .NET 8 API
  (`certificate.MatchesHostname`) to safely validate Subject Alternative Names
  (SAN) and Common Names (CN), including strict adherence to RFC 6125 wildcard
  rules (preventing sub-domain bypasses).
- **TLS 1.2 / TLS 1.3 with configurable cipher suites and signature
  algorithms:** the Firefox-style presets are translated into NSS settings:
  `SSL_CipherPrefSet` (exact cipher suite filtering), `SSL_SignatureSchemePrefSet`,
  `SSL_NamedGroupConfig` (Firefox's exact named-group list and priority order),
  `SSL_SendAdditionalKeyShares` (three key shares, like Firefox),
  `SSL_ENABLE_DELEGATED_CREDENTIALS`, `SSL_ENABLE_SESSION_TICKETS`, the ECH
  GREASE extension (`SSL_EnableTls13GreaseEch`, NSS 3.68+), the
  `compress_certificate` extension (`SSL_SetCertificateCompressionAlgorithm`,
  zlib), and ALPN with correct preference order (the wrapper compensates
  the NPN-style reordering `SSL_SetNextProtoNego` performs internally).
- **Native HTTP/2 Support:** Fully supports HTTP/2 protocol negotiation via
  ALPN ("h2"). Features a lightweight frame processing pipeline, HPACK binary
  payload encoding for pseudo-headers, and frame-level stream flow handling
  (DATA, HEADERS, SETTINGS, RST_STREAM, GOAWAY).

### NSS-specific limitations

The ClientHello replicates a real Firefox ClientHello. NSS features that
are unavailable in the linked NSS version are accepted in the API but
silently ignored:

- `alpsProtos` — NSS has no ALPS support;
- `trustAnchors` — the BoringSSL `requested_trust_anchors` extension;
- `enableEchGrease` — requires the experimental `SSL_EnableTls13GreaseEch`
  API (NSS 3.68+); silently skipped on older NSS;
- `enableBrotli` — registers RFC 8879 certificate compression algorithms in
  the Firefox order zlib(1), brotli(2), zstd(3) via
  `SSL_SetCertificateCompressionAlgorithm` (requires NSS 3.101+ with that
  experimental API). zlib is statically linked from the vendored sources
  NSS ships in nss/lib/zlib, brotli is statically linked from the vendored
  sources in `brotli/`, and zstd (a separate library — not zlib) is
  statically linked from the vendored sources in `zstd/`. Silently skipped
  when the API is unavailable;
- ML-DSA signature algorithms (`ML-DSA-44/65/87`) are skipped unless the
  linked NSS version supports them;
- the X25519MLKEM768 named group is skipped on NSS versions without ML-KEM
  support (earlier than 3.101).

## Installation

The library ships as a self-contained NuGet package: the managed assembly and
the prebuilt native binary (`proxymap_nss`) travel together under
`runtimes/{RID}/native/` (`win-x64`, `linux-x64`, `osx-arm64`), so NuGet picks
the correct binary for the consumer's platform automatically — no manual
copying.

Unlike BoringSslStream, the native binary links **dynamically** against the
system NSS/NSPR libraries (`libnss3`, `libssl3`, `libnspr4`, ...), the same
libraries Firefox itself uses:

- **Linux:** install `libnss3` (present on virtually every distribution).
- **macOS:** install NSS/NSPR via [Homebrew](https://brew.sh): `brew install nss`
  (pulls in `nspr`). The native binary links against the Homebrew
  libraries (`/opt/homebrew/opt/nss`, `/opt/homebrew/opt/nspr` on Apple
  Silicon; `/usr/local/...` on Intel Macs).
- **Windows:** the NSS/NSPR DLLs (`nspr4.dll`, `nss3.dll`, `ssl3.dll`,
  `nssutil3.dll`, `plc4.dll`, `plds4.dll`, `softokn3.dll`, `freebl3.dll`)
  must be reachable by the process, **plus `sqlite3.dll`** (softoken loads
  it dynamically at startup even in NoDB mode). When building from source
  in this repository they are copied next to the executable automatically;
  otherwise copy them from an NSS source build into the application
  directory. (The gyp build of NSS links the softoken module
  into `nss3.dll`; at startup, however, softoken dynamically loads
  `freebl3.dll`, so it must be present too — otherwise `NSS_NoDB_Init`
  fails with "error 126" (ERROR_MOD_NOT_FOUND). A missing or
  wrong-architecture `sqlite3.dll` makes the same call fail with
  "error 193" (ERROR_BAD_EXE_FORMAT) — `PR_LOAD_LIBRARY_ERROR` (-5977).
  Note that PATH can silently change *which* `sqlite3.dll` gets picked up:
  if the application directory has none, the loader walks PATH and may
  load a wrong-bitness copy from another tool's directory (PHP, MSYS2,
  MinGW, ...).)

```powershell
dotnet add package NssStream
```

## Usage

```csharp
using System.Net.Sockets;
using NssSsl;

using var client = new TcpClient(host, 443);
await using NetworkStream networkStream = client.GetStream();

using var sslStream = new NssStream(networkStream, host);
await sslStream.AuthenticateAsClientAsync();

Console.WriteLine($"TLS version:   {sslStream.ProtocolVersion}");
Console.WriteLine($"Cipher:        {sslStream.CipherName}");
Console.WriteLine($"ALPN selected: {sslStream.AlpnSelected}");
```

The stream exposes the same surface as `System.Net.Security.SslStream`
(`ReadAsync`, `WriteAsync`, certificate validation callbacks, ALPN options),
so it can be dropped in wherever a TLS stream is expected.

## Building from source

NSS and NSPR are vendored as **Git submodules** (`nss`, `nspr`) — the
same sources Firefox itself is built from, which guarantees the exact
NSS behavior (ML-KEM, RFC 8879 certificate compression, ECH GREASE)
needed to replicate the Firefox ClientHello:

```text
NssStream.sln
  NssStream/        (Managed C# class library, NuGet-packable)
  NssConsole/       (Demo console application)
  NssStream.Tests/  (xUnit test suite)
  Native/           (Native C wrapper & CMake configuration)
  nss/              (Git submodule — NSS sources)
  nspr/             (Git submodule — NSPR sources)
```

To clone this repository along with the NSS and NSPR submodules, run:

```bash
git clone --recursive https://github.com/optinsoft/NssStream.git
```

### Prerequisites

- .NET 8 SDK
- CMake 3.22+ and Ninja
- NSS/NSPR development headers and libraries (**required** — without them
  the native wrapper does not compile):

  Debian/Ubuntu/WSL (Ubuntu):

  ```bash
  sudo apt install libnss3-dev libnspr4-dev
  ```

  Fedora/RHEL:

  ```bash
  sudo dnf install nspr-devel nss-devel
  ```

  macOS (Homebrew — also installs the `nss.pc`/`nspr.pc` pkg-config files,
  so no extra paths are needed):

  ```bash
  brew install nss cmake ninja
  ```

  Alternatively, a custom NSS/NSPR prefix can be passed to CMake via
  `-DNSS_INCLUDE_DIR=... -DNSS_LIBRARY_DIR=...` (and the NSPR equivalents).
  On Linux and macOS the build links the system NSS/NSPR by default; the
  `nss`/`nspr` submodules are what the Windows build compiles (see below). To get the
  full Firefox fingerprint on Linux as well (system NSS may be older than
  3.101 and lack ML-KEM / certificate compression), build the submodules
  and point CMake at their `dist` output — at runtime the process must
  then load *those* NSS/NSPR shared libraries instead of the system ones
  (e.g. via `LD_LIBRARY_PATH`).

  Note: at runtime only the NSS/NSPR **shared libraries** are used
  (`libnss3`, `libssl3`, `libnspr4`, ...), the same libraries Firefox itself
  uses — they are installed by default on virtually every Linux
  distribution. The `*-dev` packages above are needed for building only.
  On macOS the Homebrew NSS/NSPR libraries are the runtime libraries too
  (Homebrew updates `nss` promptly, so ML-KEM and RFC 8879 certificate
  compression are available there).

  Windows has no system NSS: NSS/NSPR are built from source with
  [MozillaBuild](https://wiki.mozilla.org/MozillaBuild) — see the step-by-step
  instructions in the *Native library → Windows* section below.

### Native library

#### Linux / macOS / WSL

```bash
cd Native
./build.sh
```

On Linux (including WSL) this produces `build/libproxymap_nss.so`; on macOS —
`build/libproxymap_nss.dylib`. The wrapper is a thin C file (`nss_wrapper.c`)
that links against the system `libssl3`/`libnss3`/`libnspr4` on Linux and
against the Homebrew NSS/NSPR libraries on macOS (found via pkg-config or
the default `/opt/homebrew` / `/usr/local` prefixes).

#### Windows

Windows has no system NSS packages, so NSS and NSPR are built from source
inside the repository. The build itself runs under
[MozillaBuild](https://wiki.mozilla.org/MozillaBuild) — the toolchain Firefox
is built with on Windows.

**0. Install MozillaBuild.** Download and run the installer directly:

```
https://ftp.mozilla.org/pub/mozilla/libraries/win32/MozillaBuildSetup-Latest.exe
```

The [Firefox on Windows build instructions]
(https://firefox-source-docs.mozilla.org/setup/windows_build.html)
describe the same setup: follow only step *1. Install MozillaBuild* there
and **stop before step *2. Bootstrap a copy of the Firefox source code*** —
bootstrapping Firefox is not needed, NSS is built standalone.

What matters is the shell itself (`start-shell.bat`): bash, perl, python
and the MSVC integration it provides. The NSS build additionally needs
`gyp` and `ninja`; if they are missing, install them inside the shell:

```bash
pip install gyp-next ninja
```

**1. Install a real GNU make.** MozillaBuild does not ship `make.exe`, and
without it the shell picks up whatever `make` it finds in the Windows PATH —
which silently does nothing. Install GNU Make 4.x via `scoop install make`
(or `choco install make`); it lands in
`/c/Users/<USER>/scoop/apps/make/current/bin/make`.

The scoop directory is typically not on the shell's PATH. Without changing
system environment variables, prepend it inside the running MozillaBuild
shell:

```bash
export PATH="/c/Users/<USER>/scoop/apps/make/current/bin:$PATH"
```

The MSVC `link.exe` will most likely be shadowed by the MSYS coreutils
`link` as well, so prepend the MSVC tool directory too and refresh the
command cache:

```bash
VCBIN="/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
# (the exact MSVC version may differ on your machine)
export PATH="$VCBIN:$PATH"
hash -r
```

Verify both:

```bash
make -v   # must print "GNU Make 4.x"
which link  # must point at .../Hostx64/x64/link
``````

**2. Build NSS/NSPR** in the MozillaBuild shell (`start-shell.bat`):

```bash
cd nss
./build.sh --opt --disable-tests
```

If the build fails with `link: unknown option -- n`, the PATH fixes from
step 2 were not applied in this shell session — re-run them and try again.

The result lands in `..\dist\Release` (with `--opt`; without it — `..\dist\Debug`):

- NSS headers: `..\dist\public\nss` (`nss.h`, `ssl.h`, ...);
- NSPR headers: `..\dist\Release\include\nspr` (`nspr.h`, `prtypes.h`, ...);
- import libraries and runtime DLLs in `..\dist\Release\lib`:
  `nss3.dll.lib`, `ssl3.dll.lib`, `smime3.dll.lib`, `nssutil3.dll.lib`,
  `nspr4.lib`, `plc4.lib`, `plds4.lib`, plus
  `nss3.dll`, `ssl3.dll`, `smime3.dll`, `nssutil3.dll`, `softokn3.dll`,
  `freebl3.dll`, `nspr4.dll`, `plc4.dll`, `plds4.dll`. The gyp build links
  the softoken module into `nss3.dll`, but at startup softoken dynamically
  loads `freebl3.dll`, so at runtime all of `nspr4.dll`, `nss3.dll`,
  `ssl3.dll`, `nssutil3.dll`, `plc4.dll`, `plds4.dll`, `softokn3.dll` and
  `freebl3.dll` must be present (the latter two are also picked up
  automatically by `NssStream.csproj`).

  `sqlite3.dll` — built by the gyp build as a shared library
  (`lib/sqlite/sqlite.gyp`); make sure it is present in `dist\Release\lib`
  together with the rest. softoken loads it dynamically during
  `NSS_NoDB_Init` even in NoDB mode, and `NssStream.csproj` copies/packs it
  together with the other DLLs. Without it, `NSS_NoDB_Init` fails with
  `PR_LOAD_LIBRARY_ERROR (-5977)`, typically wrapping Win32 error 193
  (ERROR_BAD_EXE_FORMAT) when a wrong-bitness `sqlite3.dll` is found on
  PATH instead — e.g. one from PHP, MSYS2 or MinGW directories.

**3. Build the wrapper** — open a *Developer PowerShell for VS 2022 (x64)*:

```powershell
cd Native
.\build.ps1
```

The script finds the NSS/NSPR files under `..\dist` automatically (Release
is preferred over Debug; explicit paths can still be passed with
`-NssIncludeDir / -NssLibraryDir / -NsprIncludeDir / -NsprLibraryDir`).
It produces `build\Release\proxymap_nss.dll`.

**4. Runtime DLLs.** No manual copying is needed: `NssStream.csproj` picks
up `nspr4.dll`, `nss3.dll`, `ssl3.dll`, `nssutil3.dll`, `plc4.dll`,
`plds4.dll`, `softokn3.dll` and `freebl3.dll` from
`..\dist\{Release,Debug}\lib` and copies them to the
output directory of every project that references NssStream (the same way
`proxymap_nss.dll` is handled). The complete runtime set from `dist` —
including `sqlite3.dll` produced by the NSS build itself — is copied
along. Simply run:

```powershell
dotnet run --project NssConsole
```

### .NET build, tests and packing

```bash
dotnet build NssStream.sln
dotnet test  NssStream.Tests
dotnet pack  NssStream/NssStream.csproj -c Release   # -> NssStream.1.0.0.nupkg
```

The native binaries are copied into the .NET output directories automatically
during local builds, and embedded into the NuGet package under
`runtimes/linux-x64/native/`, `runtimes/win-x64/native/` and
`runtimes/osx-arm64/native/` when packing. On Apple Silicon no extra flags are
needed; for Intel Macs override the RID at pack time:

```bash
dotnet pack NssStream/NssStream.csproj -c Release -p:MacNativeRuntimeIdentifier=osx-x64
```

## Demo console application

`NssConsole` demonstrates the end-to-end flow against a real server
(`tls.peet.ws/api/tls` by default):

```bash
dotnet run --project NssConsole
```

What it does:

1. Opens a standard TCP connection to the target server (e.g. `tls.peet.ws:443`).
2. Creates an NSS `sslSocket` over the custom queue `PRFileDesc` layer and
   configures context parameters passed dynamically from C# (cipher suites,
   signature algorithms, ALPN, GREASE flags).
3. Performs `SSL_ForceHandshake()` in the asynchronous pump loop.
4. **Validates the server certificate:** immediately after a successful TLS
   handshake, it extracts the server's DER-encoded X509 certificate via the
   native wrapper (`SSL_PeerCertificate`), runs a full OS-level chain
   validation and matches the connection hostname.
5. Prints the negotiated TLS version, selected ALPN protocol, and cipher suite
   name (IANA naming, as reported by NSS).
6. **Dispatches the HTTP request:**
   - **If HTTP/2 is negotiated ("h2"):** sends the mandatory 24-byte connection
     preface, transmits initial `SETTINGS` frames, encodes request metadata
     using the HPACK encoder, wraps the binary payload into standard 9-byte
     `HEADERS` frame envelopes, and handles bidirectional settings
     acknowledgment.
   - **If HTTP/1.1 is negotiated:** falls back to dispatching plain-text
     HTTP/1.1 requests.
7. Streams the incoming protocol data (automatically demuxing framed binary
   envelopes for HTTP/2 payloads), prints response outcomes to the console,
   and flushes output records into the `./output/` directory.

### Testing certificate validation

The `Program.cs` file includes a set of pre-configured, commented-out test
hosts from the **badssl.com** project to verify secure error-handling:

- `tls.peet.ws` / `badssl.com` - **Standard Verification:** Connection should succeed.
- `expired.badssl.com` - **Expiration Failure:** Handshake must fail during `X509Chain` building.
- `untrusted-root.badssl.com` - **Trust Failure:** Handshake must fail due to an unknown root authority.
- `revoked.badssl.com` - **Revocation Failure:** Handshake must fail because the certificate was revoked by the CA.

### Debugging the raw TLS traffic

Set the `NSSW_DEBUG` environment variable to a file path to dump all raw
record-layer traffic flowing through the queue layer:

```bash
NSSW_DEBUG=/tmp/nssw.log dotnet run --project NssConsole
```

## Tests

The xUnit suite in `NssStream.Tests` runs a local TLS echo/ALPN server and
exercises the library end-to-end: chunked read/write, concurrent read+write,
dispose during concurrent I/O, ALPN options handling, and certificate policy
error reporting.

```bash
dotnet test NssStream.Tests
```

## Current Status

The underlying architecture is fully complete, completely thread-safe, and
passes the full test suite (echo, 64 MB concurrent read+write, dispose-during-
IO, ALPN override, certificate policy errors). The ClientHello is authentic
NSS/Firefox output — cipher suite selection, named groups, key shares,
delegated credentials, the ECH GREASE and compress_certificate extensions,
session tickets and ALPN ordering all follow the configured presets, limited
only by what the linked NSS version supports.

## License

See [LICENSE](LICENSE).
