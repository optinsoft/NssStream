# NssStream v1.0.6 — Release Notes

Stability and resource-management release for the NSS-backed TLS client
stream (`NssStream`) and its native wrapper (`proxymap_nss`).

## Highlights

- Fixed a process-crashing access violation (`0xC0000005` in `ntdll.dll`)
  that could occur when several connections were created concurrently on
  a freshly started process.
- Native connections are now released deterministically on `Dispose`
  instead of waiting for GC finalization.
- One native connection is created per stream instead of up to two.

## Fixed

### Native wrapper (`nss_wrapper.c`)
- **Access violation on concurrent first use.** NSPR's implicit
  initialization is not thread-safe: a second thread could take an NSPR
  lock that had not been created yet (`PR_Lock(NULL)`). NSPR is now
  initialized explicitly, exactly once, through `InitOnceExecuteOnce`
  (Windows) / `pthread_once` (POSIX) before any other NSPR call.
- **Race in the I/O layer method table.** `g_nsw_methods` could be zeroed
  and re-populated by a second thread while connections created by the
  first thread were already using it, leading to calls through NULL
  function pointers. The table is now built once, inside the same
  `PR_CallOnce` that allocates the layer identity, and a failed layer
  initialization is reported instead of being ignored.
- **Windows build break.** The wrapper's `SetLastError` helper collided
  with the Win32 `SetLastError` declared in `windows.h`
  (error C2375). Renamed to `nsw_set_last_error` / `nsw_set_last_error_f`.
#### Native wrapper hardening

- **Debug dump initialization is now thread-safe.** The optional raw-traffic
  dump (`NSSW_DEBUG`) is initialized exactly once via `PR_CallOnce`, and the
  dump lock is published before the file handle. Concurrent first use of the
  library can no longer race on the debug file or write to a half-initialized
  dump.
- **Input length validation.** `pms_ssl_feed_read`, `pms_ssl_take_write`,
  `pms_ssl_read` and `pms_ssl_write` now reject negative lengths (and
  non-positive lengths for read/write) with `PMS_SSL_ERROR` and a descriptive
  error message instead of converting them to a huge `size_t`. Zero-length
  feed/take calls are a no-op returning `0`. The internal queues also guard
  against `size_t` overflow when growing.
- **Fixed a potential stack buffer overflow in error reporting.**
  `PR_GetErrorText` has no size parameter; the NSPR error text is now copied
  only when it is known to fit the local buffer.
- **ALPN list is bounds-checked.** The ALPN protocol list is validated while
  it is built, so an oversized list can no longer overflow the wire/reversed
  buffers. Such a list now fails fast with the error
  `ALPN protocol list is too long`. The list is also parsed only once.

### Managed stream (`NssStream`)
- **Native memory leak.** `Dispose` / `DisposeAsync` never released the
  native connection; it was only freed when the `SafeHandle` finalizer
  ran. The connection is now freed in `Dispose`, under the same lock that
  serializes all native calls, so create/use/free can no longer overlap.
- **Hangs and masked errors on dispose.** The read/write `SemaphoreSlim`
  instances were disposed while operations could still be queued or in
  flight, which left waiters pending forever and made `Release()` throw
  `ObjectDisposedException` from `finally` blocks. They are no longer
  disposed, and every operation re-checks the disposed state after
  acquiring its lock.
- **Noisy pump shutdown.** An `ObjectDisposedException` raised by the
  write pump because the stream was being disposed was reported as a
  pump failure. It is now treated as a normal shutdown, and pending
  flush waiters receive `ObjectDisposedException`. The pump's
  `CancellationTokenSource` is now disposed by the pump itself.
- **Unsupported options no longer leave a half-configured stream.**
  `ApplyClientOptions` now validates unsupported options (TLS protocol
  set, client certificates, local certificate selection) before it
  changes any state.
- **P/Invoke calling convention.** All imports now declare `cdecl`
  explicitly to match the native `PMS_CALL` definition (relevant for
  32-bit Windows builds).

## Changed

- **Lazy native connection creation.** The native connection is now
  created at the start of `AuthenticateAsClientAsync`, after
  `SslClientAuthenticationOptions` have been applied. Previously it was
  created in the constructor and re-created whenever `TargetHost` or
  `ApplicationProtocols` differed from the defaults, doubling native
  setup cost and exposure to initialization races. `RecreateConnection`
  has been removed.
- **Write pump buffer.** The per-stream 16 KB pinned (POH) array was
  replaced by a pooled buffer that is pinned only for the duration of
  each native call, reducing pinned-heap fragmentation under load.

## Behavior changes to be aware of

- **Errors surface at handshake time.** Failures to create the native
  connection (invalid cipher list, missing native library, NSS
  initialization failure) are no longer thrown by the `NssStream`
  constructor. They are thrown from `AuthenticateAsClientAsync`
  (`IOException` for NSS errors), alongside other TLS errors. Code that
  catches handshake errors will now see them.
- **EOF without `close_notify`.** If the underlying transport is closed
  without a TLS `close_notify`, `ReadAsync` now returns `0`, matching
  `SslStream`, instead of throwing `EndOfStreamException`. EOF during the
  handshake still throws `EndOfStreamException`.
- **Properties before the handshake.** `ProtocolVersion`, `CipherName`
  and `AlpnSelected` return empty strings until the connection has been
  created.
- **ALPN options.** If `SslClientAuthenticationOptions.ApplicationProtocols`
  is `null` or empty, the constructor's ALPN list (default `h2:http/1.1`)
  is kept, whereas `SslStream` would send no ALPN extension.
- Invalid arguments to the native I/O functions (negative lengths, null
  buffers) and ALPN lists longer than 2048 bytes now produce an explicit error
  instead of undefined behavior.

## Upgrade notes

- No public API changes.
- The native library (`proxymap_nss`) and the managed assembly must be
  deployed together; the managed side relies on the one-time NSPR/layer
  initialization performed by the new native code.
- Recommended verification: start the process and perform a burst of
  concurrent handshakes (e.g. 30-50 at once), and dispose streams
  during handshake and during reads.