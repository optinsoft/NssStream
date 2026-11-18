# NssStream 1.0.7

ALPN correctness release. `NssStream` now honors an empty
`ApplicationProtocols` list exactly like `SslStream` does. This is a
managed-only change — the native library (`proxymap_nss`) is unchanged
from 1.0.6, so updating the managed assembly is sufficient.

## Highlights

- An empty `ApplicationProtocols` list now suppresses the ALPN extension
  entirely, matching `SslStream` semantics.
- ALPS settings are filtered down to protocols actually offered via ALPN.

## Fixed

### Managed (`NssStream`)

- **Empty `ApplicationProtocols` is honored.** Previously the ALPN protocol
  list was only set when the collection was non-empty, so applying client
  options with an empty list silently left the Chrome/Firefox ALPN preset from
  the constructor in place. Per `SslStream` semantics, once options are
  applied they fully define ALPN: `null` or an empty
  `ApplicationProtocols` now means "do not send the ALPN extension at all".
- **ALPS no longer advertises protocols that are not offered via ALPN.** The
  `_alpsProtos` list is now intersected with the effective ALPN list in
  `ApplyClientOptions`, so an application protocol that was removed (or never
  included) by the applied options is no longer announced via ALPS.

## Upgrade notes

- Managed assembly only; no native library update is required.
- If you relied on the constructor preset surviving an
  `ApplyClientOptions` call with an empty `ApplicationProtocols`, set the
  full preset explicitly in the options instead — empty now means "no ALPN".
