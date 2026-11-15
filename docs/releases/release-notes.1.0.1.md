Switch TLS presets from Chrome to Firefox (JA4 match)

Replace Chrome presets with Firefox presets derived from a real
Firefox ClientHello capture:

- NssStream: Firefox cipher suite + signature algorithm presets,
 GREASE off, ECH GREASE on, ALPN "h2:http/1.1"
- nss_wrapper: add ECDHE-ECDSA-AES256-SHA (0xC00A), Firefox named
 groups (SSL_NamedGroupConfig) with fallback for NSS without ML-KEM,
 3 key shares, session tickets + delegated credentials on,
 GREASE ECH via SSL_EnableTls13GreaseEch (size 223), RFC 8879
 compress_certificate (zlib) via SSL_SetCertificateCompressionAlgorithm
- CMake: add zlib dependency
- README: update preset description and NSS limitations

Verified ClientHello matches Firefox: ciphers, sig algs, extension
order, delegated_credentials, record_size_limit, ALPN (compress_cert
and MLKEM group require NSS >= 3.101/3.104).