/*
 * nss_wrapper.c — a thin C wrapper around Mozilla NSS (the TLS library
 * used by Firefox) that exposes the same "memory BIO" style API the
 * BoringSSL-based wrapper (ssl_wrapper.cc) provides.
 *
 * NSS has no memory BIOs. Instead it transports data through a stack of
 * PRFileDesc layers. This wrapper pushes the SSL layer (SSL_ImportFD) on
 * top of a custom "queue" layer: everything NSS "sends" is appended to an
 * internal write queue, and everything the application feeds in via
 * pms_ssl_feed_read is buffered in an internal read queue. The queue
 * layer reports itself as non-blocking, so NSS records flow through it
 * record-wise without ever touching a real socket:
 *
 *   TcpClient
 *      |
 *   NetworkStream          (innerStream, managed by C#)
 *      |
 *   NssStream (C#)         pumps bytes between the stream and the queues
 *      |
 *   NSS SSL layer          (pure TLS state, no network)
 *      |
 *   queue PRFileDesc layer (custom bottom layer of the fd stack)
 *
 * The exported C API is identical to the BoringSSL wrapper, so the
 * managed NssStream class can share the same architecture.
 */

#include "ssl_wrapper.h"

#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <sslexp.h>
#include <sslproto.h>
#include <sslerr.h>
#include <prerror.h>
#include <prlock.h>
#include <prlink.h>
#include <cert.h>
#include <secerr.h>
#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define NSW_THREAD_LOCAL __declspec(thread)
#else
#define NSW_THREAD_LOCAL __thread
#endif

#define NSW_MAX_ALPN_PROTO 255
#define NSW_ERROR_BUFFER_SIZE 512

typedef struct NswQueue
{
    uint8_t* data;
    size_t cap;  /* allocated size */
    size_t len;  /* bytes stored */
    size_t pos;  /* read offset (only used by the read queue) */
} NswQueue;

typedef struct PmsNssConnection
{
    PRFileDesc* fd;      /* top of the stack (the NSS SSL layer) */
    PRFileDesc* bottom;  /* the custom queue layer */

    NswQueue read;   /* ciphertext fed by the application */
    NswQueue write;  /* ciphertext produced by NSS */

    PRLock* lock;

    char* hostname;
} PmsNssConnection;

static NSW_THREAD_LOCAL char g_last_error[NSW_ERROR_BUFFER_SIZE] = "";

/* Optional raw-traffic debug dump: set NSSW_DEBUG=<path>. */
static FILE* g_debug_file = NULL;
static PRLock* g_debug_lock = NULL;

static void nsw_debug_write(const char* direction, const uint8_t* data, size_t len)
{
    if (!g_debug_file)
        return;

    PR_Lock(g_debug_lock);
    fprintf(g_debug_file, "%s %zu:\n", direction, len);
    for (size_t i = 0; i < len; ++i)
    {
        fputc("0123456789abcdef"[(data[i] >> 4) & 0xF], g_debug_file);
        fputc("0123456789abcdef"[data[i] & 0xF], g_debug_file);
        if ((i & 31) == 31)
            fputc('\n', g_debug_file);
    }
    fputc('\n', g_debug_file);
    fflush(g_debug_file);
    PR_Unlock(g_debug_lock);
}

static void nsw_debug_init()
{
    const char* path = PR_GetEnvSecure("NSSW_DEBUG");

    if (!path || !path[0] || g_debug_file)
        return;

    g_debug_file = fopen(path, "w");
    if (g_debug_file)
        g_debug_lock = PR_NewLock();
}

static void SetLastError(const char* message)
{
    snprintf(g_last_error, sizeof(g_last_error), "%s",
             message ? message : "Unknown error");
}

static void SetLastErrorF(const char* fmt, int error)
{
    char text[256] = "";

    if (PR_GetErrorTextLength() > 0)
    {
        PR_GetErrorText(text);
    }

    if (text[0])
    {
        snprintf(g_last_error, sizeof(g_last_error), "%s (%d): %s",
                 fmt ? fmt : "NSS error", (int)error, text);
    }
    else
    {
        snprintf(g_last_error, sizeof(g_last_error), "%s (%d)",
                 fmt ? fmt : "NSS error", (int)error);
    }
}

/* ------------------------------------------------------------------ */
/* One-time NSS initialization                                          */
/* ------------------------------------------------------------------ */

static PRCallOnceType g_nss_init_once;
static PRCallOnceType g_layer_init_once;

static PRStatus PR_CALLBACK nsw_init_nss(void)
{
    /* No certificate database: server certificates are validated by the
     * managed layer (X509Chain), exactly like the BoringSSL wrapper
     * (SSL_VERIFY_NONE + managed validation). */
    if (NSS_NoDB_Init(".") != SECSuccess)
    {
        SetLastErrorF("NSS_NoDB_Init failed", PR_GetError());
        return PR_FAILURE;
    }

    if (NSS_SetDomesticPolicy() != SECSuccess)
    {
        SetLastErrorF("NSS_SetDomesticPolicy failed", PR_GetError());
        return PR_FAILURE;
    }

    return PR_SUCCESS;
}

static PRDescIdentity g_nsw_identity = PR_INVALID_IO_LAYER;

static PRStatus PR_CALLBACK nsw_init_layer_identity(void)
{
    g_nsw_identity = PR_GetUniqueIdentity("proxymap-nss");

    return g_nsw_identity == PR_INVALID_IO_LAYER ? PR_FAILURE : PR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Queue helpers                                                        */
/* ------------------------------------------------------------------ */

static int nsw_queue_reserve(NswQueue* q, size_t extra)
{
    /* The read queue compacts when fully consumed, the write queue is
     * drained by the pump, so cap + len stays bounded in practice. */
    if (q->len + extra <= q->cap)
        return 1;

    size_t newCap = q->cap ? q->cap : 4096;
    while (newCap < q->len + extra)
        newCap *= 2;

    uint8_t* newData = (uint8_t*)realloc(q->data, newCap);
    if (!newData)
        return 0;

    q->data = newData;
    q->cap = newCap;
    return 1;
}

static void nsw_queue_free(NswQueue* q)
{
    free(q->data);
    q->data = NULL;
    q->cap = 0;
    q->len = 0;
    q->pos = 0;
}

/* ------------------------------------------------------------------ */
/* Custom PRFileDesc layer (the "memory BIO" emulation)                 */
/* ------------------------------------------------------------------ */

static PmsNssConnection* nsw_get_connection(PRFileDesc* fd)
{
    return (PmsNssConnection*)(void*)fd->secret;
}

static PRInt32 PR_CALLBACK nsw_recv(
    PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags,
    PRIntervalTime timeout)
{
    (void)flags;
    (void)timeout;

    PmsNssConnection* connection = nsw_get_connection(fd);

    if (!connection)
    {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return -1;
    }

    if (amount <= 0)
    {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return -1;
    }

    PR_Lock(connection->lock);

    size_t available = connection->read.len - connection->read.pos;

    if (available == 0)
    {
        PR_Unlock(connection->lock);
        /* The queue layer is "non-blocking": NSS translates this into
         * PR_WOULD_BLOCK_ERROR propagation and returns SECWouldBlock /
         * SECFailure, letting the caller feed more ciphertext data. */
        PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
        return -1;
    }

    if ((size_t)amount < available)
        available = (size_t)amount;

    memcpy(buf, connection->read.data + connection->read.pos, available);
    connection->read.pos += available;

    if (connection->read.pos == connection->read.len)
    {
        connection->read.pos = 0;
        connection->read.len = 0;
    }

    PR_Unlock(connection->lock);

    nsw_debug_write("<= recv", buf, available);

    return (PRInt32)available;
}

static PRInt32 PR_CALLBACK nsw_send(
    PRFileDesc* fd, const void* buf, PRInt32 amount, PRIntn flags,
    PRIntervalTime timeout)
{
    (void)flags;
    (void)timeout;

    PmsNssConnection* connection = nsw_get_connection(fd);

    if (!connection)
    {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return -1;
    }

    if (amount <= 0)
    {
        /* NSS never sends empty records, but tolerate zero-length sends. */
        return amount;
    }

    PR_Lock(connection->lock);

    if (!nsw_queue_reserve(&connection->write, (size_t)amount))
    {
        PR_Unlock(connection->lock);
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
        return -1;
    }

    memcpy(connection->write.data + connection->write.len, buf,
           (size_t)amount);
    connection->write.len += (size_t)amount;

    PR_Unlock(connection->lock);

    nsw_debug_write("=> send", buf, (size_t)amount);

    return amount;
}

static PRInt32 PR_CALLBACK nsw_read(
    PRFileDesc* fd, void* buf, PRInt32 amount)
{
    return nsw_recv(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

static PRInt32 PR_CALLBACK nsw_write(
    PRFileDesc* fd, const void* buf, PRInt32 amount)
{
    return nsw_send(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

static PRInt32 PR_CALLBACK nsw_available(PRFileDesc* fd)
{
    PmsNssConnection* connection = nsw_get_connection(fd);

    if (!connection)
        return 0;

    PR_Lock(connection->lock);
    PRInt32 result = (PRInt32)(connection->read.len - connection->read.pos);
    PR_Unlock(connection->lock);

    return result;
}

static PRInt64 PR_CALLBACK nsw_available64(PRFileDesc* fd)
{
    return (PRInt64)nsw_available(fd);
}

static PRStatus PR_CALLBACK nsw_close(PRFileDesc* fd)
{
    PmsNssConnection* connection = nsw_get_connection(fd);

    if (connection)
    {
        PR_DestroyLock(connection->lock);
        connection->lock = NULL;

        nsw_queue_free(&connection->read);
        nsw_queue_free(&connection->write);

        free(connection->hostname);
        connection->hostname = NULL;

        free(connection);
        fd->secret = NULL;
    }

    /* pl_FDDestructor frees the PRFileDesc stub itself. */
    fd->dtor(fd);
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK nsw_shutdown(PRFileDesc* fd, int how)
{
    (void)fd;
    (void)how;
    /* There is no transport below us. */
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK nsw_getpeername(PRFileDesc* fd, PRNetAddr* addr)
{
    (void)fd;

    if (!addr)
    {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return PR_FAILURE;
    }

    memset(addr, 0, sizeof(PRNetAddr));
    addr->inet.family = PR_AF_INET;
    addr->inet.port = 0;

    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK nsw_getsockname(PRFileDesc* fd, PRNetAddr* addr)
{
    return nsw_getpeername(fd, addr);
}

static PRStatus PR_CALLBACK nsw_getsocketoption(
    PRFileDesc* fd, PRSocketOptionData* data)
{
    (void)fd;

    if (!data)
    {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return PR_FAILURE;
    }

    /* The SSL layer probes the blocking mode of the stack through
     * ssl_FdIsBlocking() -> PR_GetSocketOption(). Reporting non-blocking
     * is what makes SSL_ForceHandshake() and PR_Recv() return
     * PR_WOULD_BLOCK_ERROR instead of hanging forever. */
    switch (data->option)
    {
        case PR_SockOpt_Nonblocking:
            data->value.non_blocking = PR_TRUE;
            return PR_SUCCESS;

        case PR_SockOpt_NoDelay:
            data->value.no_delay = PR_TRUE;
            return PR_SUCCESS;

        default:
            PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
            return PR_FAILURE;
    }
}

static PRStatus PR_CALLBACK nsw_setsocketoption(
    PRFileDesc* fd, const PRSocketOptionData* data)
{
    (void)fd;
    (void)data;

    /* Accept (and ignore) everything; NSS tries to disable the Nagle
     * delay before sending the close_notify alert. */
    return PR_SUCCESS;
}

static PRIOMethods g_nsw_methods;

static void nsw_init_methods(void)
{
    memset(&g_nsw_methods, 0, sizeof(g_nsw_methods));

    g_nsw_methods.file_type = PR_DESC_LAYERED;
    g_nsw_methods.close = nsw_close;
    g_nsw_methods.read = nsw_read;
    g_nsw_methods.write = nsw_write;
    g_nsw_methods.available = nsw_available;
    g_nsw_methods.available64 = nsw_available64;
    g_nsw_methods.shutdown = nsw_shutdown;
    g_nsw_methods.recv = nsw_recv;
    g_nsw_methods.send = nsw_send;
    g_nsw_methods.getsockname = nsw_getsockname;
    g_nsw_methods.getpeername = nsw_getpeername;
    g_nsw_methods.getsocketoption = nsw_getsocketoption;
    g_nsw_methods.setsocketoption = nsw_setsocketoption;
}

/* ------------------------------------------------------------------ */
/* Name tables                                                          */
/* ------------------------------------------------------------------ */

typedef struct NswCipherEntry
{
    const char* name;
    PRUint16 cipher;
} NswCipherEntry;

/* Maps OpenSSL-style cipher suite names (as used by the Firefox presets)
 * to IANA TLS cipher suite codes understood by NSS. */
static const NswCipherEntry g_cipher_map[] = {
    { "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02B },
    { "ECDHE-RSA-AES128-GCM-SHA256", 0xC02F },
    { "ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C },
    { "ECDHE-RSA-AES256-GCM-SHA384", 0xC030 },
    { "ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9 },
    { "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA8 },
    { "ECDHE-ECDSA-AES256-SHA", 0xC00A },
    { "ECDHE-RSA-AES128-SHA", 0xC013 },
    { "ECDHE-RSA-AES256-SHA", 0xC014 },
    { "AES128-GCM-SHA256", 0x009C },
    { "AES256-GCM-SHA384", 0x009D },
    { "AES128-SHA", 0x002F },
    { "AES256-SHA", 0x0035 },
    { "TLS_AES_128_GCM_SHA256", 0x1301 },
    { "TLS_AES_256_GCM_SHA384", 0x1302 },
    { "TLS_CHACHA20_POLY1305_SHA256", 0x1303 }
};

typedef struct NswSignatureEntry
{
    const char* name;
    SSLSignatureScheme scheme;
} NswSignatureEntry;

/* Maps BoringSSL-style signature algorithm names (as used by the Firefox
 * presets) to NSS SSLSignatureScheme values. Schemes not supported by
 * the linked NSS version (e.g. ML-DSA) are silently skipped. */
static const NswSignatureEntry g_signature_map[] = {
    { "RSA-PKCS1-SHA1", ssl_sig_rsa_pkcs1_sha1 },
    { "RSA-PKCS1-SHA256", ssl_sig_rsa_pkcs1_sha256 },
    { "RSA-PKCS1-SHA384", ssl_sig_rsa_pkcs1_sha384 },
    { "RSA-PKCS1-SHA512", ssl_sig_rsa_pkcs1_sha512 },
    { "ECDSA-SHA1", ssl_sig_ecdsa_sha1 },
    { "ECDSA-SECP256R1-SHA256", ssl_sig_ecdsa_secp256r1_sha256 },
    { "ECDSA-SECP384R1-SHA384", ssl_sig_ecdsa_secp384r1_sha384 },
    { "ECDSA-SECP521R1-SHA512", ssl_sig_ecdsa_secp521r1_sha512 },
    { "RSA-PSS-RSAE-SHA256", ssl_sig_rsa_pss_rsae_sha256 },
    { "RSA-PSS-RSAE-SHA384", ssl_sig_rsa_pss_rsae_sha384 },
    { "RSA-PSS-RSAE-SHA512", ssl_sig_rsa_pss_rsae_sha512 },
    { "ED25519", ssl_sig_ed25519 }
};

/* Extracts the next separator-separated, whitespace-trimmed token from
 * *cursor and copies it into |out|. Advances *cursor past the token.
 * Returns PR_FALSE when no more tokens are available. */
static PRBool nsw_next_token(
    const char** cursor, char separator, char* out, size_t outSize,
    size_t* outLen)
{
    const char* start = *cursor;
    const char* end;
    size_t length;

    if (!out || outSize == 0 || !outLen)
        return PR_FALSE;

    if (!start || !*start)
        return PR_FALSE;

    end = strchr(start, separator);
    length = end ? (size_t)(end - start) : strlen(start);

    while (length > 0 && (start[0] == ' ' || start[0] == '\t'))
    {
        ++start;
        --length;
    }

    while (length > 0 && (start[length - 1] == ' ' ||
                          start[length - 1] == '\t'))
    {
        --length;
    }

    if (end)
        *cursor = end + 1;
    else
        *cursor = start + length;

    if (length == 0 || length >= outSize)
        return PR_FALSE;

    memcpy(out, start, length);
    out[length] = '\0';
    *outLen = length;

    return PR_TRUE;
}

/* ------------------------------------------------------------------ */
/* Certificate hook: NSS-side validation is skipped; the managed layer  */
/* performs full X509Chain validation, like the BoringSSL wrapper.      */
/* ------------------------------------------------------------------ */

static SECStatus PR_CALLBACK nsw_auth_certificate_hook(
    void* arg, PRFileDesc* fd, PRBool checkSig, PRBool isServer)
{
    (void)arg;
    (void)fd;
    (void)checkSig;
    (void)isServer;

    return SECSuccess;
}

/* ------------------------------------------------------------------ */
/* RFC 8879 certificate compression (the compress_certificate xtn)      */
/*                                                                      */
/* Firefox advertises the certificate_compression extension with        */
/* zlib/brotli/zstd, in this order. zlib is statically linked from the  */
/* vendored sources NSS ships in nss/lib/zlib, brotli is statically     */
/* linked from the vendored sources in ../brotli (pass                  */
/* -DNSW_STATIC_BROTLI=OFF to CMake to resolve brotli at runtime        */
/* instead) and zstd is statically linked from the vendored sources in  */
/* ../zstd (pass -DNSW_STATIC_ZSTD=OFF the same way). Algorithms whose  */
/* codec is unavailable are simply not advertised. NSS sends the        */
/* registered algorithms in registration order, so the three codecs     */
/* are registered in the Firefox order zlib(1), brotli(2), zstd(3).     */
/*                                                                      */
/* The public SSLCertificateCompressionAlgorithm type was renamed       */
/* between NSS releases (SSLCertificateCompressionAlgorithmType in      */
/* 3.98 vs SSLCertificateCompressionAlgorithm later), so the wire-      */
/* compatible layout is mirrored here and the experimental API is       */
/* resolved by name via SSL_GetExperimentalAPI.                         */
/* ------------------------------------------------------------------ */
/* zlib callback pair for RFC 8879 certificate compression.             */
/* encode() receives an input SECItem and must allocate + fill the      */
/* output SECItem (NSS frees it with SECITEM_FreeItem); decode()        */
/* receives the output buffer and reports the bytes it produced.        */
/* ------------------------------------------------------------------ */

static SECStatus nsw_zlib_encode(const SECItem* input, SECItem* output)
{
    uLong bound;
    uLong encodedLen;
    PRUint8* data;

    if (!input || !input->data || !output)
    {
        return SECFailure;
    }

    bound = compressBound((uLong)input->len);
    data = (PRUint8*)PORT_Alloc((size_t)bound);
    if (!data)
    {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    encodedLen = bound;
    if (compress2(data, &encodedLen, input->data,
                  (uLong)input->len, Z_DEFAULT_COMPRESSION) != Z_OK)
    {
        PORT_Free(data);
        PORT_SetError(SEC_ERROR_IO);
        return SECFailure;
    }

    output->type = siBuffer;
    output->data = data;
    output->len = (unsigned int)encodedLen;
    return SECSuccess;
}

static SECStatus nsw_zlib_decode(
    const SECItem* input, unsigned char* output, size_t outputLen,
    size_t* usedLen)
{
    uLongf decodedLen;

    if (!input || !input->data || !output || !usedLen || outputLen == 0)
    {
        return SECFailure;
    }

    decodedLen = (uLongf)outputLen;
    if (uncompress(output, &decodedLen, input->data,
                   (uLong)input->len) != Z_OK)
    {
        return SECFailure;
    }

    *usedLen = (size_t)decodedLen;
    return SECSuccess;
}

typedef struct NswCertCompressionAlgorithmStr
{
    PRUint16 id;
    const char* name;
    SECStatus (*encode)(const SECItem* input, SECItem* output);
    SECStatus (*decode)(
        const SECItem* input, unsigned char* output, size_t outputLen,
        size_t* usedLen);
} NswCertCompressionAlgorithm;

/* ------------------------------------------------------------------ */
/* brotli codec (RFC 8879 algorithm id 2).                               */
/* Statically linked from the vendored ../brotli sources by default      */
/* (NSW_BROTLI_STATIC); with -DNSW_STATIC_BROTLI=OFF the entry points    */
/* are resolved at runtime via PR_LoadLibrary instead.                   */
/* ------------------------------------------------------------------ */

#define NSW_BROTLI_DEFAULT_QUALITY       11
#define NSW_BROTLI_DEFAULT_WINDOW        22
#define NSW_BROTLI_MODE_GENERIC          0
#define NSW_BROTLI_DECODER_RESULT_SUCCESS 1

#ifdef NSW_BROTLI_STATIC

#include <brotli/decode.h>
#include <brotli/encode.h>

/* The real public headers provide the prototypes, so the actual entry
 * points are wired up at compile time (const pointers, never NULL). */
static BROTLI_BOOL (*const nsw_brotli_compress)(
    int quality, int lgwin, BrotliEncoderMode mode,
    size_t inputSize, const uint8_t* input,
    size_t* encodedSize, uint8_t* encoded) = BrotliEncoderCompress;
static BrotliDecoderResult (*const nsw_brotli_decompress)(
    size_t encodedSize, const uint8_t* encoded,
    size_t* decodedSize, uint8_t* decoded) = BrotliDecoderDecompress;

#else /* !NSW_BROTLI_STATIC */

typedef size_t (*NswBrotliEncoderCompressFn)(
    int quality, int lgwin, int mode,
    size_t inputSize, const uint8_t* input,
    size_t* encodedSize, uint8_t* encoded);
typedef int (*NswBrotliDecoderDecompressFn)(
    size_t encodedSize, const uint8_t* encoded,
    size_t* decodedSize, uint8_t* decoded);

static NswBrotliEncoderCompressFn nsw_brotli_compress;
static NswBrotliDecoderDecompressFn nsw_brotli_decompress;

#endif /* NSW_BROTLI_STATIC */

static SECStatus nsw_brotli_encode(const SECItem* input, SECItem* output)
{
    size_t encodedLen;
    PRUint8* data;

    if (!input || !input->data || !output || !nsw_brotli_compress)
    {
        return SECFailure;
    }

    /* BrotliEncoderMaxCompressedSize() is a static inline in the public
     * header; use the same formula (input + input/2 + 1024) directly. */
    encodedLen = (size_t)input->len + (size_t)input->len / 2 + 1024;
    data = (PRUint8*)PORT_Alloc(encodedLen);
    if (!data)
    {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    if (!nsw_brotli_compress(
            NSW_BROTLI_DEFAULT_QUALITY, NSW_BROTLI_DEFAULT_WINDOW,
            NSW_BROTLI_MODE_GENERIC, (size_t)input->len, input->data,
            &encodedLen, data))
    {
        PORT_Free(data);
        PORT_SetError(SEC_ERROR_IO);
        return SECFailure;
    }

    output->type = siBuffer;
    output->data = data;
    output->len = (unsigned int)encodedLen;
    return SECSuccess;
}

static SECStatus nsw_brotli_decode(
    const SECItem* input, unsigned char* output, size_t outputLen,
    size_t* usedLen)
{
    size_t decodedLen;

    if (!input || !input->data || !output || !usedLen || outputLen == 0 ||
        !nsw_brotli_decompress)
    {
        return SECFailure;
    }

    decodedLen = outputLen;
    if (nsw_brotli_decompress(
            (size_t)input->len, input->data, &decodedLen, output) !=
        NSW_BROTLI_DECODER_RESULT_SUCCESS)
    {
        return SECFailure;
    }

    *usedLen = decodedLen;
    return SECSuccess;
}

/* ------------------------------------------------------------------ */
/* zstd codec (RFC 8879 algorithm id 3).                                 */
/* Statically linked from the vendored ../zstd sources by default        */
/* (NSW_ZSTD_STATIC); with -DNSW_STATIC_ZSTD=OFF the entry points        */
/* are resolved at runtime via PR_LoadLibrary instead.                   */
/* ------------------------------------------------------------------ */

#define NSW_ZSTD_DEFAULT_CLEVEL 3

typedef size_t (*NswZstdCompressFn)(
    void* dst, size_t dstCap, const void* src, size_t srcSize, int level);
typedef size_t (*NswZstdDecompressFn)(
    void* dst, size_t dstCap, const void* src, size_t srcSize);
typedef unsigned (*NswZstdIsErrorFn)(size_t code);

#ifdef NSW_ZSTD_STATIC

#include <zstd.h>

/* The real public header provides the prototypes, so the actual entry
 * points are wired up at compile time (const pointers, never NULL). */
static const NswZstdCompressFn nsw_zstd_compress = ZSTD_compress;
static const NswZstdDecompressFn nsw_zstd_decompress = ZSTD_decompress;
static const NswZstdIsErrorFn nsw_zstd_is_error = ZSTD_isError;

#else /* !NSW_ZSTD_STATIC */

static NswZstdCompressFn nsw_zstd_compress;
static NswZstdDecompressFn nsw_zstd_decompress;
static NswZstdIsErrorFn nsw_zstd_is_error;

#endif /* NSW_ZSTD_STATIC */

static SECStatus nsw_zstd_encode(const SECItem* input, SECItem* output)
{
    size_t encodedLen;
    PRUint8* data;

    if (!input || !input->data || !output || !nsw_zstd_compress ||
        !nsw_zstd_is_error)
    {
        return SECFailure;
    }

    /* ZSTD_COMPRESSBOUND(input) = input + input/8 + 128 (plus a small
     * safety margin, the formula is a static inline in zstd.h). */
    encodedLen = (size_t)input->len + (size_t)input->len / 8 + 512;
    data = (PRUint8*)PORT_Alloc(encodedLen);
    if (!data)
    {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    encodedLen = nsw_zstd_compress(
        data, encodedLen, input->data, (size_t)input->len,
        NSW_ZSTD_DEFAULT_CLEVEL);
    if (nsw_zstd_is_error(encodedLen))
    {
        PORT_Free(data);
        PORT_SetError(SEC_ERROR_IO);
        return SECFailure;
    }

    output->type = siBuffer;
    output->data = data;
    output->len = (unsigned int)encodedLen;
    return SECSuccess;
}

static SECStatus nsw_zstd_decode(
    const SECItem* input, unsigned char* output, size_t outputLen,
    size_t* usedLen)
{
    size_t decodedLen;

    if (!input || !input->data || !output || !usedLen || outputLen == 0 ||
        !nsw_zstd_decompress || !nsw_zstd_is_error)
    {
        return SECFailure;
    }

    decodedLen = nsw_zstd_decompress(
        output, outputLen, input->data, (size_t)input->len);
    if (nsw_zstd_is_error(decodedLen))
    {
        return SECFailure;
    }

    *usedLen = decodedLen;
    return SECSuccess;
}

/* ------------------------------------------------------------------ */
/* One-time codec loading (thread-safe via PR_CallOnce).                */
/* ------------------------------------------------------------------ */

static PRBool nsw_brotli_loaded = PR_FALSE;
static PRBool nsw_zstd_loaded = PR_FALSE;

#if !defined(NSW_BROTLI_STATIC) || !defined(NSW_ZSTD_STATIC)
static PRBool nsw_load_codec_symbol(
    const char* libraryName, const char* symbol, void** fn)
{
    PRLibrary* library = PR_LoadLibrary(libraryName);
    if (!library)
    {
        return PR_FALSE;
    }

    *fn = (void*)PR_FindFunctionSymbol(library, symbol);
    return *fn != NULL;
}
#endif

static PRStatus nsw_load_compression_codecs(void)
{
#ifdef NSW_BROTLI_STATIC
    /* brotli is statically linked and wired up at compile time; the
     * encoder/decoder entry points are always available. */
    nsw_brotli_loaded = PR_TRUE;
#else /* !NSW_BROTLI_STATIC */
#ifdef _WIN32
    static const char brotliEncLib[] = "brotlienc.dll";
    static const char brotliDecLib[] = "brotlidec.dll";
#else
    static const char brotliEncLib[] = "libbrotlienc.so.1";
    static const char brotliDecLib[] = "libbrotlidec.so.1";
#endif

    if (nsw_load_codec_symbol(
            brotliEncLib, "BrotliEncoderCompress",
            (void**)&nsw_brotli_compress) &&
        nsw_load_codec_symbol(
            brotliDecLib, "BrotliDecoderDecompress",
            (void**)&nsw_brotli_decompress))
    {
        nsw_brotli_loaded = PR_TRUE;
    }
#endif /* NSW_BROTLI_STATIC */

#ifdef NSW_ZSTD_STATIC
    /* zstd is statically linked and wired up at compile time; the
     * codec entry points are always available. */
    nsw_zstd_loaded = PR_TRUE;
#else /* !NSW_ZSTD_STATIC */
#ifdef _WIN32
    static const char zstdLib[] = "libzstd.dll";
#else
    static const char zstdLib[] = "libzstd.so.1";
#endif

    if (nsw_load_codec_symbol(
            zstdLib, "ZSTD_compress", (void**)&nsw_zstd_compress) &&
        nsw_load_codec_symbol(
            zstdLib, "ZSTD_decompress", (void**)&nsw_zstd_decompress) &&
        nsw_load_codec_symbol(
            zstdLib, "ZSTD_isError", (void**)&nsw_zstd_is_error))
    {
        nsw_zstd_loaded = PR_TRUE;
    }
#endif /* NSW_ZSTD_STATIC */

    return PR_SUCCESS;
}

static PRCallOnceType nsw_codec_load_once;

/* Registers the certificate compression algorithms in the Firefox order
 * zlib(1), brotli(2), zstd(3). Returns PR_TRUE when at least the zlib
 * algorithm was registered (older NSS versions without the experimental
 * API support no registration at all, in which case the
 * compress_certificate extension is simply not sent). */
static PRBool nsw_enable_cert_compression(PRFileDesc* fd)
{
    static const NswCertCompressionAlgorithm zlibAlg = {
        1,               /* zlib */
        "zlib",
        nsw_zlib_encode,
        nsw_zlib_decode
    };
    static const NswCertCompressionAlgorithm brotliAlg = {
        2,               /* brotli */
        "brotli",
        nsw_brotli_encode,
        nsw_brotli_decode
    };
    static const NswCertCompressionAlgorithm zstdAlg = {
        3,               /* zstd */
        "zstd",
        nsw_zstd_encode,
        nsw_zstd_decode
    };

    typedef SECStatus (*SetCertCompressionFn)(
        PRFileDesc*, NswCertCompressionAlgorithm);

    void* api = SSL_GetExperimentalAPI(
        "SSL_SetCertificateCompressionAlgorithm");
    if (!api)
    {
        return PR_FALSE;
    }

    PR_CallOnce(&nsw_codec_load_once, nsw_load_compression_codecs);

    SetCertCompressionFn setAlg = (SetCertCompressionFn)api;

    PRBool ok = setAlg(fd, zlibAlg) == SECSuccess;
    if (nsw_brotli_loaded)
    {
        ok = setAlg(fd, brotliAlg) == SECSuccess && ok;
    }
    if (nsw_zstd_loaded)
    {
        ok = setAlg(fd, zstdAlg) == SECSuccess && ok;
    }
    return ok;
}

/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Exported API (identical to the BoringSSL wrapper)                    */
/* ------------------------------------------------------------------ */

PMS_EXPORT void* PMS_CALL pms_ssl_create(
    const char* hostname,
    const char* cipher_list,
    int enable_grease,
    int enable_ech_grease,
    const char* alpn_protos,
    const char* alps_protos,
    const char* trust_anchors,
    const char* sig_algs,
    int enable_signed_cert_timestamps,
    int set_ocsp_status_type,
    int enable_brotli)
{
    (void)alps_protos;         /* NSS has no ALPS support */
    (void)trust_anchors;       /* BoringSSL-specific extension */

    if (!hostname || !hostname[0])
    {
        SetLastError("Hostname is empty");
        return NULL;
    }

    if (PR_CallOnce(&g_nss_init_once, nsw_init_nss) != PR_SUCCESS)
        return NULL; /* g_last_error already set */

    nsw_debug_init();

    if (PR_CallOnce(&g_layer_init_once, nsw_init_layer_identity) != PR_SUCCESS ||
        g_nsw_methods.close == NULL)
    {
        nsw_init_methods();
    }

    PmsNssConnection* connection =
        (PmsNssConnection*)calloc(1, sizeof(PmsNssConnection));

    if (!connection)
    {
        SetLastError("Out of memory");
        return NULL;
    }

    connection->lock = PR_NewLock();

    if (!connection->lock)
    {
        SetLastError("PR_NewLock failed");
        free(connection);
        return NULL;
    }

    connection->hostname = strdup(hostname);

    if (!connection->hostname)
    {
        PR_DestroyLock(connection->lock);
        SetLastError("Out of memory");
        free(connection);
        return NULL;
    }

    PRFileDesc* stub = PR_CreateIOLayerStub(g_nsw_identity, &g_nsw_methods);

    if (!stub)
    {
        SetLastErrorF("PR_CreateIOLayerStub failed", PR_GetError());
        PR_DestroyLock(connection->lock);
        free(connection->hostname);
        free(connection);
        return NULL;
    }

    stub->secret = (PRFilePrivate*)connection;

    /* After PR_PushIOLayer (inside SSL_ImportFD) the PRFileDesc structs
     * swap contents: `stub` now refers to the SSL layer, and the original
     * queue layer lives at fd->lower. */
    PRFileDesc* fd = SSL_ImportFD(NULL, stub);

    if (!fd)
    {
        SetLastErrorF("SSL_ImportFD failed", PR_GetError());
        stub->dtor(stub);
        PR_DestroyLock(connection->lock);
        free(connection->hostname);
        free(connection);
        return NULL;
    }

    connection->fd = fd;
    connection->bottom = fd->lower;

    /* TLS 1.2 and TLS 1.3 only, like the BoringSSL wrapper. */
    SSLVersionRange versionRange = {
        SSL_LIBRARY_VERSION_TLS_1_2,
        SSL_LIBRARY_VERSION_TLS_1_3
    };

    if (SSL_VersionRangeSet(fd, &versionRange) != SECSuccess)
    {
        SetLastErrorF("SSL_VersionRangeSet failed", PR_GetError());
        PR_Close(fd);
        return NULL;
    }

    /* Firefox offers exactly these groups, in this order (X25519MLKEM768,
     * x25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072); every other
     * implemented group is disabled. Older NSS builds without ML-KEM
     * reject the hybrid group, so retry without it. */
    {
        static const SSLNamedGroup firefoxGroups[] = {
            (SSLNamedGroup)4588,          /* X25519MLKEM768 */
            ssl_grp_ec_curve25519,
            ssl_grp_ec_secp256r1,
            ssl_grp_ec_secp384r1,
            ssl_grp_ec_secp521r1,
            ssl_grp_ffdhe_2048,
            ssl_grp_ffdhe_3072
        };
        unsigned groupCount =
            (unsigned)(sizeof(firefoxGroups) / sizeof(firefoxGroups[0]));

        SECStatus rv = SSL_NamedGroupConfig(fd, firefoxGroups, groupCount);
        if (rv != SECSuccess)
        {
            rv = SSL_NamedGroupConfig(fd, firefoxGroups + 1, groupCount - 1);
        }
        if (rv != SECSuccess)
        {
            SetLastErrorF("SSL_NamedGroupConfig failed", PR_GetError());
            PR_Close(fd);
            return NULL;
        }
    }

    /* Firefox sends key shares for the first three named groups
     * (X25519MLKEM768, x25519 and P-256), which lets most servers
     * complete the handshake without a HelloRetryRequest. NSS sends a
     * share for one group only by default, which triggers an HRR and a
     * second ClientHello - match Firefox here. */
    if (SSL_SendAdditionalKeyShares(fd, 2) != SECSuccess)
    {
        SetLastErrorF("SSL_SendAdditionalKeyShares failed", PR_GetError());
        PR_Close(fd);
        return NULL;
    }

    /* Managed validation. */
    if (SSL_AuthCertificateHook(fd, nsw_auth_certificate_hook, NULL) !=
        SECSuccess)
    {
        SetLastErrorF("SSL_AuthCertificateHook failed", PR_GetError());
        PR_Close(fd);
        return NULL;
    }

    if (cipher_list && cipher_list[0])
    {
        PRUint16 requested[64];
        unsigned requestedCount = 0;
        const char* cursor = cipher_list;
        char token[128];
        size_t tokenLen;
        PRBool unknown = PR_FALSE;

        while (nsw_next_token(&cursor, ':', token, sizeof(token), &tokenLen) &&
               requestedCount < sizeof(requested) / sizeof(requested[0]))
        {
            size_t matched = 0;

            for (size_t i = 0; i < sizeof(g_cipher_map) / sizeof(g_cipher_map[0]);
                 ++i)
            {
                if (strcmp(token, g_cipher_map[i].name) == 0)
                {
                    requested[requestedCount++] = g_cipher_map[i].cipher;
                    ++matched;
                    break;
                }
            }

            /* Accept raw IANA hex codes (0xNNNN) as well. */
            if (matched == 0 && tokenLen > 2 && token[0] == '0' &&
                (token[1] == 'x' || token[1] == 'X'))
            {
                unsigned value = (unsigned)strtoul(token, NULL, 16);

                if (value > 0 && value <= 0xFFFF)
                {
                    requested[requestedCount++] = (PRUint16)value;
                    ++matched;
                }
            }

            if (matched == 0)
                unknown = PR_TRUE;
        }

        if (requestedCount == 0)
        {
            SetLastError("SSL cipher list did not contain any "
                         "cipher suite supported by NSS");
            PR_Close(fd);
            return NULL;
        }

        /* Disable every implemented cipher that was not requested.
         * TLS 1.3 cipher suites (0x13xx) are always left enabled: they
         * are negotiated independently of the cipher list in BoringSSL,
         * and disabling them would rule out TLS 1.3 entirely. */
        const PRUint16* implemented = SSL_GetImplementedCiphers();
        PRUint16 count = SSL_GetNumImplementedCiphers();

        for (PRUint16 i = 0; i < count; ++i)
        {
            PRUint16 cipher = implemented[i];
            PRBool enable = PR_FALSE;

            if (cipher >= 0x1300 && cipher <= 0x13FF)
                continue;

            for (unsigned j = 0; j < requestedCount; ++j)
            {
                if (requested[j] == cipher)
                {
                    enable = PR_TRUE;
                    break;
                }
            }

            if (SSL_CipherPrefSet(fd, cipher, enable) != SECSuccess)
            {
                SetLastErrorF("SSL_CipherPrefSet failed", PR_GetError());
                PR_Close(fd);
                return NULL;
            }
        }

        /* Firefox sends the enabled suites in its own order, which for
         * some suites differs from the fixed order of NSS's
         * SSL_ImplementedCiphers list (sslenum.c): Firefox offers
         * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xC00A) before
         * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013), while NSS's
         * default order does not. SSL_CipherPrefSet only enables or
         * disables suites; the experimental SSL_CipherSuiteOrderSet API
         * (NSS 3.87+) restores the order given in the cipher list.
         * TLS 1.3 suites are not part of the cipher list (like in the
         * BoringSSL wrapper, they are negotiated independently), so they
         * keep their default position in front. */
        typedef SECStatus (*NswCipherSuiteOrderSetFn)(
            PRFileDesc*, const PRUint16*, PRUint16);

        void* orderApi = SSL_GetExperimentalAPI(
            "SSL_CipherSuiteOrderSet");
        if (orderApi)
        {
            PRUint16 order[128];
            unsigned orderCount = 0;
            const PRUint16* implemented = SSL_GetImplementedCiphers();
            PRUint16 implCount = SSL_GetNumImplementedCiphers();
            unsigned maxOrder = sizeof(order) / sizeof(order[0]);

            /* TLS 1.3 suites first, in the NSS default order. */
            for (PRUint16 i = 0; i < implCount && orderCount < maxOrder; ++i)
            {
                if (implemented[i] >= 0x1300 && implemented[i] <= 0x13FF)
                    order[orderCount++] = implemented[i];
            }

            /* Then the cipher-list suites in cipher-list order (skip
             * duplicates of the TLS 1.3 codes added above). */
            for (unsigned j = 0; j < requestedCount && orderCount < maxOrder; ++j)
            {
                PRBool seen = PR_FALSE;

                for (unsigned k = 0; k < orderCount; ++k)
                {
                    if (order[k] == requested[j])
                    {
                        seen = PR_TRUE;
                        break;
                    }
                }

                if (!seen)
                    order[orderCount++] = requested[j];
            }

            if (((NswCipherSuiteOrderSetFn)orderApi)(
                    fd, order, (PRUint16)orderCount) != SECSuccess)
            {
                SetLastErrorF("SSL_CipherSuiteOrderSet failed", PR_GetError());
                PR_Close(fd);
                return NULL;
            }
        }

        (void)unknown;
    }

    if (enable_grease)
    {
        SSL_OptionSet(fd, SSL_ENABLE_GREASE, PR_TRUE);
        SSL_OptionSet(fd, SSL_ENABLE_CH_EXTENSION_PERMUTATION, PR_TRUE);
    }

    if (enable_ech_grease)
    {
        /* Firefox appends the GREASE encrypted_client_hello extension
         * (0xFE0D) to every ClientHello. Available via the experimental
         * API since NSS 3.68; ignored when the linked NSS is older. */
        if (SSL_EnableTls13GreaseEch(fd, PR_TRUE) != SECSuccess)
        {
            SetLastError("SSL_EnableTls13GreaseEch is not available");
        }
        /* Firefox pads the GREASE ECH extension so it is 281 bytes long,
         * which also keeps the ClientHello past the 512-byte boundary
         * above which NSS stops adding the padding extension. */
        SSL_SetTls13GreaseEchSize(fd, 223);
    }

    /* ALPN: convert "h2:http/1.1" into the 8-bit length-prefixed wire
     * format expected by SSL_SetNextProtoNego. */
    if (alpn_protos && alpn_protos[0])
    {
        uint8_t wire[2048];
        size_t wireLen = 0;
        const char* cursor = alpn_protos;
        char token[128];
        size_t tokenLen;

        while (nsw_next_token(&cursor, ':', token, sizeof(token), &tokenLen))
        {
            wire[wireLen++] = (uint8_t)tokenLen;
            memcpy(wire + wireLen, token, tokenLen);
            wireLen += tokenLen;
        }

        if (wireLen > 0)
        {
            /* NSS stores the list for NPN, where the *fallback* protocol
             * must come first, and therefore moves the first entry to the
             * end of the advertised ALPN list. Feed the protocols in
             * reverse order so the advertised ALPN list matches the
             * preference order given by the caller. */
            size_t entryOffset[256];
            size_t entryCount = 0;
            size_t offset = 0;
            uint8_t reversed[2048];
            size_t reversedLen = 0;

            while (offset < wireLen &&
                   entryCount < sizeof(entryOffset) / sizeof(entryOffset[0]))
            {
                entryOffset[entryCount++] = offset;
                offset += (size_t)wire[offset] + 1;
            }

            if (offset == wireLen)
            {
                for (size_t i = entryCount; i > 0; --i)
                {
                    size_t off = entryOffset[i - 1];
                    size_t len = (size_t)wire[off] + 1;

                    memcpy(reversed + reversedLen, wire + off, len);
                    reversedLen += len;
                }

                if (SSL_SetNextProtoNego(
                        fd, reversed, (unsigned int)reversedLen) != SECSuccess)
                {
                    SetLastErrorF("SSL_SetNextProtoNego failed", PR_GetError());
                    PR_Close(fd);
                    return NULL;
                }
            }
        }
    }

    if (sig_algs && sig_algs[0])
    {
        SSLSignatureScheme schemes[64];
        unsigned count = 0;
        const char* cursor = sig_algs;
        char token[64];
        size_t tokenLen;

        while (nsw_next_token(&cursor, ':', token, sizeof(token), &tokenLen) &&
               count < sizeof(schemes) / sizeof(schemes[0]))
        {
            for (size_t i = 0;
                 i < sizeof(g_signature_map) / sizeof(g_signature_map[0]);
                 ++i)
            {
                if (strcmp(token, g_signature_map[i].name) == 0)
                {
                    schemes[count++] = g_signature_map[i].scheme;
                    break;
                }
            }
        }

        if (count > 0 &&
            SSL_SignatureSchemePrefSet(fd, schemes, count) != SECSuccess)
        {
            SetLastErrorF("SSL_SignatureSchemePrefSet failed", PR_GetError());
            PR_Close(fd);
            return NULL;
        }
    }

    if (enable_signed_cert_timestamps)
    {
        SSL_OptionSet(fd, SSL_ENABLE_SIGNED_CERT_TIMESTAMPS, PR_TRUE);
    }

    if (set_ocsp_status_type)
    {
        SSL_OptionSet(fd, SSL_ENABLE_OCSP_STAPLING, PR_TRUE);
    }

    /* Firefox sends the session_ticket extension in every ClientHello;
     * NSS disables session tickets by default. */
    SSL_OptionSet(fd, SSL_ENABLE_SESSION_TICKETS, PR_TRUE);

    /* Firefox sends the delegated_credentials extension in every
     * ClientHello; NSS disables delegated credentials by default. */
    SSL_OptionSet(fd, SSL_ENABLE_DELEGATED_CREDENTIALS, PR_TRUE);

    /* enable_brotli maps to the RFC 8879 certificate_compression
     * extension (see the note at nsw_enable_cert_compression). */
    if (enable_brotli)
    {
        nsw_enable_cert_compression(fd);
    }

    /* SNI and the session cache key. */
    if (SSL_SetURL(fd, connection->hostname) != SECSuccess)
    {
        SetLastErrorF("SSL_SetURL failed", PR_GetError());
        PR_Close(fd);
        return NULL;
    }

    SSL_SetSockPeerID(fd, connection->hostname);

    if (SSL_ResetHandshake(fd, PR_FALSE) != SECSuccess)
    {
        SetLastErrorF("SSL_ResetHandshake failed", PR_GetError());
        PR_Close(fd);
        return NULL;
    }

    return connection;
}

PMS_EXPORT int PMS_CALL pms_ssl_connect(void* connection_ptr)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    SECStatus rv = SSL_ForceHandshake(connection->fd);

    if (rv == SECSuccess)
        return PMS_SSL_OK;

    PRErrorCode error = PR_GetError();

    if (error == PR_WOULD_BLOCK_ERROR)
        return PMS_SSL_WANT_READ;

    if (error == PR_END_OF_FILE_ERROR)
        return PMS_SSL_ZERO_RETURN;

    SetLastErrorF("SSL_ForceHandshake failed", error);
    return PMS_SSL_ERROR;
}

PMS_EXPORT int PMS_CALL pms_ssl_feed_read(
    void* connection_ptr, const uint8_t* buffer, int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    if (length == 0)
        return 0;

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    PR_Lock(connection->lock);

    if (!nsw_queue_reserve(&connection->read, (size_t)length))
    {
        PR_Unlock(connection->lock);
        SetLastError("Out of memory");
        return PMS_SSL_ERROR;
    }

    /* NSS always consumes the queue fully before returning
     * PR_WOULD_BLOCK_ERROR, so the queue must be empty here; still,
     * append after any residual bytes to be safe. */
    if (connection->read.pos != 0 && connection->read.pos < connection->read.len)
    {
        memmove(connection->read.data,
                connection->read.data + connection->read.pos,
                connection->read.len - connection->read.pos);
        connection->read.len -= connection->read.pos;
    }

    connection->read.pos = 0;
    memcpy(connection->read.data + connection->read.len, buffer,
           (size_t)length);
    connection->read.len += (size_t)length;

    PR_Unlock(connection->lock);

    return length;
}

PMS_EXPORT int PMS_CALL pms_ssl_take_write(
    void* connection_ptr, uint8_t* buffer, int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    if (length == 0)
        return 0;

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    PR_Lock(connection->lock);

    size_t pending = connection->write.len;

    if (pending == 0)
    {
        PR_Unlock(connection->lock);
        return 0;
    }

    size_t taken = pending < (size_t)length ? pending : (size_t)length;

    memcpy(buffer, connection->write.data, taken);
    connection->write.len -= taken;

    if (connection->write.len > 0)
        memmove(connection->write.data, connection->write.data + taken,
                connection->write.len);

    PR_Unlock(connection->lock);

    return (int)taken;
}

PMS_EXPORT int PMS_CALL pms_ssl_pending_write(void* connection_ptr)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    PR_Lock(connection->lock);
    int pending = (int)connection->write.len;
    PR_Unlock(connection->lock);

    return pending;
}

PMS_EXPORT int PMS_CALL pms_ssl_read(
    void* connection_ptr, uint8_t* buffer, int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    int result = (int)PR_Recv(
        connection->fd, buffer, length, 0, PR_INTERVAL_NO_TIMEOUT);

    if (result > 0)
        return result;

    if (result == 0)
        return PMS_SSL_ZERO_RETURN;

    PRErrorCode error = PR_GetError();

    if (error == PR_WOULD_BLOCK_ERROR)
        return PMS_SSL_WANT_READ;

    if (error == PR_END_OF_FILE_ERROR)
        return PMS_SSL_ZERO_RETURN;

    SetLastErrorF("PR_Recv failed", error);
    return PMS_SSL_ERROR;
}

PMS_EXPORT int PMS_CALL pms_ssl_write(
    void* connection_ptr, const uint8_t* buffer, int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    int result = (int)PR_Send(
        connection->fd, buffer, length, 0, PR_INTERVAL_NO_TIMEOUT);

    if (result > 0)
        return result;

    if (result == 0)
        return PMS_SSL_ZERO_RETURN;

    PRErrorCode error = PR_GetError();

    if (error == PR_WOULD_BLOCK_ERROR)
        return PMS_SSL_WANT_WRITE;

    SetLastErrorF("PR_Send failed", error);
    return PMS_SSL_ERROR;
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_protocol_version(void* connection_ptr)
{
    static NSW_THREAD_LOCAL char version[16];

    if (!connection_ptr)
        return "";

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    SSLChannelInfo info;
    memset(&info, 0, sizeof(info));

    if (SSL_GetChannelInfo(connection->fd, &info, sizeof(info)) != SECSuccess)
        return "";

    switch (info.protocolVersion)
    {
        case SSL_LIBRARY_VERSION_TLS_1_2:
            return "TLS 1.2";
        case SSL_LIBRARY_VERSION_TLS_1_3:
            return "TLS 1.3";
        default:
            snprintf(version, sizeof(version), "TLS 0x%04x",
                     info.protocolVersion);
            return version;
    }
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_cipher_name(void* connection_ptr)
{
    static NSW_THREAD_LOCAL char cipherName[128];

    if (!connection_ptr)
        return "";

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    SSLChannelInfo info;
    memset(&info, 0, sizeof(info));

    if (SSL_GetChannelInfo(connection->fd, &info, sizeof(info)) != SECSuccess)
        return "";

    SSLCipherSuiteInfo suite;
    memset(&suite, 0, sizeof(suite));

    if (SSL_GetCipherSuiteInfo(info.cipherSuite, &suite, sizeof(suite)) !=
        SECSuccess)
    {
        return "";
    }

    snprintf(cipherName, sizeof(cipherName), "%s", suite.cipherSuiteName);

    return cipherName;
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_alpn_selected(void* connection_ptr)
{
    static NSW_THREAD_LOCAL char alpn[NSW_MAX_ALPN_PROTO + 1];

    if (!connection_ptr)
        return "";

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    SSLNextProtoState state = SSL_NEXT_PROTO_NO_SUPPORT;
    unsigned int length = 0;

    if (SSL_GetNextProto(
            connection->fd, &state, (unsigned char*)alpn, &length,
            NSW_MAX_ALPN_PROTO) != SECSuccess)
    {
        return "";
    }

    if ((state != SSL_NEXT_PROTO_NEGOTIATED &&
         state != SSL_NEXT_PROTO_SELECTED) ||
        length == 0)
    {
        return "";
    }

    alpn[length] = '\0';
    return alpn;
}

PMS_EXPORT const char* PMS_CALL pms_ssl_get_last_error()
{
    return g_last_error;
}

PMS_EXPORT void PMS_CALL pms_ssl_free(void* connection_ptr)
{
    if (!connection_ptr)
        return;

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    /* PR_Close -> ssl_Close: sends close_notify, pops the SSL layer and
     * calls nsw_close() on the queue layer, which frees the connection
     * and all its buffers. */
    PR_Close(connection->fd);
}

PMS_EXPORT int PMS_CALL pms_ssl_get_peer_certificate(
    void* connection_ptr, uint8_t* buffer, int max_length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    PmsNssConnection* connection = (PmsNssConnection*)connection_ptr;

    CERTCertificate* cert = SSL_PeerCertificate(connection->fd);

    if (!cert)
    {
        SetLastError("No peer certificate found");
        return 0;
    }

    SECItem* der = &cert->derCert;
    int certLen = der->len > 0x7FFFFFFF ? 0x7FFFFFFF : (int)der->len;

    if (!buffer)
    {
        CERT_DestroyCertificate(cert);
        return certLen;
    }

    if (max_length < certLen)
    {
        SetLastError("Buffer is too small for certificate");
        CERT_DestroyCertificate(cert);
        return PMS_SSL_ERROR;
    }

    memcpy(buffer, der->data, (size_t)certLen);

    CERT_DestroyCertificate(cert);
    return certLen;
}
