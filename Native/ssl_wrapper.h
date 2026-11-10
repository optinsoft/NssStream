#pragma once

#include <stdint.h>

#ifdef _WIN32
#define PMS_EXPORT __declspec(dllexport)
#define PMS_CALL __cdecl
#else
#define PMS_EXPORT
#define PMS_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PMS_SSL_OK           1
#define PMS_SSL_ZERO_RETURN  0
#define PMS_SSL_ERROR       -1
#define PMS_SSL_WANT_READ   -2
#define PMS_SSL_WANT_WRITE  -3

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
    int enable_brotli);

PMS_EXPORT int PMS_CALL pms_ssl_connect(
    void* connection);

PMS_EXPORT int PMS_CALL pms_ssl_feed_read(
    void* connection,
    const uint8_t* buffer,
    int length);

PMS_EXPORT int PMS_CALL pms_ssl_take_write(
    void* connection,
    uint8_t* buffer,
    int length);

PMS_EXPORT int PMS_CALL pms_ssl_pending_write(
    void* connection);

PMS_EXPORT int PMS_CALL pms_ssl_read(
    void* connection,
    uint8_t* buffer,
    int length);

PMS_EXPORT int PMS_CALL pms_ssl_write(
    void* connection,
    const uint8_t* buffer,
    int length);

PMS_EXPORT const char* PMS_CALL pms_ssl_get_protocol_version(
    void* connection);

PMS_EXPORT const char* PMS_CALL pms_ssl_get_cipher_name(
    void* connection);

PMS_EXPORT const char* PMS_CALL pms_ssl_get_alpn_selected(
    void* connection_ptr);

PMS_EXPORT const char* PMS_CALL pms_ssl_get_last_error();

PMS_EXPORT void PMS_CALL pms_ssl_free(
    void* connection);

PMS_EXPORT int PMS_CALL pms_ssl_get_peer_certificate(
    void* connection_ptr,
    uint8_t* buffer,
    int max_length);

#ifdef __cplusplus
}
#endif
