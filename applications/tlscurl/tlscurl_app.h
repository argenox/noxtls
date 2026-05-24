/**
* This file is part of the NoxTLS Library.
*
 * @file tlscurl_app.h
 * @brief Named limits and constants for the tlscurl HTTPS test utility.
 */
#ifndef TLSCURL_APP_H
#define TLSCURL_APP_H

/** Maximum host name length (including NUL). */
#define TLSCURL_HOST_MAX 256u
/** Maximum URL path length (including NUL). */
#define TLSCURL_PATH_MAX 512U
/** Default port for HTTPS when not specified in URL. */
#define TLSCURL_DEFAULT_HTTPS_PORT 443u
/** Buffer size for building the HTTP request line and headers. */
#define TLSCURL_REQUEST_BUILD_MAX 65536u
/** Application data read chunk size from TLS. */
#define TLSCURL_TLS_RECV_CHUNK 4096u
/** Maximum number of custom headers from repeated --header. */
#define TLSCURL_MAX_CUSTOM_HEADERS 48U
/** Maximum length of one header line (name: value). */
#define TLSCURL_HEADER_LINE_MAX 1024U
/** Maximum HTTP method length. */
#define TLSCURL_METHOD_MAX 16U
/** Maximum length of --data string (excluding NUL). */
#define TLSCURL_DATA_ARG_MAX 8192u
/** Port string buffer size for getaddrinfo. */
#define TLSCURL_PORT_STR_MAX 8U
/** Maximum bytes read from --data-file into memory. */
#define TLSCURL_MAX_BODY_FILE_BYTES (1024U * 1024U)
/** Maximum bytes read from --ca (PEM bundle or single cert) into memory. */
#define TLSCURL_CA_BUNDLE_READ_MAX (4U * 1024U * 1024U)
/** Length of SHA-256 digest bytes used for SPKI pinning. */
#define TLSCURL_PIN_SHA256_LEN 32U
/** Base64 output length for 32-byte SHA-256 digest (without NUL). */
#define TLSCURL_PIN_SHA256_B64_LEN 44U
/** Buffer size for base64 SHA-256 pin including terminating NUL. */
#define TLSCURL_PIN_SHA256_B64_BUF_LEN (TLSCURL_PIN_SHA256_B64_LEN + 1U)
/** Prefix accepted in pin values (e.g. sha256/<base64>). */
#define TLSCURL_PIN_SHA256_PREFIX "sha256/"
/** Prefix length for TLSCURL_PIN_SHA256_PREFIX. */
#define TLSCURL_PIN_SHA256_PREFIX_LEN 7U
/** DER tag values used for extracting SubjectPublicKeyInfo from certificate DER. */
#define TLSCURL_DER_TAG_INTEGER 0x02u
#define TLSCURL_DER_TAG_SEQUENCE 0x30u
#define TLSCURL_DER_TAG_CTX0_EXPLICIT 0xA0u

#endif /* TLSCURL_APP_H */
