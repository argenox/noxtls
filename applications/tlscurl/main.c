/*
* This file is part of the NoxTLS Library.
*
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif
/**
 * @file main.c
 * @brief HTTPS test client with curl-like request options and TLS diagnostics.
 * @defgroup noxtls_app_tlscurl tlscurl
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <errno.h>
#endif

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#define TLSCURL_SOCKERR() ((int)WSAGetLastError())
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define CLOSESOCK close
#define TLSCURL_SOCKERR() (errno)
#endif

#include "noxtls_common.h"
#include "noxtls_config.h"
#include "noxtls-lib/certs/certificates.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"
#include "utility/base64.h"

#include "tlscurl_app.h"

typedef struct {
    socket_t sock;
} tlscurl_conn_t;

typedef enum {
    TLS_MODE_1_2 = 0,
    TLS_MODE_1_3,
    TLS_MODE_AUTO
} tls_mode_t;

typedef enum {
    TLSCURL_ACTIVE_NONE = 0,
    TLSCURL_ACTIVE_TLS12,
    TLSCURL_ACTIVE_TLS13
} tlscurl_active_tls_t;

typedef struct {
    char line[TLSCURL_HEADER_LINE_MAX];
} tlscurl_header_entry_t;

typedef struct {
    tlscurl_header_entry_t entries[TLSCURL_MAX_CUSTOM_HEADERS];
    uint32_t count;
} tlscurl_headers_t;

typedef struct {
    const char *url;
    const char *ca_file;
    const char *crl_file;
    const char *pin_sha256;
    const char *method;
    const char *data_arg;
    const char *data_file;
    const char *output_path;
    const char *tlsdump_path;
    const char *keylog_path;
    tlscurl_headers_t headers;
    tls_mode_t tls_mode;
    uint8_t prefer_chacha;
    uint8_t strict_hostname;
    int verbose;
} tlscurl_config_t;

/**
 * @brief Return 1 if the last socket error is transient (retryable).
 * @param err Platform socket error code.
 * @return 1 for retryable conditions, 0 otherwise.
 */
static int tlscurl_sockerr_is_retryable(int err)
{
#ifdef _WIN32
    if(err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) {
        return 1;
    }
#else
    if(err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
        return 1;
    }
#endif
    return 0;
}

/**
 * @brief Print usage text for tlscurl.
 * @param prog Program name (argv[0]).
 */
static void tlscurl_print_usage(const char *prog)
{
    const char *p;

    p = (prog != NULL) ? prog : "tlscurl";
    printf("Usage: %s <https://host[:port]/path> [options]\n", p);
    printf("Options:\n");
    printf("  -h, --help                 Show this help\n");
    printf("  -v, --verbose              Verbose (repeat for more: -vv)\n");
    printf("  -X, --method <verb>        HTTP method (default GET)\n");
    printf("  -H, --header <line>        Add request header (Name: value). Repeatable.\n");
    printf("  -d, --data <string>        Request body (UTF-8/literal; small payloads)\n");
    printf("      --data-file <path>     Read body from file (max %u bytes)\n",
           (unsigned)TLSCURL_MAX_BODY_FILE_BYTES);
    printf("  -o, --output <path>        Write response body to file (- for stdout)\n");
    printf("      --ca <path>            Trust anchor PEM/DER (required unless localhost default)\n");
    printf("      --crl <path>           Optional CRL PEM/DER for revocation checks\n");
    printf("      --pin-sha256 <pin>     Expected SPKI SHA-256 pin (base64 or sha256/base64)\n");
    printf("      --tls12|--tls13|--auto TLS version selection (default tls12; auto tries 1.3 then 1.2)\n");
    printf("      --strict-hostname      Disable wildcard hostname matching (exact SAN/CN only)\n");
    printf("      --keylog <path>        NSS key log file (TLS 1.3; also SSLKEYLOGFILE)\n");
    printf("      --tlsdump <path>       Append TLS record hex dump (see noxtls_tls_set_record_dump_file)\n");
    printf("      --prefer-chacha        Prefer ChaCha20-Poly1305 for TLS 1.3 ClientHello\n");
}

/**
 * @brief Case-insensitive prefix check for header lines.
 * @param line Full header line.
 * @param prefix ASCII prefix (e.g. "host:").
 * @return 1 if line starts with prefix ignoring case, else 0.
 */
static int tlscurl_header_has_prefix_ci(const char *line, const char *prefix)
{
    size_t i;

    if(line == NULL || prefix == NULL) {
        return 0;
    }
    for(i = 0; prefix[i] != '\0'; i++) {
        char a;
        char b;

        a = line[i];
        b = prefix[i];
        if(a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if(b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if(a != b) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Return human-readable TLS state name.
 * @param st TLS state enum.
 * @return Static string name.
 */
static const char *tlscurl_tls_state_name(tls_state_t st)
{
    switch(st) {
    case TLS_STATE_INIT:
        return "INIT";
    case TLS_STATE_HANDSHAKING:
        return "HANDSHAKING";
    case TLS_STATE_CONNECTED:
        return "CONNECTED";
    case TLS_STATE_CLOSING:
        return "CLOSING";
    case TLS_STATE_CLOSED:
        return "CLOSED";
    case TLS_STATE_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Map common certificate return codes to a short label.
 * @param rc Return code from NoxTLS.
 * @return Static label or NULL if none.
 */
static const char *tlscurl_cert_rc_label(noxtls_return_t rc)
{
    if(rc == NOXTLS_RETURN_CERT_PARSE_FAILED) {
        return "CERT_PARSE_FAILED";
    }
    if(rc == NOXTLS_RETURN_CERT_VERIFY_FAILED) {
        return "CERT_VERIFY_FAILED";
    }
    if(rc == NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED) {
        return "CERT_VERIFY_SIGNATURE_FAILED";
    }
    if(rc == NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH) {
        return "CERT_VERIFY_HOSTNAME_MISMATCH";
    }
    if(rc == NOXTLS_RETURN_CERT_EXPIRED) {
        return "CERT_EXPIRED";
    }
    if(rc == NOXTLS_RETURN_CERT_NOT_YET_VALID) {
        return "CERT_NOT_YET_VALID";
    }
    if(rc == NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED) {
        return "CERT_VERIFY_CHAIN_FAILED";
    }
    if(rc == NOXTLS_RETURN_CERT_REVOKED) {
        return "CERT_REVOKED";
    }
    if(rc == NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS) {
        return "TLS_WEAK_DHE_PARAMS";
    }
    return NULL;
}

/**
 * @brief Print certificate failure details if the library populated them.
 * @param op Operation label for context.
 * @param rc Return code from the failed operation.
 */
static void tlscurl_print_cert_failure_details(const char *op, noxtls_return_t rc)
{
    noxtls_cert_verify_failure_info_t info;

    if(op == NULL) {
        return;
    }
    memset(&info, 0, sizeof(info));
    noxtls_cert_verify_failure_get(&info);
    if(info.populated == 0) {
        printf("[tlscurl] cert failure detail: not populated (op=%s rc=%d)\n", op, (int)rc);
        return;
    }
    printf("[tlscurl] cert failure detail (op=%s stored_rc=%d):\n", op, (int)info.return_code);
    if(info.subject_dn[0] != '\0') {
        printf("  subject_dn: %s\n", info.subject_dn);
    }
    if(info.expected_hostname[0] != '\0') {
        printf("  expected_hostname: %s\n", info.expected_hostname);
    }
    if(info.not_before[0] != '\0' || info.not_after[0] != '\0') {
        printf("  validity: not_before=%s not_after=%s\n", info.not_before, info.not_after);
    }
    printf("  cert_index: %u\n", (unsigned)info.cert_index);
}

/**
 * @brief Print a unified TLS error line with optional cert details.
 * @param phase Human-readable phase (e.g. handshake, send).
 * @param rc NoxTLS return code.
 */
static void tlscurl_print_tls_error(const char *phase, noxtls_return_t rc)
{
    const char *lab;

    lab = tlscurl_cert_rc_label(rc);
    if(lab != NULL) {
        printf("[tlscurl] TLS error phase=%s rc=%d (%s)\n", phase, (int)rc, lab);
        if(rc == NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS) {
            printf("[tlscurl] detail: server sent weak/unsupported finite-field DH parameters\n");
        } else {
            tlscurl_print_cert_failure_details(phase, rc);
        }
    } else {
        printf("[tlscurl] TLS error phase=%s rc=%d\n", phase, (int)rc);
    }
}

/**
 * @brief Print build-time TLS feature flags (subset).
 */
static void tlscurl_print_build_features(void)
{
    printf("[tlscurl] NoxTLS build flags (subset):\n");
    printf("  NOXTLS_FEATURE_TLS=%d TLS12=%d TLS13=%d DTLS=%d\n",
           NOXTLS_FEATURE_TLS, NOXTLS_FEATURE_TLS12, NOXTLS_FEATURE_TLS13, NOXTLS_FEATURE_DTLS);
    printf("  NOXTLS_FEATURE_CERT=%d ECC=%d X25519=%d CHACHA20_POLY1305=%d ML_KEM=%d ML_DSA=%d\n",
           NOXTLS_FEATURE_CERT, NOXTLS_FEATURE_ECC, NOXTLS_FEATURE_X25519,
           NOXTLS_FEATURE_CHACHA20_POLY1305, NOXTLS_FEATURE_ML_KEM, NOXTLS_FEATURE_ML_DSA);
}

/**
 * @brief Print host OS/compiler hints for test logs.
 */
static void tlscurl_print_platform(void)
{
    printf("[tlscurl] platform: ");
#ifdef _WIN32
    printf("Windows");
#ifdef _MSC_VER
    printf(" MSVC=%d", _MSC_VER);
#endif
#else
    printf("POSIX");
#endif
    printf("\n");
}

/**
 * @brief Read entire CA file into a NUL-terminated buffer (size capped).
 * @param ca_file Path to PEM/DER bundle or single certificate.
 * @param out_buf Receives malloc pointer; caller frees.
 * @param out_len Receives byte length excluding added NUL.
 * @return NOXTLS_RETURN_SUCCESS or error code.
 */
static noxtls_return_t tlscurl_read_ca_file_raw(const char *ca_file, uint8_t **out_buf, uint32_t *out_len)
{
    FILE *fp;
    long sz;
    uint8_t *buf;
    size_t rd;

    if(ca_file == NULL || out_buf == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *out_buf = NULL;
    *out_len = 0;
#ifdef _MSC_VER
    if(fopen_s(&fp, ca_file, "rb") != 0) {
        fp = NULL;
    }
#else
    fp = fopen(ca_file, "rb");
#endif
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    sz = ftell(fp);
    if(sz < 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    if((uint64_t)sz > (uint64_t)TLSCURL_CA_BUNDLE_READ_MAX) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    buf = (uint8_t *)malloc((size_t)sz + 1u);
    if(buf == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    rd = fread(buf, 1u, (size_t)sz, fp);
    fclose(fp);
    if(rd != (size_t)sz) {
        free(buf);
        return NOXTLS_RETURN_FAILED;
    }
    buf[sz] = 0;
    *out_buf = buf;
    *out_len = (uint32_t)sz;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Convert CRLF sequences to LF in place; shortens length and keeps a trailing NUL.
 * @param data Mutable PEM/DER buffer.
 * @param len_io In: byte length; out: new length after compaction.
 */
static void tlscurl_normalize_pem_crlf(uint8_t *data, uint32_t *len_io)
{
    uint32_t w;
    uint32_t r;
    uint32_t len;

    if(data == NULL || len_io == NULL) {
        return;
    }
    len = *len_io;
    w = 0u;
    r = 0u;
    while(r < len) {
        if(r + 1u < len && data[r] == (uint8_t)'\r' && data[r + 1u] == (uint8_t)'\n') {
            data[w] = (uint8_t)'\n';
            w++;
            r += 2u;
        } else {
            data[w] = data[r];
            w++;
            r++;
        }
    }
    data[w] = 0;
    *len_io = w;
}

/**
 * @brief Build trust store from PEM bytes that may contain multiple certificates.
 * @param data PEM (or leading PEM blocks) bytes.
 * @param len Length of data (NUL at data[len] allowed but not required).
 * @return NOXTLS_RETURN_SUCCESS if at least one certificate was added.
 */
static noxtls_return_t tlscurl_trust_store_from_pem_blocks(const uint8_t *data, uint32_t len)
{
    noxtls_return_t rc;
    x509_certificate_chain_t trust_chain;
    const char *begin_mark;
    const char *end_mark;
    size_t begin_len;
    size_t end_len;
    uint32_t added;
    char *scan;
    char *end_scan;

    if(data == NULL || len == 0u) {
        return NOXTLS_RETURN_NULL;
    }
    begin_mark = CERT_BEGIN_STR;
    end_mark = CERT_END_STR;
    begin_len = strlen(begin_mark);
    end_len = strlen(end_mark);
    rc = noxtls_x509_certificate_chain_init(&trust_chain);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    added = 0u;
    scan = (char *)(void *)data;
    if(len >= 3u && (uint8_t)data[0] == 0xEFu && (uint8_t)data[1] == 0xBBu && (uint8_t)data[2] == 0xBFu) {
        scan += 3;
    }
    end_scan = (char *)(void *)data + (size_t)len;
    while(scan < end_scan) {
        char *b;
        char *e;
        uint32_t block_len;
        x509_certificate_t one;

        b = strstr(scan, begin_mark);
        if(b == NULL || b >= end_scan) {
            break;
        }
        e = strstr(b + begin_len, end_mark);
        if(e == NULL) {
            noxtls_x509_certificate_chain_free(&trust_chain);
            return NOXTLS_RETURN_BAD_DATA;
        }
        e += end_len;
        block_len = (uint32_t)(e - b);
        if(block_len > NOXTLS_MAX_CERT_SIZE) {
            scan = e;
            while(scan < end_scan && (*scan == '\r' || *scan == '\n')) {
                scan++;
            }
            continue;
        }
        noxtls_x509_certificate_init(&one);
        rc = noxtls_x509_certificate_parse_pem(&one, (const uint8_t *)b, block_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&one);
            scan = e;
            while(scan < end_scan && (*scan == '\r' || *scan == '\n')) {
                scan++;
            }
            continue;
        }
        rc = noxtls_x509_certificate_chain_add(&trust_chain, &one);
        noxtls_x509_certificate_free(&one);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_chain_free(&trust_chain);
            return rc;
        }
        added++;
        scan = e;
        while(scan < end_scan && (*scan == '\r' || *scan == '\n')) {
            scan++;
        }
    }
    if(added == 0u) {
        noxtls_x509_certificate_chain_free(&trust_chain);
        return NOXTLS_RETURN_BAD_DATA;
    }
    rc = noxtls_x509_trust_store_set(&trust_chain);
    noxtls_x509_certificate_chain_free(&trust_chain);
    return rc;
}

/**
 * @brief Load CA PEM/DER file or multi-cert PEM bundle into the global trust store.
 * @param ca_file Path to PEM/DER CA or bundle (e.g. cacert.pem).
 * @return NOXTLS_RETURN_SUCCESS or error code.
 */
static noxtls_return_t tlscurl_configure_trust_store(const char *ca_file)
{
    noxtls_return_t rc;
    x509_certificate_t ca_cert;
    x509_certificate_chain_t trust_chain;
    uint8_t *raw;
    uint32_t raw_len;

    if(ca_file == NULL || ca_file[0] == '\0') {
        return NOXTLS_RETURN_NULL;
    }
    rc = tlscurl_read_ca_file_raw(ca_file, &raw, &raw_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    tlscurl_normalize_pem_crlf(raw, &raw_len);

    noxtls_x509_certificate_init(&ca_cert);
    rc = noxtls_x509_certificate_parse_pem(&ca_cert, raw, raw_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_certificate_chain_init(&trust_chain);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&ca_cert);
            free(raw);
            return rc;
        }
        rc = noxtls_x509_certificate_chain_add(&trust_chain, &ca_cert);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_x509_trust_store_set(&trust_chain);
        }
        noxtls_x509_certificate_chain_free(&trust_chain);
        noxtls_x509_certificate_free(&ca_cert);
        free(raw);
        return rc;
    }
    (void)noxtls_x509_certificate_init(&ca_cert);

    rc = noxtls_x509_certificate_parse_der(&ca_cert, raw, raw_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_certificate_chain_init(&trust_chain);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&ca_cert);
            free(raw);
            return rc;
        }
        rc = noxtls_x509_certificate_chain_add(&trust_chain, &ca_cert);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_x509_trust_store_set(&trust_chain);
        }
        noxtls_x509_certificate_chain_free(&trust_chain);
        noxtls_x509_certificate_free(&ca_cert);
        free(raw);
        return rc;
    }
    (void)noxtls_x509_certificate_init(&ca_cert);

    rc = tlscurl_trust_store_from_pem_blocks(raw, raw_len);
    free(raw);
    return rc;
}

/**
 * @brief Parse URL into host, path, and port (default 443).
 * @param url Full URL with optional scheme.
 * @param host Output host buffer.
 * @param host_len Size of host buffer.
 * @param path Output path buffer.
 * @param path_len Size of path buffer.
 * @param port Output port (network default 443 if omitted).
 * @return 0 on success, -1 on parse error.
 */
static int tlscurl_parse_url(const char *url, char *host, size_t host_len,
                                      char *path, size_t path_len, uint16_t *port)
{
    const char *p;
    const char *host_start;
    const char *host_end;
    const char *path_start;

    if(url == NULL || host == NULL || path == NULL || port == NULL) {
        return -1;
    }
    p = url;
    if(strncmp(p, "https://", 8) == 0) {
        p += 8;
    } else if(strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    host_start = p;
    while(*p != '\0' && *p != '/' && *p != ':') {
        p++;
    }
    host_end = p;
    if(host_end == host_start) {
        return -1;
    }
    if((size_t)(host_end - host_start) >= host_len) {
        return -1;
    }
    memcpy(host, host_start, (size_t)(host_end - host_start));
    host[host_end - host_start] = '\0';
    *port = (uint16_t)TLSCURL_DEFAULT_HTTPS_PORT;
    if(*p == ':') {
        const char *colon;

        p++;
        colon = p;
        while(*p != '\0' && *p != '/') {
            if(*p < '0' || *p > '9') {
                return -1;
            }
            p++;
        }
        if(p == colon) {
            return -1;
        }
        *port = (uint16_t)atoi(colon);
    }
    if(*p == '/') {
        path_start = p;
    } else {
        path_start = "/";
    }
    {
        size_t plen;

        plen = strlen(path_start);
        if(plen >= path_len) {
            return -1;
        }
        memcpy(path, path_start, plen);
        path[plen] = '\0';
    }
    return 0;
}

/**
 * @brief Decode DER length octets and advance input pointer.
 * @param p In/out pointer to current DER cursor.
 * @param end End pointer (one past final byte).
 * @param out_len Decoded length output.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA on malformed input.
 */
static noxtls_return_t tlscurl_der_read_len(const uint8_t **p, const uint8_t *end, uint32_t *out_len)
{
    uint8_t first;
    uint32_t i;
    uint32_t nbytes;
    uint32_t len;

    if(p == NULL || *p == NULL || end == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(*p >= end) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    first = **p;
    (*p)++;
    if((first & 0x80u) == 0u) {
        *out_len = (uint32_t)first;
        return NOXTLS_RETURN_SUCCESS;
    }
    nbytes = (uint32_t)(first & 0x7Fu);
    if(nbytes == 0u || nbytes > 4u || (size_t)(end - *p) < (size_t)nbytes) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    len = 0u;
    for(i = 0u; i < nbytes; i++) {
        len = (len << 8) | (uint32_t)(*p)[i];
    }
    *p += nbytes;
    *out_len = len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Read one DER TLV item and optionally enforce the expected tag.
 * @param p In/out pointer to DER cursor.
 * @param end End pointer (one past final byte).
 * @param expected_tag Expected tag value, or 0xFF to accept any tag.
 * @param tlv_start Output pointer to the beginning of TLV.
 * @param tlv_len Output total TLV length in bytes.
 * @param val_start Output pointer to value bytes.
 * @param val_len Output value length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA on malformed/tag mismatch.
 */
static noxtls_return_t tlscurl_der_read_tlv(const uint8_t **p, const uint8_t *end, uint8_t expected_tag,
                                            const uint8_t **tlv_start, uint32_t *tlv_len,
                                            const uint8_t **val_start, uint32_t *val_len)
{
    const uint8_t *start;
    const uint8_t *v;
    uint32_t l;
    noxtls_return_t rc;

    if(p == NULL || *p == NULL || end == NULL || tlv_start == NULL || tlv_len == NULL ||
       val_start == NULL || val_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(*p >= end) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    start = *p;
    if(expected_tag != 0xFFu && **p != expected_tag) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    (*p)++;
    v = *p;
    rc = tlscurl_der_read_len(&v, end, &l);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((size_t)(end - v) < (size_t)l) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *tlv_start = start;
    *val_start = v;
    *val_len = l;
    *tlv_len = (uint32_t)((v - start) + l);
    *p = v + l;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Extract SubjectPublicKeyInfo DER sequence from parsed leaf certificate.
 * @param cert Parsed leaf certificate from active TLS context.
 * @param spki_tlv Output pointer to SPKI DER TLV bytes.
 * @param spki_tlv_len Output SPKI DER TLV length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, error code on malformed certificate data.
 */
static noxtls_return_t tlscurl_extract_leaf_spki_der(const x509_certificate_t *cert,
                                                     const uint8_t **spki_tlv,
                                                     uint32_t *spki_tlv_len)
{
    const uint8_t *p;
    const uint8_t *end;
    const uint8_t *cert_val;
    const uint8_t *tbs_val;
    const uint8_t *unused_tlv;
    const uint8_t *unused_val;
    uint32_t cert_val_len;
    uint32_t tbs_val_len;
    uint32_t unused_tlv_len;
    uint32_t unused_val_len;
    noxtls_return_t rc;

    if(cert == NULL || cert->raw_data == NULL || cert->raw_data_len == 0u || spki_tlv == NULL || spki_tlv_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    p = cert->raw_data;
    end = cert->raw_data + cert->raw_data_len;

    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE, &unused_tlv, &unused_tlv_len, &cert_val, &cert_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    p = cert_val;
    end = cert_val + cert_val_len;
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE, &unused_tlv, &unused_tlv_len, &tbs_val, &tbs_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    p = tbs_val;
    end = tbs_val + tbs_val_len;

    if(p < end && *p == TLSCURL_DER_TAG_CTX0_EXPLICIT) {
        rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_CTX0_EXPLICIT,
                                  &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_INTEGER,
                              &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE,
                              &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE,
                              &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE,
                              &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE,
                              &unused_tlv, &unused_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tlscurl_der_read_tlv(&p, end, TLSCURL_DER_TAG_SEQUENCE,
                              spki_tlv, spki_tlv_len, &unused_val, &unused_val_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return base64 pin value from accepted CLI forms.
 * @param pin_raw User-supplied pin string.
 * @return Base64 segment pointer, or NULL if invalid/empty.
 */
static const char *tlscurl_pin_value_b64(const char *pin_raw)
{
    if(pin_raw == NULL || pin_raw[0] == '\0') {
        return NULL;
    }
    if(strncmp(pin_raw, TLSCURL_PIN_SHA256_PREFIX, TLSCURL_PIN_SHA256_PREFIX_LEN) == 0) {
        return pin_raw + TLSCURL_PIN_SHA256_PREFIX_LEN;
    }
    return pin_raw;
}

/**
 * @brief Verify peer leaf SPKI SHA-256 pin against expected CLI value.
 * @param active Active TLS mode.
 * @param tls12 TLS 1.2 context pointer.
 * @param tls13 TLS 1.3 context pointer.
 * @param pin_raw User pin string (base64 or sha256/base64).
 * @param verbose Verbosity level.
 * @return NOXTLS_RETURN_SUCCESS on match; NOXTLS_RETURN_CERT_VERIFY_FAILED on mismatch.
 */
static noxtls_return_t tlscurl_verify_spki_pin(tlscurl_active_tls_t active,
                                               const tls12_context_t *tls12,
                                               const tls13_context_t *tls13,
                                               const char *pin_raw,
                                               int verbose)
{
    const char *expected_b64;
    const x509_certificate_t *leaf;
    const uint8_t *spki_tlv;
    uint32_t spki_tlv_len;
    uint8_t digest[TLSCURL_PIN_SHA256_LEN];
    char actual_b64[TLSCURL_PIN_SHA256_B64_BUF_LEN];
    noxtls_sha_ctx_t sha_ctx;
    noxtls_return_t rc;
    int encoded_len;

    if(pin_raw == NULL || pin_raw[0] == '\0') {
        return NOXTLS_RETURN_SUCCESS;
    }
    expected_b64 = tlscurl_pin_value_b64(pin_raw);
    if(expected_b64 == NULL) {
        printf("[tlscurl] ERROR: invalid --pin-sha256 (empty)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(strlen(expected_b64) != TLSCURL_PIN_SHA256_B64_LEN) {
        printf("[tlscurl] ERROR: --pin-sha256 must be %u base64 chars (SHA-256)\n",
               (unsigned)TLSCURL_PIN_SHA256_B64_LEN);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(active == TLSCURL_ACTIVE_TLS12 && tls12 != NULL) {
        leaf = (const x509_certificate_t *)tls12->server_cert_parsed;
    } else if(active == TLSCURL_ACTIVE_TLS13 && tls13 != NULL) {
        leaf = (const x509_certificate_t *)tls13->server_cert_parsed;
    } else {
        return NOXTLS_RETURN_FAILED;
    }
    if(leaf == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tlscurl_extract_leaf_spki_der(leaf, &spki_tlv, &spki_tlv_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[tlscurl] ERROR: unable to extract leaf SPKI DER rc=%d\n", (int)rc);
        return rc;
    }
    rc = noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha256_update(&sha_ctx, spki_tlv, spki_tlv_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_sha256_finish(&sha_ctx, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memset(actual_b64, 0, sizeof(actual_b64));
    encoded_len = noxtls_base64_encode(digest, TLSCURL_PIN_SHA256_LEN, actual_b64);
    if(encoded_len != (int)TLSCURL_PIN_SHA256_B64_LEN) {
        return NOXTLS_RETURN_FAILED;
    }
    if(strcmp(actual_b64, expected_b64) != 0) {
        printf("[tlscurl] ERROR: SPKI pin mismatch\n");
        printf("  expected: sha256/%s\n", expected_b64);
        printf("  actual:   sha256/%s\n", actual_b64);
        return NOXTLS_RETURN_CERT_VERIFY_FAILED;
    }
    if(verbose >= 1) {
        printf("[tlscurl] pin verify: sha256/%s (match)\n", actual_b64);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Establish TCP connection to host:port.
 * @param host Hostname or IP string.
 * @param port TCP port.
 * @param out_sock Connected socket on success.
 * @return 0 on success, -1 on failure.
 */
static int tlscurl_connect_tcp(const char *host, uint16_t port, socket_t *out_sock)
{
    char port_str[TLSCURL_PORT_STR_MAX];
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *it;
    socket_t sock;

    if(host == NULL || out_sock == NULL) {
        return -1;
    }
    (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    res = NULL;
    if(getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    sock = INVALID_SOCKET;
    for(it = res; it != NULL; it = it->ai_next) {
        sock = (socket_t)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(sock == INVALID_SOCKET) {
            continue;
        }
        if(connect(sock, it->ai_addr, (int)it->ai_addrlen) == 0) {
            break;
        }
        CLOSESOCK(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if(sock == INVALID_SOCKET) {
        return -1;
    }
    *out_sock = sock;
    return 0;
}

/**
 * @brief TLS send callback over BSD sockets.
 */
static int32_t tlscurl_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    tlscurl_conn_t *conn;
    uint32_t sent_total;

    conn = (tlscurl_conn_t *)user_data;
    if(conn == NULL || data == NULL) {
        return -1;
    }
    sent_total = 0;
    while(sent_total < len) {
        int chunk;
        int sent;

        chunk = (int)(len - sent_total);
        sent = (int)send(conn->sock, (const char *)data + sent_total, (size_t)chunk, 0);
        if(sent <= 0) {
            int err = TLSCURL_SOCKERR();
            if(tlscurl_sockerr_is_retryable(err)) {
#ifdef _WIN32
                Sleep(1);
#endif
                continue;
            }
            return -1;
        }
        sent_total += (uint32_t)sent;
    }
    return (int32_t)sent_total;
}

/**
 * @brief TLS recv callback over BSD sockets.
 */
static int32_t tlscurl_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    tlscurl_conn_t *conn;
    uint32_t recv_total;

    conn = (tlscurl_conn_t *)user_data;
    if(conn == NULL || data == NULL) {
        return -1;
    }
    recv_total = 0;
    while(recv_total < len) {
        int chunk;
        int received;

        chunk = (int)(len - recv_total);
        received = (int)recv(conn->sock, (char *)data + recv_total, (size_t)chunk, 0);
        if(received <= 0) {
            int err = TLSCURL_SOCKERR();
            if(tlscurl_sockerr_is_retryable(err)) {
#ifdef _WIN32
                Sleep(1);
#endif
                continue;
            }
            return -1;
        }
        recv_total += (uint32_t)received;
    }
    return (int32_t)recv_total;
}

/**
 * @brief Append one custom header if capacity allows.
 * @param hdr Headers collection.
 * @param line Full "Name: value" line.
 * @return 0 on success, -1 if invalid or full.
 */
static int tlscurl_headers_add(tlscurl_headers_t *hdr, const char *line)
{
    const char *colon;
    size_t n;

    if(hdr == NULL || line == NULL) {
        return -1;
    }
    colon = strchr(line, ':');
    if(colon == NULL) {
        return -1;
    }
    if(hdr->count >= TLSCURL_MAX_CUSTOM_HEADERS) {
        return -1;
    }
    n = strlen(line);
    if(n >= TLSCURL_HEADER_LINE_MAX) {
        return -1;
    }
    memcpy(hdr->entries[hdr->count].line, line, n + 1u);
    hdr->count++;
    return 0;
}

/**
 * @brief Detect if custom headers already include Host.
 * @param hdr Headers collection.
 * @return 1 if Host present (case-insensitive), else 0.
 */
static int tlscurl_headers_has_host(const tlscurl_headers_t *hdr)
{
    uint32_t i;

    if(hdr == NULL) {
        return 0;
    }
    for(i = 0; i < hdr->count; i++) {
        if(tlscurl_header_has_prefix_ci(hdr->entries[i].line, "host:") != 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Read entire file into malloc'd buffer (size capped).
 * @param path File path.
 * @param out_len Output byte length.
 * @return Allocated buffer or NULL on error.
 */
static uint8_t *tlscurl_read_file_binary(const char *path, uint32_t *out_len)
{
    FILE *fp;
    long sz;
    uint8_t *buf;
    size_t rd;

    if(path == NULL || out_len == NULL) {
        return NULL;
    }
    *out_len = 0;
#ifdef _MSC_VER
    if(fopen_s(&fp, path, "rb") != 0) {
        fp = NULL;
    }
#else
    fp = fopen(path, "rb");
#endif
    if(fp == NULL) {
        return NULL;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if(sz < 0) {
        fclose(fp);
        return NULL;
    }
    if(fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    if((uint64_t)sz > (uint64_t)TLSCURL_MAX_BODY_FILE_BYTES) {
        fclose(fp);
        return NULL;
    }
    buf = (uint8_t *)malloc((size_t)sz + 1u);
    if(buf == NULL) {
        fclose(fp);
        return NULL;
    }
    rd = fread(buf, 1u, (size_t)sz, fp);
    fclose(fp);
    if(rd != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = 0;
    *out_len = (uint32_t)sz;
    return buf;
}

/**
 * @brief Open output stream for response body.
 * @param output_path Path or "-" for stdout.
 * @param out_fp Receives opened FILE* (caller may fclose except stdout).
 * @return 0 on success, -1 on error.
 */
static int tlscurl_open_output(const char *output_path, FILE **out_fp)
{
    if(out_fp == NULL) {
        return -1;
    }
    *out_fp = stdout;
    if(output_path == NULL || strcmp(output_path, "-") == 0) {
        return 0;
    }
#ifdef _MSC_VER
    if(fopen_s(out_fp, output_path, "wb") != 0) {
        *out_fp = NULL;
    }
#else
    *out_fp = fopen(output_path, "wb");
#endif
    if(*out_fp == NULL) {
        return -1;
    }
    return 0;
}

/**
 * @brief Print negotiated TLS details after handshake.
 * @param active Active TLS stack.
 * @param tls12 TLS 1.2 context if used.
 * @param tls13 TLS 1.3 context if used.
 * @param verbose 0=summary, 1=normal, 2=extra fields.
 */
static void tlscurl_print_negotiated(tlscurl_active_tls_t active, const tls12_context_t *tls12,
                                       const tls13_context_t *tls13, int verbose)
{
    if(active == TLSCURL_ACTIVE_TLS13 && tls13 != NULL) {
        printf("[tlscurl] TLS 1.3 negotiated: cipher_suite=0x%04X selected_kex_group=0x%04X hybrid=%u\n",
               (unsigned)tls13->cipher_suite, (unsigned)tls13->selected_kex_group,
               (unsigned)tls13->selected_kex_is_hybrid);
        printf("[tlscurl] TLS 1.3 base: version=0x%04X state=%s\n",
               (unsigned)tls13->base.base.version, tlscurl_tls_state_name(tls13->base.base.state));
        printf("[tlscurl] TLS 1.3 0-RTT / session: ticket_stored=%u early_data_phase=%u early_data_accepted=%u\n",
               (unsigned)tls13->ticket_stored, (unsigned)tls13->early_data_phase,
               (unsigned)tls13->early_data_accepted);
        printf("[tlscurl] TLS 1.3 0-RTT / session: early_data_sent=%u sent_end_of_early_data=%u max_early_data_size=%u\n",
               (unsigned)tls13->early_data_sent, (unsigned)tls13->sent_end_of_early_data,
               (unsigned)tls13->max_early_data_size);
        printf("[tlscurl] TLS 1.3 PSK: psk_in_use=%u psk_use_ecdhe=%u psk_selected_identity=%u ticket_cipher_suite=0x%04X\n",
               (unsigned)tls13->psk_in_use, (unsigned)tls13->psk_use_ecdhe,
               (unsigned)tls13->psk_selected_identity, (unsigned)tls13->ticket_cipher_suite);
        if(verbose >= 2) {
            printf("[tlscurl] TLS 1.3 record_size_limit_send=%u recv=%u handshake_messages_len=%u\n",
                   (unsigned)tls13->record_size_limit_send, (unsigned)tls13->record_size_limit_recv,
                   (unsigned)tls13->handshake_messages_len);
        }
    } else if(active == TLSCURL_ACTIVE_TLS12 && tls12 != NULL) {
        printf("[tlscurl] TLS 1.2 negotiated: cipher_suite=0x%04X\n", (unsigned)tls12->cipher_suite);
        printf("[tlscurl] TLS 1.2 base: version=0x%04X state=%s\n",
               (unsigned)tls12->base.base.version, tlscurl_tls_state_name(tls12->base.base.state));
        if(verbose >= 2) {
            printf("[tlscurl] TLS 1.2 handshake_messages_len=%u premaster_secret_len=%u\n",
                   (unsigned)tls12->handshake_messages_len, (unsigned)tls12->premaster_secret_len);
        }
    }
}

/**
 * @brief Parse command line into tlscurl_config_t.
 * @param argc argc from main.
 * @param argv argv from main.
 * @param cfg Output configuration.
 * @return 1 on success, 0 on usage error.
 */
static int tlscurl_parse_cli(int argc, char **argv, tlscurl_config_t *cfg)
{
    int i;

    if(cfg == NULL || argc < 2 || argv == NULL) {
        return 0;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->tls_mode = TLS_MODE_1_2;
    cfg->method = "GET";
    for(i = 1; i < argc; i++) {
        const char *a;

        a = argv[i];
        if(strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            return 0;
        }
        if(strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            cfg->verbose++;
            continue;
        }
        if(strcmp(a, "-vv") == 0) {
            cfg->verbose += 2;
            continue;
        }
        if((strcmp(a, "-X") == 0 || strcmp(a, "--method") == 0) && i + 1 < argc) {
            cfg->method = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--method=", 9) == 0) {
            cfg->method = a + 9;
            continue;
        }
        if((strcmp(a, "-H") == 0 || strcmp(a, "--header") == 0) && i + 1 < argc) {
            if(tlscurl_headers_add(&cfg->headers, argv[i + 1]) != 0) {
                return 0;
            }
            i++;
            continue;
        }
        if(strncmp(a, "--header=", 9) == 0) {
            if(tlscurl_headers_add(&cfg->headers, a + 9) != 0) {
                return 0;
            }
            continue;
        }
        if((strcmp(a, "-d") == 0 || strcmp(a, "--data") == 0) && i + 1 < argc) {
            cfg->data_arg = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--data=", 7) == 0) {
            cfg->data_arg = a + 7;
            continue;
        }
        if(strcmp(a, "--data-file") == 0 && i + 1 < argc) {
            cfg->data_file = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--data-file=", 12) == 0) {
            cfg->data_file = a + 12;
            continue;
        }
        if((strcmp(a, "-o") == 0 || strcmp(a, "--output") == 0) && i + 1 < argc) {
            cfg->output_path = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--output=", 9) == 0) {
            cfg->output_path = a + 9;
            continue;
        }
        if(strcmp(a, "--ca") == 0 && i + 1 < argc) {
            cfg->ca_file = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--ca=", 5) == 0) {
            cfg->ca_file = a + 5;
            continue;
        }
        if(strcmp(a, "--crl") == 0 && i + 1 < argc) {
            cfg->crl_file = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--crl=", 6) == 0) {
            cfg->crl_file = a + 6;
            continue;
        }
        if(strcmp(a, "--pin-sha256") == 0 && i + 1 < argc) {
            cfg->pin_sha256 = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--pin-sha256=", 13) == 0) {
            cfg->pin_sha256 = a + 13;
            continue;
        }
        if(strcmp(a, "--keylog") == 0 && i + 1 < argc) {
            cfg->keylog_path = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--keylog=", 9) == 0) {
            cfg->keylog_path = a + 9;
            continue;
        }
        if(strcmp(a, "--tlsdump") == 0 && i + 1 < argc) {
            cfg->tlsdump_path = argv[i + 1];
            i++;
            continue;
        }
        if(strncmp(a, "--tlsdump=", 10) == 0) {
            cfg->tlsdump_path = a + 10;
            continue;
        }
        if(strcmp(a, "--tls12") == 0) {
            cfg->tls_mode = TLS_MODE_1_2;
            continue;
        }
        if(strcmp(a, "--tls13") == 0) {
            cfg->tls_mode = TLS_MODE_1_3;
            continue;
        }
        if(strcmp(a, "--auto") == 0) {
            cfg->tls_mode = TLS_MODE_AUTO;
            continue;
        }
        if(strcmp(a, "--prefer-chacha") == 0) {
            cfg->prefer_chacha = 1u;
            continue;
        }
        if(strcmp(a, "--strict-hostname") == 0) {
            cfg->strict_hostname = 1u;
            continue;
        }
        if(a[0] == '-') {
            return 0;
        }
        if(cfg->url != NULL) {
            return 0;
        }
        cfg->url = a;
    }
    if(cfg->url == NULL) {
        return 0;
    }
    if(cfg->data_arg != NULL && cfg->data_file != NULL) {
        return 0;
    }
    return 1;
}

/**
 * @brief Build and send HTTP/1.1 request over active TLS session.
 * @param active Active TLS mode.
 * @param tls12 TLS 1.2 context (if active).
 * @param tls13 TLS 1.3 context (if active).
 * @param method HTTP method string.
 * @param path Request path.
 * @param host Host for Host header.
 * @param port TCP port (for Host header when non-443).
 * @param hdr Custom headers.
 * @param body Optional body bytes.
 * @param body_len Body length (may be 0).
 * @return NOXTLS_RETURN_SUCCESS or error from send.
 */
static noxtls_return_t tlscurl_send_http(tlscurl_active_tls_t active, tls12_context_t *tls12,
                                         tls13_context_t *tls13, const char *method, const char *path,
                                         const char *host, uint16_t port, const tlscurl_headers_t *hdr,
                                         const uint8_t *body, uint32_t body_len)
{
    char *req;
    size_t cap;
    size_t pos;
    uint32_t hi;
    int n;
    noxtls_return_t rc;

    if(method == NULL || path == NULL || host == NULL || hdr == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    cap = (size_t)TLSCURL_REQUEST_BUILD_MAX;
    if(body_len > (uint32_t)(cap / 2u)) {
        cap = (size_t)body_len + (size_t)TLSCURL_REQUEST_BUILD_MAX;
    }
    req = (char *)malloc(cap);
    if(req == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    pos = 0;
    n = snprintf(req + pos, cap - pos, "%s %s HTTP/1.1\r\n", method, path);
    if(n < 0 || (size_t)n >= cap - pos) {
        free(req);
        return NOXTLS_RETURN_FAILED;
    }
    pos += (size_t)n;
    if(tlscurl_headers_has_host(hdr) == 0) {
        if(port != (uint16_t)TLSCURL_DEFAULT_HTTPS_PORT) {
            n = snprintf(req + pos, cap - pos, "Host: %s:%u\r\n", host, (unsigned)port);
        } else {
            n = snprintf(req + pos, cap - pos, "Host: %s\r\n", host);
        }
        if(n < 0 || (size_t)n >= cap - pos) {
            free(req);
            return NOXTLS_RETURN_FAILED;
        }
        pos += (size_t)n;
    }
    n = snprintf(req + pos, cap - pos,
                   "User-Agent: NoxTLS-tlscurl/0.1\r\n"
                   "Accept: */*\r\n"
                   "Accept-Encoding: identity\r\n"
                   "Connection: close\r\n");
    if(n < 0 || (size_t)n >= cap - pos) {
        free(req);
        return NOXTLS_RETURN_FAILED;
    }
    pos += (size_t)n;
    for(hi = 0; hi < hdr->count; hi++) {
        size_t ln;

        ln = strlen(hdr->entries[hi].line);
        if(pos + ln + 2u >= cap) {
            free(req);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(req + pos, hdr->entries[hi].line, ln);
        pos += ln;
        req[pos++] = '\r';
        req[pos++] = '\n';
    }
    if(body != NULL && body_len > 0u) {
        n = snprintf(req + pos, cap - pos, "Content-Length: %u\r\n", (unsigned)body_len);
        if(n < 0 || (size_t)n >= cap - pos) {
            free(req);
            return NOXTLS_RETURN_FAILED;
        }
        pos += (size_t)n;
    }
    if(pos + 2u >= cap) {
        free(req);
        return NOXTLS_RETURN_FAILED;
    }
    req[pos++] = '\r';
    req[pos++] = '\n';
    if(body != NULL && body_len > 0u) {
        if(pos + (size_t)body_len > cap) {
            free(req);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(req + pos, body, (size_t)body_len);
        pos += (size_t)body_len;
    }
    if(active == TLSCURL_ACTIVE_TLS13) {
        rc = noxtls_tls13_send(tls13, (const uint8_t *)req, (uint32_t)pos);
    } else if(active == TLSCURL_ACTIVE_TLS12) {
        rc = noxtls_tls12_send(tls12, (const uint8_t *)req, (uint32_t)pos);
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }
    free(req);
    return rc;
}

/**
 * @brief Application entry: HTTPS request with TLS diagnostics.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, non-zero on error.
 */
int main(int argc, char **argv)
{
    tlscurl_config_t cfg;
    char host[TLSCURL_HOST_MAX];
    char path[TLSCURL_PATH_MAX];
    uint16_t port;
    socket_t sock;
    tlscurl_conn_t conn;
    tls12_context_t tls12_ctx;
    tls13_context_t tls13_ctx;
    tlscurl_active_tls_t active;
    int trust_configured;
    noxtls_return_t rc;
    FILE *out_fp;
    uint8_t *body_buf;
    uint32_t body_len;
    const char *ca_use;
    noxtls_x509_crl_t verify_crl;
    int verify_crl_loaded;

#ifdef _WIN32
    {
        WSADATA wsa;

        if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("[tlscurl] ERROR: WSAStartup failed\n");
            return 1;
        }
    }
#endif
    body_buf = NULL;
    body_len = 0;
    trust_configured = 0;
    sock = INVALID_SOCKET;
    active = TLSCURL_ACTIVE_NONE;
    memset(&tls12_ctx, 0, sizeof(tls12_ctx));
    memset(&tls13_ctx, 0, sizeof(tls13_ctx));
    out_fp = stdout;
    noxtls_x509_crl_init(&verify_crl);
    verify_crl_loaded = 0;

    if(argc >= 2 && argv[1] != NULL &&
       (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        tlscurl_print_usage((argc > 0 && argv[0] != NULL) ? argv[0] : "tlscurl");
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    if(tlscurl_parse_cli(argc, argv, &cfg) == 0) {
        tlscurl_print_usage((argc > 0 && argv != NULL) ? argv[0] : "tlscurl");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    if(cfg.verbose >= 1) {
        tlscurl_print_platform();
        tlscurl_print_build_features();
    }
    if(cfg.keylog_path != NULL && cfg.keylog_path[0] != '\0') {
        noxtls_tls13_set_keylog_file(cfg.keylog_path);
    }
    if(getenv("SSLKEYLOGFILE") != NULL && (cfg.keylog_path == NULL || cfg.keylog_path[0] == '\0')) {
        noxtls_tls13_set_keylog_file(getenv("SSLKEYLOGFILE"));
    }
    if(cfg.tlsdump_path != NULL && cfg.tlsdump_path[0] != '\0') {
        noxtls_tls_set_record_dump_file(cfg.tlsdump_path);
    }
    if(cfg.strict_hostname != 0u) {
        noxtls_x509_set_hostname_wildcard_matching(0);
    } else {
        noxtls_x509_set_hostname_wildcard_matching(1);
    }
    if(tlscurl_parse_url(cfg.url, host, sizeof(host), path, sizeof(path), &port) != 0) {
        printf("[tlscurl] ERROR: invalid URL\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    ca_use = cfg.ca_file;
    if(ca_use == NULL) {
        if(strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0) {
            ca_use = "server.crt";
        }
    }
    if(ca_use == NULL) {
        printf("[tlscurl] ERROR: no trust anchor; use --ca <pem|der> (or localhost with server.crt)\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    noxtls_cert_verify_failure_clear();
    rc = tlscurl_configure_trust_store(ca_use);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[tlscurl] ERROR: trust store load failed rc=%d path=%s\n", (int)rc, ca_use);
        tlscurl_print_tls_error("trust_store", rc);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    trust_configured = 1;

    if(cfg.data_file != NULL) {
        body_buf = tlscurl_read_file_binary(cfg.data_file, &body_len);
        if(body_buf == NULL) {
            printf("[tlscurl] ERROR: cannot read --data-file (missing, too large, or read error)\n");
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    } else if(cfg.data_arg != NULL) {
        size_t dl;

        dl = strlen(cfg.data_arg);
        if(dl > (size_t)TLSCURL_DATA_ARG_MAX) {
            printf("[tlscurl] ERROR: --data string too long (max %u)\n", (unsigned)TLSCURL_DATA_ARG_MAX);
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        body_buf = (uint8_t *)malloc(dl + 1u);
        if(body_buf == NULL) {
            printf("[tlscurl] ERROR: out of memory for body\n");
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        memcpy(body_buf, cfg.data_arg, dl + 1u);
        body_len = (uint32_t)dl;
    }

    if(tlscurl_open_output(cfg.output_path, &out_fp) != 0) {
        printf("[tlscurl] ERROR: cannot open --output file\n");
        free(body_buf);
        if(trust_configured != 0) {
            noxtls_x509_trust_store_clear();
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("[tlscurl] connect %s:%u path=%s tls_mode=%d\n", host, (unsigned)port, path, (int)cfg.tls_mode);
    if(tlscurl_connect_tcp(host, port, &sock) != 0) {
        printf("[tlscurl] ERROR: TCP connect failed sock_err=%d\n", TLSCURL_SOCKERR());
        free(body_buf);
        if(out_fp != stdout) {
            fclose(out_fp);
        }
        if(trust_configured != 0) {
            noxtls_x509_trust_store_clear();
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    conn.sock = sock;

    if(cfg.crl_file != NULL && cfg.crl_file[0] != '\0') {
        rc = noxtls_x509_crl_load_file(&verify_crl, cfg.crl_file);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: CRL load failed rc=%d path=%s\n", (int)rc, cfg.crl_file);
            tlscurl_print_tls_error("crl_load", rc);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        verify_crl_loaded = 1;
    }

    if(cfg.tls_mode == TLS_MODE_1_3 || cfg.tls_mode == TLS_MODE_AUTO) {
        rc = noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: tls13_context_init rc=%d\n", (int)rc);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(verify_crl_loaded != 0) {
                noxtls_x509_crl_free(&verify_crl);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        tls13_ctx.server_name = host;
        tls13_ctx.server_name_len = (uint16_t)strlen(host);
        noxtls_tls13_set_verify_crl(&tls13_ctx, verify_crl_loaded ? &verify_crl : NULL);
        if(cfg.prefer_chacha != 0u) {
            tls13_ctx.prefer_chacha20 = 1u;
        }
        rc = noxtls_tls_set_io_callbacks(&tls13_ctx.base.base, tlscurl_send_cb, tlscurl_recv_cb, &conn);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: set_io_callbacks tls13 rc=%d\n", (int)rc);
            noxtls_tls13_context_free(&tls13_ctx);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(verify_crl_loaded != 0) {
                noxtls_x509_crl_free(&verify_crl);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        noxtls_cert_verify_failure_clear();
        rc = noxtls_tls13_connect(&tls13_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] WARNING: TLS 1.3 handshake failed rc=%d\n", (int)rc);
            tlscurl_print_tls_error("tls13_connect", rc);
            noxtls_tls13_context_free(&tls13_ctx);
            if(cfg.tls_mode == TLS_MODE_1_3) {
                CLOSESOCK(sock);
                free(body_buf);
                if(out_fp != stdout) {
                    fclose(out_fp);
                }
                if(verify_crl_loaded != 0) {
                    noxtls_x509_crl_free(&verify_crl);
                }
                if(trust_configured != 0) {
                    noxtls_x509_trust_store_clear();
                }
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
        } else {
            active = TLSCURL_ACTIVE_TLS13;
        }
    }

    if(active == TLSCURL_ACTIVE_NONE) {
        rc = noxtls_tls12_context_init(&tls12_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: tls12_context_init rc=%d\n", (int)rc);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(verify_crl_loaded != 0) {
                noxtls_x509_crl_free(&verify_crl);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        tls12_ctx.server_name = host;
        tls12_ctx.server_name_len = (uint16_t)strlen(host);
        noxtls_tls12_set_verify_crl(&tls12_ctx, verify_crl_loaded ? &verify_crl : NULL);
        rc = noxtls_tls_set_io_callbacks(&tls12_ctx.base.base, tlscurl_send_cb, tlscurl_recv_cb, &conn);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: set_io_callbacks tls12 rc=%d\n", (int)rc);
            noxtls_tls12_context_free(&tls12_ctx);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(verify_crl_loaded != 0) {
                noxtls_x509_crl_free(&verify_crl);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        noxtls_cert_verify_failure_clear();
        rc = noxtls_tls12_connect(&tls12_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[tlscurl] ERROR: TLS 1.2 handshake failed rc=%d\n", (int)rc);
            tlscurl_print_tls_error("tls12_connect", rc);
            noxtls_tls12_context_free(&tls12_ctx);
            CLOSESOCK(sock);
            free(body_buf);
            if(out_fp != stdout) {
                fclose(out_fp);
            }
            if(verify_crl_loaded != 0) {
                noxtls_x509_crl_free(&verify_crl);
            }
            if(trust_configured != 0) {
                noxtls_x509_trust_store_clear();
            }
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        active = TLSCURL_ACTIVE_TLS12;
    }

    printf("[tlscurl] handshake complete (active=%s)\n",
           (active == TLSCURL_ACTIVE_TLS13) ? "TLS1.3" : "TLS1.2");
    rc = tlscurl_verify_spki_pin(active, &tls12_ctx, &tls13_ctx, cfg.pin_sha256, cfg.verbose);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        tlscurl_print_tls_error("pin_verify", rc);
        if(active == TLSCURL_ACTIVE_TLS13) {
            noxtls_tls13_close(&tls13_ctx);
            noxtls_tls13_context_free(&tls13_ctx);
        } else {
            noxtls_tls12_close(&tls12_ctx);
            noxtls_tls12_context_free(&tls12_ctx);
        }
        CLOSESOCK(sock);
        free(body_buf);
        if(out_fp != stdout) {
            fclose(out_fp);
        }
        if(verify_crl_loaded != 0) {
            noxtls_x509_crl_free(&verify_crl);
        }
        if(trust_configured != 0) {
            noxtls_x509_trust_store_clear();
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    tlscurl_print_negotiated(active, &tls12_ctx, &tls13_ctx, cfg.verbose);

    rc = tlscurl_send_http(active, &tls12_ctx, &tls13_ctx, cfg.method, path, host, port, &cfg.headers,
                          body_buf, body_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[tlscurl] ERROR: HTTP send failed rc=%d\n", (int)rc);
        tlscurl_print_tls_error("http_send", rc);
        if(active == TLSCURL_ACTIVE_TLS13) {
            noxtls_tls13_close(&tls13_ctx);
            noxtls_tls13_context_free(&tls13_ctx);
        } else {
            noxtls_tls12_close(&tls12_ctx);
            noxtls_tls12_context_free(&tls12_ctx);
        }
        CLOSESOCK(sock);
        free(body_buf);
        if(out_fp != stdout) {
            fclose(out_fp);
        }
        if(verify_crl_loaded != 0) {
            noxtls_x509_crl_free(&verify_crl);
        }
        if(trust_configured != 0) {
            noxtls_x509_trust_store_clear();
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if(cfg.verbose >= 1) {
        printf("[tlscurl] ---- response body (TLS app data) ----\n");
    }
    for(;;) {
        uint8_t buf[TLSCURL_TLS_RECV_CHUNK];
        uint32_t len;

        len = (uint32_t)sizeof(buf) - 1u;
        if(active == TLSCURL_ACTIVE_TLS13) {
            rc = noxtls_tls13_recv(&tls13_ctx, buf, &len);
        } else {
            rc = noxtls_tls12_recv(&tls12_ctx, buf, &len);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(cfg.verbose >= 1) {
                printf("\n[tlscurl] recv ended rc=%d (often EOF after close_notify)\n", (int)rc);
            }
            break;
        }
        if(len == 0u) {
            break;
        }
        (void)fwrite(buf, 1u, (size_t)len, out_fp);
    }
    if(cfg.verbose >= 1) {
        printf("[tlscurl] ---- end response ----\n");
    }

    if(active == TLSCURL_ACTIVE_TLS13) {
        noxtls_tls13_close(&tls13_ctx);
        noxtls_tls13_context_free(&tls13_ctx);
    } else {
        noxtls_tls12_close(&tls12_ctx);
        noxtls_tls12_context_free(&tls12_ctx);
    }
    CLOSESOCK(sock);
    free(body_buf);
    if(out_fp != stdout) {
        fclose(out_fp);
    }
    if(verify_crl_loaded != 0) {
        noxtls_x509_crl_free(&verify_crl);
    }
    if(trust_configured != 0) {
        noxtls_x509_trust_store_clear();
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
