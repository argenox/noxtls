/*
* This file is part of the NoxTLS Library.
*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*/
/**
 * @file main.c
 * @brief Configurable HTTPS server with negotiated-algorithm reporting.
 */

/* MUST be the FIRST #include: app-local noxtls_config.h (project policy)
 * MSVC searches the directory of the including header first for "..."
 * style includes; if a library header pulls in "noxtls_config.h" before
 * this app does, the top-level config wins. Hoisting our local one
 * here ensures _NOXTLS_CONFIG_H_ is set from THIS file. */
#include "noxtls_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define STR_CASE_EQ(a, b) (_stricmp((a), (b)) == 0)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
#define CLOSESOCK close
#define STR_CASE_EQ(a, b) (strcasecmp((a), (b)) == 0)
#endif

#include "noxtls_common.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/common/noxtls_debug_printf.h"
#include "noxtls-lib/pkc/ecc/noxtls_ecc.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "noxtls-lib/tls/noxtls_tls.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"
#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
#include "noxtls-lib/tls/noxtls_tls_unified.h"

/* ============================================================================
 * Application-private static workspace (per project policy)
 * ============================================================================
 *
 * Every application owns a large statically-allocated workspace buffer; all
 * dynamic allocations made by this translation unit are served out of it via
 * a simple bump arena. The buffer's size lives in this app's noxtls_config.h
 * (NOXTLS_APP_STATIC_BUFFER_SIZE) so it can be tuned independently per app.
 *
 * free() is a no-op; the whole arena is released en-masse via
 * app_workspace_reset() (e.g. between commands) which also wipes any
 * transient secret material that may have been allocated.
 */
static uint8_t  g_app_workspace[NOXTLS_APP_STATIC_BUFFER_SIZE];
static size_t   g_app_workspace_off = 0U;
#define APP_WORKSPACE_ALIGN ((size_t)16U)

typedef enum {
    FILE_FORMAT_AUTO = 0,
    FILE_FORMAT_PEM = 1,
    FILE_FORMAT_DER = 2
} file_format_t;

typedef struct {
    const char *name;
    uint16_t suite;
} cipher_suite_entry_t;

typedef struct {
    socket_t sock;
} https_conn_t;

typedef enum {
    SERVER_KEY_KIND_NONE = 0,
    SERVER_KEY_KIND_RSA = 1,
    SERVER_KEY_KIND_ECDSA = 2,
    SERVER_KEY_KIND_ED25519 = 3,
    SERVER_KEY_KIND_ED448 = 4
} server_key_kind_t;

/**
 * @brief Allocate workspace
 *
 * @param[in] n The size to allocate
 * @return The pointer to the allocated workspace
 */
static void *app_workspace_alloc(size_t n)
{
    size_t off = (g_app_workspace_off + (APP_WORKSPACE_ALIGN - 1U)) &
                 ~(APP_WORKSPACE_ALIGN - 1U);
    if(n == 0U || off > sizeof(g_app_workspace) ||
       n > sizeof(g_app_workspace) - off) {
        return NULL;
    }
    g_app_workspace_off = off + n;
    return &g_app_workspace[off];
}

/**
 * @brief Free the workspace
 *
 * @param[in] p The pointer to the workspace to free
 * @return void
 */
static void app_workspace_free(void *p) 
{ 
    (void)p; 
}

/**
 * @brief Reset the workspace
 *
 * @return void
 */
static void app_workspace_reset(void)
{
    if(g_app_workspace_off > 0U) {
        memset(g_app_workspace, 0, g_app_workspace_off);
    }
    g_app_workspace_off = 0U;
}

/* Redirect malloc()/free() in this translation unit to the static workspace.
 * Library and standard headers have already been pulled in above; they
 * declared malloc/free as plain functions and are unaffected. App code below
 * uses these macros transparently. */
#undef malloc
#undef free
#define malloc(n) app_workspace_alloc(n)
#define free(p)   app_workspace_free(p)
#endif

#define DEFAULT_PORT 8443
#define DEFAULT_CERT_FILE "server.crt"
#define DEFAULT_KEY_FILE "server.key"
#define DEFAULT_BIND_IP "127.0.0.1"
#define REQUEST_BUFFER_SIZE 65536u
#define REQUEST_READ_CHUNK 65535u
#define HTTP_HEADER_BUFFER_SIZE 512U
#define HTTP_BODY_BUFFER_SIZE 4096u
#define TLS_SEND_CHUNK 16384u
#define CLIENT_IO_TIMEOUT_MS 15000u
#define MAX_CIPHER_SUITES 64U

#if !defined(HTTPS_SERVER_APP_VERSION)
#define HTTPS_SERVER_APP_VERSION "unknown"
#endif
#define MAX_CERT_CHAIN_ENTRIES 8U
#define MAX_ALPN_PROTOCOLS 8U
#define MAX_ALPN_PROTOCOL_LEN 64U
static const char *DEFAULT_ALPN_PROTOCOLS[] = { "http/1.1", "h2" };
static const uint32_t DEFAULT_ALPN_PROTOCOL_COUNT =
    (uint32_t)(sizeof(DEFAULT_ALPN_PROTOCOLS) / sizeof(DEFAULT_ALPN_PROTOCOLS[0]));
/*
 * Default TLS 1.2 offer: forward-secret AEAD first (no static RSA key exchange, no 3DES).
 * Weak CBC/SHA1 ECDHE/DHE-RSA suites are appended last for tlsfuzzer scripts that pin only
 * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA / TLS_DHE_RSA_WITH_AES_128_CBC_SHA (e.g. test_sig_algs.py).
 */
static const uint16_t TLS12_FALLBACK_DEFAULT_SUITES[] = {
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    /* DHE_RSA AES-GCM: tlsfuzzer test_unsupported_curve_fallback (ECDHEâ†’DHE when supported_groups has no usable EC). */
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    /*
     * tlsfuzzer test_sig_algs.py (and similar probes) pin TLS_ECDHE/DHE_RSA_WITH_AES_128_CBC_SHA only.
     * Keep these after AEAD so normal clients still negotiate forward-secret AEAD first.
     */
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA
};

typedef struct {
    x509_certificate_t cert;
    x509_private_key_t key_pk;
    ecc_key_t ecc_key;
} https_tls13_ecdsa_matrix_slot_t;

static https_tls13_ecdsa_matrix_slot_t g_https_tls13_ecdsa_matrix[8];
static uint32_t g_https_tls13_ecdsa_matrix_n;

#ifndef _WIN32
/**
 * @brief Extract the directory portion of a POSIX path.
 *
 * For example, "cert.pem" yields ".", and "/a/b.pem" yields "/a".
 *
 * @param[in] path Input path.
 * @param[out] dir Buffer for the directory result.
 * @param[in] dir_len Size of @p dir in bytes.
 * @return void
 */
static void https_path_dirname(const char *path, char *dir, size_t dir_len)
{
    const char *slash;

    if(path == NULL || dir_len < 2U) {
        if(dir_len >= 1U && dir != NULL) {
            dir[0] = '.';
            dir[1] = '\0';
        }
        return;
    }
    slash = strrchr(path, '/');
    if(slash == NULL) {
        dir[0] = '.';
        dir[1] = '\0';
        return;
    }
    if(slash == path) {
        if(dir_len >= 2U) {
            dir[0] = '/';
            dir[1] = '\0';
        }
        return;
    }
    {
        size_t n = (size_t)(slash - path);
        if(n >= dir_len) {
            n = dir_len - 1U;
        }
        memcpy(dir, path, n);
        dir[n] = '\0';
    }
}

/**
 * @brief Join the path
 *
 * @param[in] out The output to join the path into
 * @param[in] out_len The length of the output to join the path into
 * @param[in] dir The directory to join the path into
 * @param[in] base The base to join the path into
 * @return 1 on success, 0 on failure
 */
static int https_join_path(char *out, size_t out_len, const char *dir, const char *base)
{
    int w = snprintf(out, out_len, "%s/%s", dir, base);
    return w > 0 && (size_t)w < out_len;
}

/**
 * @brief Look for tls12_rsa.crt and tls12_rsa.key in a directory.
 *
 * If both files exist and are readable, writes full paths to @p out_cert and @p out_key.
 *
 * @param[in] dir Directory to search.
 * @param[out] out_cert Buffer for certificate path.
 * @param[in] out_cert_len Size of @p out_cert.
 * @param[out] out_key Buffer for private key path.
 * @param[in] out_key_len Size of @p out_key.
 * @return 1 if both files were found, 0 otherwise
 */
static int https_try_tls12_rsa_in_dir(const char *dir,
                                      char *out_cert,
                                      size_t out_cert_len,
                                      char *out_key,
                                      size_t out_key_len)
{
    if(dir == NULL || dir[0] == '\0' || out_cert == NULL || out_key == NULL ||
       out_cert_len == 0U || out_key_len == 0U) {
        return 0;
    }
    out_cert[0] = '\0';
    out_key[0] = '\0';
    if(!https_join_path(out_cert, out_cert_len, dir, "tls12_rsa.crt")) {
        return 0;
    }
    if(!https_join_path(out_key, out_key_len, dir, "tls12_rsa.key")) {
        return 0;
    }
    if(access(out_cert, R_OK) != 0 || access(out_key, R_OK) != 0) {
        out_cert[0] = '\0';
        out_key[0] = '\0';
        return 0;
    }
    return 1;
}

/**
 * @brief Auto-discover TLS 1.2 RSA cert/key next to the primary certificate.
 *
 * Used so ECDSA (or other non-RSA) deployments pick up tls12_rsa.* without
 * explicit --tls12-cert/--tls12-key (tlsfuzzer DHE_RSA scripts).
 *
 * @param[in] cert_path Primary certificate path; its directory is searched.
 * @param[out] out_cert Buffer for TLS 1.2 certificate path.
 * @param[in] out_cert_len Size of @p out_cert.
 * @param[out] out_key Buffer for TLS 1.2 private key path.
 * @param[in] out_key_len Size of @p out_key.
 * @return 1 if paths were found, 0 otherwise
 */
static int https_try_auto_tls12_rsa_paths(const char *cert_path,
                                          char *out_cert,
                                          size_t out_cert_len,
                                          char *out_key,
                                          size_t out_key_len)
{
    char dir[512];

    if(cert_path == NULL) {
        return 0;
    }
    https_path_dirname(cert_path, dir, sizeof(dir));
    return https_try_tls12_rsa_in_dir(dir, out_cert, out_cert_len, out_key, out_key_len);
}

#if defined(__linux__)
/**
 * @brief Auto-discover TLS 1.2 RSA cert/key next to the Linux executable.
 *
 * Uses /proc/self/exe so ECDSA certs outside the build tree still pick up
 * binary/tls12_rsa.* .
 *
 * @param[out] out_cert Buffer for certificate path.
 * @param[in] out_cert_len Size of @p out_cert.
 * @param[out] out_key Buffer for private key path.
 * @param[in] out_key_len Size of @p out_key.
 * @return 1 if paths were found, 0 otherwise
 */
static int https_try_tls12_rsa_next_to_linux_exe(char *out_cert,
                                                 size_t out_cert_len,
                                                 char *out_key,
                                                 size_t out_key_len)
{
    char exe_buf[512];
    ssize_t n;

    n = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if(n <= 0) {
        return 0;
    }
    exe_buf[n] = '\0';
    {
        char dir[512];
        https_path_dirname(exe_buf, dir, sizeof(dir));
        return https_try_tls12_rsa_in_dir(dir, out_cert, out_cert_len, out_key, out_key_len);
    }
}
#endif /* __linux__ */

/**
 * @brief Look for tls12_rsa_pss.crt and tls12_rsa_pss.key in a directory.
 *
 * Optional RSASSA-PSS SPKI material beside the primary cert or https_server binary.
 *
 * @param[in] dir Directory to search.
 * @param[out] out_cert Buffer for certificate path.
 * @param[in] out_cert_len Size of @p out_cert.
 * @param[out] out_key Buffer for private key path.
 * @param[in] out_key_len Size of @p out_key.
 * @return 1 if both files were found, 0 otherwise
 */
static int https_try_tls12_rsa_pss_in_dir(const char *dir,
                                          char *out_cert,
                                          size_t out_cert_len,
                                          char *out_key,
                                          size_t out_key_len)
{
    if(dir == NULL || dir[0] == '\0' || out_cert == NULL || out_key == NULL ||
       out_cert_len == 0U || out_key_len == 0U) {
        return 0;
    }
    out_cert[0] = '\0';
    out_key[0] = '\0';
    if(!https_join_path(out_cert, out_cert_len, dir, "tls12_rsa_pss.crt")) {
        return 0;
    }
    if(!https_join_path(out_key, out_key_len, dir, "tls12_rsa_pss.key")) {
        return 0;
    }
    if(access(out_cert, R_OK) != 0 || access(out_key, R_OK) != 0) {
        out_cert[0] = '\0';
        out_key[0] = '\0';
        return 0;
    }
    return 1;
}

/**
 * @brief Try to get the TLS 1.2 RSA PSS paths
 *
 * @param[in] cert_path The certificate path to try to get the TLS 1.2 RSA PSS paths from
 * @param[out] out_cert The output to try to get the TLS 1.2 RSA PSS paths into
 * @param[in] out_cert_len The length of the output to try to get the TLS 1.2 RSA PSS paths into
 * @param[out] out_key The output to try to get the TLS 1.2 RSA PSS paths into
 * @param[in] out_key_len The length of the output to try to get the TLS 1.2 RSA PSS paths into
 * @return 1 on success, 0 on failure
 */
static int https_try_auto_tls12_rsa_pss_paths(const char *cert_path,
                                               char *out_cert,
                                               size_t out_cert_len,
                                               char *out_key,
                                               size_t out_key_len)
{
    char dir[512];

    if(cert_path == NULL) {
        return 0;
    }
    https_path_dirname(cert_path, dir, sizeof(dir));
    return https_try_tls12_rsa_pss_in_dir(dir, out_cert, out_cert_len, out_key, out_key_len);
}

#if defined(__linux__)

/**
 * @brief Try to get the TLS 1.2 RSA PSS paths next to the Linux executable
 *
 * @param[out] out_cert The output to try to get the TLS 1.2 RSA PSS paths next to the Linux executable into
 * @param[in] out_cert_len The length of the output to try to get the TLS 1.2 RSA PSS paths next to the Linux executable into
 * @param[out] out_key The output to try to get the TLS 1.2 RSA PSS paths next to the Linux executable into
 * @param[in] out_key_len The length of the output to try to get the TLS 1.2 RSA PSS paths next to the Linux executable into
 * @return 1 on success, 0 on failure
 */
static int https_try_tls12_rsa_pss_next_to_linux_exe(char *out_cert,
                                                    size_t out_cert_len,
                                                    char *out_key,
                                                    size_t out_key_len)
{
    char exe_buf[512];
    ssize_t n;

    n = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if(n <= 0) {
        return 0;
    }
    exe_buf[n] = '\0';
    {
        char dir[512];
        https_path_dirname(exe_buf, dir, sizeof(dir));
        return https_try_tls12_rsa_pss_in_dir(dir, out_cert, out_cert_len, out_key, out_key_len);
    }
}
#endif /* __linux__ */
#endif /* !_WIN32 */

/**
 * @brief Get the X.509 private key type name
 *
 * @param[in] t The private key type to get the name from
 * @return The private key type name
 */
static const char *https_x509_private_key_type_name(x509_private_key_type_t t)
{
    switch(t) {
        case X509_PRIVATE_KEY_RSA:
            return "RSA";
        case X509_PRIVATE_KEY_ECC:
            return "ECDSA";
        case X509_PRIVATE_KEY_ED25519:
            return "Ed25519";
        case X509_PRIVATE_KEY_ED448:
            return "Ed448";
        default:
            return "unknown";
    }
}

/**
 * @brief Infer the leaf certificate public key type
 * Infer SPKI algorithm from parsed leaf certificate (must match --key type for TLS handshakes).
 *
 * @param[in] cert The certificate to infer the leaf certificate public key type from
 * @param[out] out The output to infer the leaf certificate public key type into
 * @return 1 on success, 0 on failure
 * 
 */
static int https_infer_leaf_cert_public_key_type(const x509_certificate_t *cert,
                                                 x509_private_key_type_t *out)
{
    if(cert == NULL || out == NULL) {
        return 0;
    }
    if(cert->has_ed448) {
        *out = X509_PRIVATE_KEY_ED448;
        return 1;
    }
    if(cert->has_ed25519) {
        *out = X509_PRIVATE_KEY_ED25519;
        return 1;
    }
    if(cert->rsa_modulus != NULL && cert->rsa_modulus_len > 0U) {
        *out = X509_PRIVATE_KEY_RSA;
        return 1;
    }
    if(cert->ecc_public_key != NULL && cert->ecc_public_key_len > 0U) {
        *out = X509_PRIVATE_KEY_ECC;
        return 1;
    }
    return 0;
}



/**
 * @brief Close the client socket
 *
 * @param[in] sock The socket to close the client socket from
 * @return void
 */
static void close_client_socket(socket_t sock)
{
    if(sock == INVALID_SOCKET_VALUE) {
        return;
    }
#ifdef _WIN32
    shutdown(sock, SD_SEND);
#else
    {
        char drain_buf[4096];
        ssize_t dn;
        int di;

        (void)shutdown(sock, SHUT_WR);
        /*
         * tlsfuzzer often pipelines another record (e.g. application data) after a
         * malformed post-handshake message. If we close() while those bytes are still
         * unread in the socket buffer, Linux may RST the connection and the client
         * never observes the fatal alert (ExpectAlert becomes "Unexpected closure").
         */
        for(di = 0; di < 64; di++) {
            dn = recv(sock, drain_buf, sizeof(drain_buf), MSG_DONTWAIT);
            if(dn > 0) {
                continue;
            }
            if(dn == 0) {
                break;
            }
            if(errno == EINTR) {
                continue;
            }
            break;
        }
        usleep(50000); /* allow pending alert record to leave kernel send queue */
    }
#endif
    CLOSESOCK(sock);
}

static const cipher_suite_entry_t CIPHER_NAME_TABLE[] = {
    { "TLS_RSA_WITH_3DES_EDE_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA },
    { "TLS_RSA_WITH_AES_128_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA },
    { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA },
    { "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA },
    { "TLS_RSA_WITH_AES_256_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA },
    { "TLS_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_RSA_WITH_AES_256_CBC_SHA256", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 },
    { "TLS_RSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_RSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA },
    { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
    { "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 },
    { "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
    { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8 },
    { "TLS_RSA_WITH_AES_128_CCM", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM },
    { "TLS_RSA_WITH_AES_256_CCM", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM },
    { "TLS_RSA_WITH_AES_128_CCM_8", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 },
    { "TLS_RSA_WITH_AES_256_CCM_8", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 },
    { "TLS_DHE_RSA_WITH_AES_128_CCM", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM },
    { "TLS_DHE_RSA_WITH_AES_256_CCM", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM },
    { "TLS_DHE_RSA_WITH_AES_128_CCM_8", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 },
    { "TLS_DHE_RSA_WITH_AES_256_CCM_8", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 },
    { "TLS_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_AES_128_GCM_SHA256 },
    { "TLS_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_AES_256_GCM_SHA384 },
    { "TLS_CHACHA20_POLY1305_SHA256", TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 },
    { "TLS_AES_128_CCM_SHA256", TLS_CIPHER_SUITE_AES_128_CCM_SHA256 },
    { "TLS_AES_128_CCM_8_SHA256", TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256 }
};

/**
 * @brief Get the format name
 *
 * @param[in] format The format to get the name from
 * @return The format name
 */
static const char *format_name(file_format_t format)
{
    if(format == FILE_FORMAT_PEM) return "pem";
    if(format == FILE_FORMAT_DER) return "der";
    return "auto";
}

/**
 * @brief Get the server key kind name
 *
 * @param[in] kind The server key kind to get the name from
 * @return The server key kind name
 */
static const char *server_key_kind_name(server_key_kind_t kind)
{
    if(kind == SERVER_KEY_KIND_RSA) return "RSA";
    if(kind == SERVER_KEY_KIND_ECDSA) return "ECDSA";
    if(kind == SERVER_KEY_KIND_ED25519) return "Ed25519";
    if(kind == SERVER_KEY_KIND_ED448) return "Ed448";
    return "unknown";
}

/**
 * @brief Get the TLS version name
 *
 * @param[in] version The TLS version to get the name from
 * @return The TLS version name
 */
static const char *tls_version_name(uint16_t version)
{
    if(version == TLS_VERSION_1_3) return "TLS 1.3";
    if(version == TLS_VERSION_1_2) return "TLS 1.2";
    if(version == TLS_VERSION_1_1) return "TLS 1.1";
    if(version == TLS_VERSION_1_0) return "TLS 1.0";
    return "unknown";
}

/**
 * @brief Get the cipher suite name
 *
 * @param[in] suite The cipher suite to get the name from
 * @return The cipher suite name
 */
static const char *tls_cipher_suite_name(uint16_t suite)
{
    uint32_t i;
    for(i = 0; i < (uint32_t)(sizeof(CIPHER_NAME_TABLE) / sizeof(CIPHER_NAME_TABLE[0])); i++) {
        if(CIPHER_NAME_TABLE[i].suite == suite) {
            return CIPHER_NAME_TABLE[i].name;
        }
    }
    return "UNKNOWN_CIPHER_SUITE";
}

/**
 * @brief Get the group name
 *
 * @param[in] group The group to get the name from
 * @return The group name
 */
static const char *tls_group_name(uint16_t group)
{
    switch(group) {
        case TLS_NAMED_GROUP_SECP256R1: return "secp256r1";
        case TLS_NAMED_GROUP_SECP384R1: return "secp384r1";
        case TLS_NAMED_GROUP_SECP521R1: return "secp521r1";
        case TLS_NAMED_GROUP_X25519: return "x25519";
        case TLS_NAMED_GROUP_X448: return "x448";
        case TLS_NAMED_GROUP_FFDHE2048: return "ffdhe2048";
        case TLS_NAMED_GROUP_FFDHE3072: return "ffdhe3072";
        case TLS_NAMED_GROUP_FFDHE4096: return "ffdhe4096";
        case TLS_NAMED_GROUP_FFDHE6144: return "ffdhe6144";
        case TLS_NAMED_GROUP_FFDHE8192: return "ffdhe8192";
        case TLS_NAMED_GROUP_MLKEM512: return "mlkem512";
        case TLS_NAMED_GROUP_MLKEM768: return "mlkem768";
        case TLS_NAMED_GROUP_MLKEM1024: return "mlkem1024";
        case TLS_NAMED_GROUP_X25519_MLKEM512: return "x25519_mlkem512";
        case TLS_NAMED_GROUP_X25519_MLKEM768: return "x25519_mlkem768";
        case TLS_NAMED_GROUP_X25519_MLKEM1024: return "x25519_mlkem1024";
        default: return "n/a";
    }
}

/**
 * @brief Get the KEX name from the suite and TLS 1.3 group
 *
 * @param[in] suite The suite to get the KEX name from
 * @param[in] tls13_group The TLS 1.3 group to get the KEX name from
 * @return The KEX name
 */
static const char *tls_kex_name_from_suite(uint16_t suite, uint16_t tls13_group)
{
    if(suite >= 0x1301u && suite <= 0x13FFu) {
        return tls_group_name(tls13_group);
    }
    if(suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384) {
        return "RSA";
    }
    if(suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8) {
        return "DHE_RSA";
    }
    if(suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384) {
        return "ECDHE_RSA";
    }
    if(suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8) {
        return "ECDHE_ECDSA";
    }
    return "unknown";
}

/**
 * @brief Get the bulk cipher name
 *
 * @param[in] suite The suite to get the bulk cipher name from
 * @return The bulk cipher name
 */
static const char *tls_bulk_cipher_name(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            return "3DES-CBC";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
            return "AES-128-CBC";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
            return "AES-256-CBC";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
            return "AES-128-GCM";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            return "AES-256-GCM";
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
            return "AES-128-CCM";
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
            return "AES-256-CCM";
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
            return "AES-128-CCM";
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
            return "AES-128-CCM-8";
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "ChaCha20-Poly1305";
        default:
            return "unknown";
    }
}

/**
 * @brief Get the hash name
 *
 * @param[in] suite The suite to get the hash name from
 * @return The hash name
 */
static const char *tls_hash_name(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            return "SHA-1";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
            return "SHA-256";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            return "SHA-384";
        default:
            return "unknown";
    }
}

/**
 * @brief Parse the format argument
 *
 * @param[in] text The text to parse the format argument from
 * @param[out] format The format to parse the format argument into
 * @return The return code
 */
static int parse_format_arg(const char *text, file_format_t *format)
{
    if(text == NULL || format == NULL) {
        return 0;
    }
    if(STR_CASE_EQ(text, "auto")) {
        *format = FILE_FORMAT_AUTO;
        return 1;
    }
    if(STR_CASE_EQ(text, "pem")) {
        *format = FILE_FORMAT_PEM;
        return 1;
    }
    if(STR_CASE_EQ(text, "der")) {
        *format = FILE_FORMAT_DER;
        return 1;
    }
    return 0;
}

/**
 * @brief Parse the port argument
 *
 * @param[in] text The text to parse the port argument from
 * @param[out] port The port to parse the port argument into
 * @return The return code
 */
static int parse_port_arg(const char *text, uint16_t *port)
{
    char *end = NULL;
    long value;
    if(text == NULL || port == NULL) {
        return 0;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if(errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    if(value < 1 || value > 65535) {
        return 0;
    }
    *port = (uint16_t)value;
    return 1;
}

/**
 * @brief Trim the string in place
 *
 * @param[in] s The string to trim the string in place from
 * @return The trimmed string
 */
static char *trim_in_place(char *s)
{
    char *end;
    while(*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    end = s + strlen(s);
    while(end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return s;
}

/**
 * @brief Parse the cipher token
 *
 * @param[in] token The token to parse the cipher token from
 * @param[out] suite The suite to parse the cipher token into
 * @return The return code
 */
static int parse_cipher_token(const char *token, uint16_t *suite)
{
    uint32_t i;
    if(token == NULL || suite == NULL) {
        return 0;
    }

    if((token[0] == '0') && (token[1] == 'x' || token[1] == 'X')) {
        char *end = NULL;
        unsigned long value = strtoul(token + 2, &end, 16);
        if(end != token + 2 && *end == '\0' && value <= 0xFFFFul) {
            *suite = (uint16_t)value;
            return 1;
        }
    }

    for(i = 0; i < (uint32_t)(sizeof(CIPHER_NAME_TABLE) / sizeof(CIPHER_NAME_TABLE[0])); i++) {
        if(STR_CASE_EQ(token, CIPHER_NAME_TABLE[i].name)) {
            *suite = CIPHER_NAME_TABLE[i].suite;
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Parse the cipher suite list
 *
 * @param[in] arg The argument to parse the cipher suite list from
 * @param[out] out_suites The suites to parse the cipher suite list into
 * @param[out] out_count The count of the suites to parse the cipher suite list into
 * @return The return code
 */
static int parse_cipher_suite_list(const char *arg, uint16_t *out_suites, uint32_t *out_count)
{
    char *copy;
    char *cursor;
    uint32_t count = 0;
    if(arg == NULL || out_suites == NULL || out_count == NULL) {
        return 0;
    }

    copy = (char *)malloc(strlen(arg) + 1U);
    if(copy == NULL) {
        return 0;
    }
    memcpy(copy, arg, strlen(arg) + 1U);

    cursor = copy;
    while(cursor != NULL && *cursor != '\0') {
        char *sep = strchr(cursor, ',');
        char *token;
        uint16_t suite_id;
        if(sep != NULL) {
            *sep = '\0';
        }
        token = trim_in_place(cursor);
        if(*token == '\0') {
            free(copy);
            return 0;
        }
        if(count >= MAX_CIPHER_SUITES) {
            free(copy);
            return 0;
        }
        if(!parse_cipher_token(token, &suite_id)) {
            free(copy);
            return 0;
        }
        out_suites[count++] = suite_id;
        if(sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    free(copy);
    *out_count = count;
    return (count > 0U) ? 1 : 0;
}

static noxtls_return_t load_certificate_with_format(x509_certificate_t *cert, const char *path, file_format_t format);

/**
 * @brief Free the certificate chain buffers
 *
 * @param[in] chain_data The data to free the certificate chain buffers from
 * @param[in] chain_lens The lengths of the certificate chain buffers to free the certificate chain buffers from
 * @param[in] chain_count The count of the certificate chain buffers to free the certificate chain buffers from
 * @return void
 */
static void free_certificate_chain_buffers(uint8_t **chain_data, uint32_t *chain_lens, uint32_t chain_count)
{
    uint32_t i;
    if(chain_data != NULL) {
        for(i = 0; i < chain_count; i++) {
            if(chain_data[i] != NULL) {
                free(chain_data[i]);
            }
        }
        free(chain_data);
    }
    if(chain_lens != NULL) {
        free(chain_lens);
    }
}

/**
 * @brief Load the certificate chain list
 *
 * @param[in] arg The argument to load the certificate chain list from
 * @param[in] format The format to load the certificate chain list from
 * @param[out] out_chain_data The data to load the certificate chain list into
 * @param[out] out_chain_lens The lengths of the certificate chain list to load the certificate chain list into
 * @param[out] out_chain_count The count of the certificate chain list to load the certificate chain list into
 * @return The return code
 */
static int load_certificate_chain_list(const char *arg,
                                       file_format_t format,
                                       uint8_t ***out_chain_data,
                                       uint32_t **out_chain_lens,
                                       uint32_t *out_chain_count)
{
    char *copy = NULL;
    char *cursor = NULL;
    uint8_t **chain_data = NULL;
    uint32_t *chain_lens = NULL;
    uint32_t chain_count = 0;

    if(arg == NULL || out_chain_data == NULL || out_chain_lens == NULL || out_chain_count == NULL) {
        return 0;
    }

    *out_chain_data = NULL;
    *out_chain_lens = NULL;
    *out_chain_count = 0;

    copy = (char *)malloc(strlen(arg) + 1U);
    if(copy == NULL) {
        return 0;
    }
    memcpy(copy, arg, strlen(arg) + 1U);

    chain_data = (uint8_t **)calloc(MAX_CERT_CHAIN_ENTRIES, sizeof(uint8_t *));
    chain_lens = (uint32_t *)calloc(MAX_CERT_CHAIN_ENTRIES, sizeof(uint32_t));
    if(chain_data == NULL || chain_lens == NULL) {
        free(copy);
        free(chain_data);
        free(chain_lens);
        return 0;
    }

    cursor = copy;
    while(cursor != NULL && *cursor != '\0') {
        char *sep = strchr(cursor, ',');
        char *token;
        x509_certificate_t chain_cert;

        if(sep != NULL) {
            *sep = '\0';
        }
        token = trim_in_place(cursor);
        if(*token == '\0' || chain_count >= MAX_CERT_CHAIN_ENTRIES) {
            free(copy);
            free_certificate_chain_buffers(chain_data, chain_lens, chain_count);
            return 0;
        }

        memset(&chain_cert, 0, sizeof(chain_cert));
        noxtls_x509_certificate_init(&chain_cert);
        if(load_certificate_with_format(&chain_cert, token, format) != NOXTLS_RETURN_SUCCESS ||
           chain_cert.raw_data == NULL || chain_cert.raw_data_len == 0U) {
            noxtls_x509_certificate_free(&chain_cert);
            free(copy);
            free_certificate_chain_buffers(chain_data, chain_lens, chain_count);
            return 0;
        }

        chain_data[chain_count] = (uint8_t *)malloc(chain_cert.raw_data_len);
        if(chain_data[chain_count] == NULL) {
            noxtls_x509_certificate_free(&chain_cert);
            free(copy);
            free_certificate_chain_buffers(chain_data, chain_lens, chain_count);
            return 0;
        }
        memcpy(chain_data[chain_count], chain_cert.raw_data, chain_cert.raw_data_len);
        chain_lens[chain_count] = chain_cert.raw_data_len;
        chain_count++;
        noxtls_x509_certificate_free(&chain_cert);

        if(sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    free(copy);
    if(chain_count == 0U) {
        free(chain_data);
        free(chain_lens);
        return 0;
    }

    *out_chain_data = chain_data;
    *out_chain_lens = chain_lens;
    *out_chain_count = chain_count;
    return 1;
}

/**
 * @brief Load the file bytes
 *
 * @param[in] path The path to load the file bytes from
 * @param[out] out_buf The buffer to load the file bytes into
 * @param[out] out_len The length of the buffer to load the file bytes into
 * @return The return code
 */
static noxtls_return_t load_file_bytes(const char *path, uint8_t **out_buf, uint32_t *out_len)
{
    FILE *fp;
    long size;
    uint8_t *buf;
    size_t read_len;
    if(path == NULL || out_buf == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *out_buf = NULL;
    *out_len = 0;

    fp = fopen(path, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    size = ftell(fp);
    if(size <= 0 || size > 0x7FFFFFFF) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    buf = (uint8_t *)malloc((size_t)size);
    if(buf == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    read_len = fread(buf, 1U, (size_t)size, fp);
    fclose(fp);
    if(read_len != (size_t)size) {
        free(buf);
        return NOXTLS_RETURN_FAILED;
    }
    *out_buf = buf;
    *out_len = (uint32_t)size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Load the certificate with format
 *
 * @param[in] cert The certificate to load the certificate with format from
 * @param[in] path The path to load the certificate with format from
 * @param[in] format The format to load the certificate with format from
 * @return The return code
 */
static noxtls_return_t load_certificate_with_format(x509_certificate_t *cert, const char *path, file_format_t format)
{
    noxtls_return_t rc;
    uint8_t *file_data = NULL;
    uint32_t file_len = 0;
    if(cert == NULL || path == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(format == FILE_FORMAT_AUTO) {
        return noxtls_x509_certificate_load_file(cert, path);
    }

    rc = load_file_bytes(path, &file_data, &file_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(format == FILE_FORMAT_PEM) {
        rc = noxtls_x509_certificate_parse_pem(cert, file_data, file_len);
    } else {
        rc = noxtls_x509_certificate_parse_der(cert, file_data, file_len);
    }
    free(file_data);
    return rc;
}

/**
 * @brief Load the private key with format
 *
 * @param[in] key The private key to load the private key with format from
 * @param[in] path The path to load the private key with format from
 * @param[in] format The format to load the private key with format from
 * @return The return code
 */
static noxtls_return_t load_private_key_with_format(x509_private_key_t *key, const char *path, file_format_t format)
{
    noxtls_return_t rc;
    uint8_t *file_data = NULL;
    uint32_t file_len = 0;
    if(key == NULL || path == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(format == FILE_FORMAT_AUTO) {
        return noxtls_x509_private_key_load_file(key, path);
    }

    rc = load_file_bytes(path, &file_data, &file_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(format == FILE_FORMAT_PEM) {
        rc = noxtls_x509_private_key_parse_pem(key, file_data, file_len);
    } else {
        rc = noxtls_x509_private_key_parse_der(key, file_data, file_len);
    }
    free(file_data);
    return rc;
}

/**
 * @brief Parse the hex bytes
 *
 * @param[in] hex The hex to parse the hex bytes from
 * @param[out] out The output to parse the hex bytes into
 * @param[out] out_len The length of the output to parse the hex bytes into
 * @param[in] out_cap The capacity of the output to parse the hex bytes into
 * @return The return code
 */
static int parse_hex_bytes(const char *hex, uint8_t *out, uint16_t *out_len, uint16_t out_cap)
{
    uint16_t i;
    uint16_t nbytes;
    if(hex == NULL || out == NULL || out_len == NULL) {
        return 0;
    }
    if(hex[0] == '\0') {
        return 0;
    }
    if((strlen(hex) % 2U) != 0U) {
        return 0;
    }
    nbytes = (uint16_t)(strlen(hex) / 2U);
    if(nbytes == 0U || nbytes > out_cap) {
        return 0;
    }
    for(i = 0; i < nbytes; i++) {
        unsigned int v;
        char hi = hex[i * 2U];
        char lo = hex[i * 2U + 1U];
        if(!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) {
            return 0;
        }
        if(sscanf(&hex[i * 2U], "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
    }
    *out_len = nbytes;
    return 1;
}

/**
 * @brief Parse the TLS 1.3 PSK mode
 *
 * @param[in] text The text to parse the TLS 1.3 PSK mode from
 * @param[out] mode The mode to parse the TLS 1.3 PSK mode into
 * @return The return code
 */
static int parse_tls13_psk_mode(const char *text, uint8_t *mode)
{
    if(text == NULL || mode == NULL) {
        return 0;
    }
    if(STR_CASE_EQ(text, "psk_ke")) {
        *mode = TLS13_PSK_KE_MODE_PSK_KE;
        return 1;
    }
    if(STR_CASE_EQ(text, "psk_dhe_ke")) {
        *mode = TLS13_PSK_KE_MODE_PSK_DHE_KE;
        return 1;
    }
    return 0;
}

/**
 * @brief Parse the ALPN list
 *
 * @param[in] text The text to parse the ALPN list from
 * @param[out] protocol_bufs The protocol buffers to parse the ALPN list into
 * @param[out] protocol_ptrs The protocol pointers to parse the ALPN list into
 * @param[out] count The count of the protocols to parse the ALPN list into
 * @return The return code
 */
static int parse_alpn_list(const char *text,
                           char protocol_bufs[][MAX_ALPN_PROTOCOL_LEN],
                           const char **protocol_ptrs,
                           uint32_t *count)
{
    char *copy = NULL;
    char *token;
    uint32_t n = 0;
#ifdef _WIN32
    char *next = NULL;
#else
    char *saveptr = NULL;
#endif

    if(text == NULL || protocol_bufs == NULL || protocol_ptrs == NULL || count == NULL) {
        return 0;
    }

    copy = strdup(text);
    if(copy == NULL) {
        return 0;
    }

#ifdef _WIN32
    token = strtok_s(copy, ",", &next);
#else
    token = strtok_r(copy, ",", &saveptr);
#endif
    while(token != NULL) {
        size_t len;
        while(*token == ' ' || *token == '\t') {
            token++;
        }
        len = strlen(token);
        while(len > 0U && (token[len - 1U] == ' ' || token[len - 1U] == '\t')) {
            token[--len] = '\0';
        }
        if(len == 0U || len >= MAX_ALPN_PROTOCOL_LEN || n >= MAX_ALPN_PROTOCOLS) {
            free(copy);
            return 0;
        }
        memcpy(protocol_bufs[n], token, len + 1U);
        protocol_ptrs[n] = protocol_bufs[n];
        n++;
#ifdef _WIN32
        token = strtok_s(NULL, ",", &next);
#else
        token = strtok_r(NULL, ",", &saveptr);
#endif
    }

    free(copy);
    if(n == 0U) {
        return 0;
    }
    *count = n;
    return 1;
}

/**
 * @brief Print the usage
 *
 * @param[in] prog The program to print the usage from
 * @return void
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [port] [options]\n", prog);
    printf("  port                   Listen port (default: %u)\n", (unsigned)DEFAULT_PORT);
    printf("  -if, --interface <ip>  Bind interface IPv4 (default: %s)\n", DEFAULT_BIND_IP);
    printf("  -v                     Enable standard debug output\n");
    printf("  -vv                    Enable full debug output (includes verbose TLS13 traces)\n");
    printf("  --cert <file>          Server certificate file (default: %s)\n", DEFAULT_CERT_FILE);
    printf("  --cert-chain <files>   Optional intermediate cert files (comma-separated)\n");
    printf("  --cert-format <fmt>    Certificate format: auto|pem|der (default: auto)\n");
    printf("  --key <file>           Server private key file (default: %s)\n", DEFAULT_KEY_FILE);
    printf("  --key-format <fmt>     Private key format: auto|pem|der (default: auto)\n");
    printf("  --tls12-cert <file>    Optional RSA cert for TLS 1.2 fallback when primary key is non-RSA\n");
    printf("  --tls12-cert-chain <files> Optional TLS 1.2 intermediate cert files (comma-separated)\n");
    printf("  --tls12-cert-format <fmt> Optional TLS 1.2 cert format: auto|pem|der (default: auto)\n");
    printf("  --tls12-key <file>     Optional RSA key for TLS 1.2 fallback when primary key is non-RSA\n");
    printf("  --tls12-key-format <fmt> Optional TLS 1.2 key format: auto|pem|der (default: auto)\n");
    printf("                         (Unix) If omitted: <dir-of-primary-cert>/tls12_rsa.crt|.key; on Linux also <dir-of-https_server-binary>/tls12_rsa.*\n");
    printf("  --cipher-suites <lst>  Comma-separated allowlist by name or hex id (e.g. TLS_AES_128_GCM_SHA256,0x1303)\n");
    printf("  --alpn <protocols>     Comma-separated ALPN protocols (default: http/1.1)\n");
    printf("  --tls13-psk-id <text>  Optional TLS 1.3 external PSK identity (for interop testing)\n");
    printf("  --tls13-psk-key <hex>  Optional TLS 1.3 external PSK key in hex (without 0x)\n");
    printf("  --tls13-psk-mode <m>   TLS 1.3 PSK mode: psk_ke|psk_dhe_ke (default: psk_dhe_ke)\n");
    printf("  --tls13-ecdsa-matrix-dir <d>  Directory with tlsfuzzer ECDSA matrix PEMs "
           "(prime256v1|secp384r1|secp521r1|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1 .crt/.key); "
           "requires ECDSA primary key\n");
    printf("  --request-client-cert  Request client certificate authentication (mTLS)\n");
    printf("  --require-client-cert  Require client certificate in TLS 1.3 (sends certificate_required if absent)\n");
    printf("  --expect-client-sni <host>  If set, mismatching ClientHello SNI sends unrecognized_name (warning; use with tlsfuzzer --sni)\n");
    printf("  --expect-client-sni-fatal   With --expect-client-sni, send fatal unrecognized_name on mismatch\n");
    printf("  --debug-log <file>     Append noxtls debug output to log file\n");
    printf("  --unified              Use noxtls_tls_connection_t API\n");
    printf("  --disable-tls13        Server negotiates TLS 1.2 only (for tlsfuzzer test_tls13_non_support)\n");
    printf("  --disable-heartbeat    Disable TLS 1.2 RFC 6520 heartbeat extension/records (default)\n");
    printf("  --enable-heartbeat     Enable TLS 1.2 RFC 6520 heartbeat extension/records\n");
    printf("  --version, -V          Print NoxTLS build version and exit\n");
    printf("  --help, -h             Show this help message\n");
    printf("\n");
    printf("Supported private key algorithms: RSA (TLS 1.2/1.3), ECDSA, Ed25519, Ed448 (TLS 1.3)\n");
    printf("Generate an RSA self-signed cert for testing:\n");
    printf("  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj /CN=localhost\n");
}

/**
 * @brief Create the listen socket
 *
 * @param[in] port The port to create the listen socket from
 * @param[in] bind_ip The IP address to create the listen socket from
 * @return The listen socket
 */
static socket_t create_listen_socket(uint16_t port, const char *bind_ip)
{
    socket_t listen_sock;
    struct sockaddr_in addr;
#ifdef _WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(listen_sock == INVALID_SOCKET_VALUE) {
        return INVALID_SOCKET_VALUE;
    }

    {
#ifdef _WIN32
        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(bind_ip == NULL || bind_ip[0] == '\0') {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }
    if(inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }
    addr.sin_port = htons(port);

    if(bind(listen_sock, (struct sockaddr *)&addr, addrlen) != 0) {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }
    if(listen(listen_sock, 5) != 0) {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }
    return listen_sock;
}

/**
 * @brief Configure the client socket timeouts
 *
 * @param[in] sock The socket to configure the client socket timeouts from
 * @return void
 */
static void configure_client_socket_timeouts(socket_t sock)
{
#ifdef _WIN32
    DWORD timeout_ms = (DWORD)CLIENT_IO_TIMEOUT_MS;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, (int)sizeof(timeout_ms));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, (int)sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = (time_t)(CLIENT_IO_TIMEOUT_MS / 1000u);
    tv.tv_usec = (suseconds_t)((CLIENT_IO_TIMEOUT_MS % 1000u) * 1000u);
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

/**
 * @brief Send the HTTPS data
 *
 * @param[in] user_data The user data to send the HTTPS data from
 * @param[in] data The data to send the HTTPS data from
 * @param[in] len The length of the data to send the HTTPS data from
 * @return The return code
 */
static int32_t https_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t *)user_data;
    uint32_t sent_total = 0;
    if(conn == NULL || data == NULL) {
        return -1;
    }
    while(sent_total < len) {
        int chunk = (int)(len - sent_total);
#ifdef _WIN32
        int sent = send(conn->sock, (const char *)data + sent_total, chunk, 0);
#else
        ssize_t sent = send(conn->sock, data + sent_total, (size_t)chunk, 0);
#endif
        if(sent <= 0) {
            return -1;
        }
        sent_total += (uint32_t)sent;
    }
    return (int32_t)sent_total;
}

/**
 * @brief Receive the HTTPS data
 *
 * @param[in] user_data The user data to receive the HTTPS data from
 * @param[out] data The data to receive the HTTPS data from
 * @param[in] len The length of the data to receive the HTTPS data from
 * @return The return code
 */
static int32_t https_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t *)user_data;
    uint32_t recv_total = 0;
    if(conn == NULL || data == NULL) {
        return -1;
    }
    while(recv_total < len) {
        int chunk = (int)(len - recv_total);
#ifdef _WIN32
        int received = recv(conn->sock, (char *)data + recv_total, chunk, 0);
#else
        ssize_t received = recv(conn->sock, data + recv_total, (size_t)chunk, 0);
#endif
        if(received <= 0) {
            return -1;
        }
        recv_total += (uint32_t)received;
    }
    return (int32_t)recv_total;
}

/**
 * @brief Check if the request is likely a plain HTTP request
 *
 * @param[in] sock The socket to check if the request is likely a plain HTTP request from
 * @return 1 if the request is likely a plain HTTP request, 0 otherwise
 */
static int is_likely_plain_http_request(socket_t sock)
{
    uint8_t peek[8];
#ifdef _WIN32
    int received = recv(sock, (char *)peek, (int)sizeof(peek), MSG_PEEK);
#else
    ssize_t received = recv(sock, peek, sizeof(peek), MSG_PEEK);
#endif

    if(received < 4) {
        return 0;
    }

    if(memcmp(peek, "GET ", 4) == 0) return 1;
    if(memcmp(peek, "POST ", 5) == 0) return 1;
    if(memcmp(peek, "HEAD ", 5) == 0) return 1;
    if(memcmp(peek, "PUT ", 4) == 0) return 1;
    if(memcmp(peek, "PATCH ", 6) == 0) return 1;
    if(memcmp(peek, "DELETE ", 7) == 0) return 1;
    if(memcmp(peek, "OPTIONS ", 8) == 0) return 1;
    if(memcmp(peek, "TRACE ", 6) == 0) return 1;
    if(memcmp(peek, "CONNECT ", 8) == 0) return 1;

    return 0;
}

/**
 * @brief Send the HTTPS required response
 *
 * @param[in] sock The socket to send the HTTPS required response from
 * @return void
 */
static void send_https_required_response(socket_t sock)
{
    static const char body[] =
        "This endpoint expects HTTPS (TLS). Use an https:// URL.\n";
    char header[256];
    int header_len;
    uint32_t sent_total = 0;

    header_len = snprintf(header, sizeof(header),
                          "HTTP/1.1 400 Bad Request\r\n"
                          "Content-Type: text/plain; charset=UTF-8\r\n"
                          "Connection: close\r\n"
                          "Content-Length: %u\r\n"
                          "\r\n",
                          (unsigned)sizeof(body) - 1U);
    if(header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        return;
    }

    while(sent_total < (uint32_t)header_len) {
        int chunk = (int)((uint32_t)header_len - sent_total);
#ifdef _WIN32
        int sent = send(sock, (const char *)header + sent_total, chunk, 0);
#else
        ssize_t sent = send(sock, header + sent_total, (size_t)chunk, 0);
#endif
        if(sent <= 0) {
            return;
        }
        sent_total += (uint32_t)sent;
    }

    sent_total = 0;
    while(sent_total < (uint32_t)(sizeof(body) - 1U)) {
        int chunk = (int)((uint32_t)(sizeof(body) - 1U) - sent_total);
#ifdef _WIN32
        int sent = send(sock, body + sent_total, chunk, 0);
#else
        ssize_t sent = send(sock, body + sent_total, (size_t)chunk, 0);
#endif
        if(sent <= 0) {
            return;
        }
        sent_total += (uint32_t)sent;
    }
}

/**
 * @brief Check if the HTTP headers are complete
 *
 * @param[in] buf The buffer to check if the HTTP headers are complete from
 * @param[in] len The length of the buffer to check if the HTTP headers are complete from
 * @return 1 if the HTTP headers are complete, 0 otherwise
 */
static int http_headers_complete(const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    if(buf == NULL || len < 4U) {
        return 0;
    }
    for(i = 0; i + 4U <= len; i++) {
        if(buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return 1;
        }
    }
    /* Accept LF-LF terminator too; tlsfuzzer probes often use "\\n\\n". */
    for(i = 0; i + 2U <= len; i++) {
        if(buf[i] == '\n' && buf[i + 1] == '\n') {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Detect tlsfuzzer test_lengths.py echo probes.
 *
 * Sends non-HTTP probes as A*(n-1)+LF (1..2^14 bytes) or, with
 * max_fragment_length=4096 and length 16384, four segments of 4095x'A'+LF.
 * The script expects the same payload echoed as application data.
 *
 * @param[in] buf Received application data.
 * @param[in] len Length of @p buf in bytes.
 * @return 1 if the buffer matches a lengths echo payload, 0 otherwise
 */
static int https_buf_is_tls_lengths_echo_payload(const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    uint32_t s;
    int all_a_prefix = 1;

    if(buf == NULL || len == 0U) {
        return 0;
    }
    if(len == 1U) {
        return buf[0] == (uint8_t)'\n';
    }
    for(i = 0; i + 1U < len; i++) {
        if(buf[i] != (uint8_t)'A') {
            all_a_prefix = 0;
            break;
        }
    }
    if(all_a_prefix != 0 && buf[len - 1U] == (uint8_t)'\n') {
        return 1;
    }
    if(len != 16384u) {
        return 0;
    }
    for(s = 0U; s < 4U; s++) {
        uint32_t base = s * 4096u;
        for(i = 0; i < 4095u; i++) {
            if(buf[base + i] != (uint8_t)'A') {
                return 0;
            }
        }
        if(buf[base + 4095u] != (uint8_t)'\n') {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Serve one request
 *
 * @param[in] tls_ctx The TLS context to serve the request from
 * @param[in] is_tls13 Whether the request is TLS 1.3
 * @param[in] body The body of the request
 * @param[in] body_len The length of the body of the request
 * @return The return code
 */ 
static int serve_one_request(void *tls_ctx, int is_tls13, const char *body, size_t body_len)
{
    noxtls_return_t rc;
    uint8_t *req_buf = (uint8_t *)malloc(REQUEST_BUFFER_SIZE);
    uint32_t req_len = 0;
    int trigger_server_keyupdate = 0;

    if(req_buf == NULL) {
        return -1;
    }

    while(req_len < REQUEST_BUFFER_SIZE - 1U) {
        uint32_t space = (REQUEST_BUFFER_SIZE - 1U) - req_len;
        if(space == 0U) {
            goto fail;
        }
        uint32_t to_recv = space;
        if(to_recv > REQUEST_READ_CHUNK) {
            to_recv = REQUEST_READ_CHUNK;
        }
        if(is_tls13) {
            rc = noxtls_tls13_recv((tls13_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        } else {
            rc = noxtls_tls12_recv((tls12_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto fail;
        }
        if(to_recv == 0U) {
            if(req_len > 0U) {
                break;
            }
            continue;
        }
        req_len += to_recv;
        if(req_len < REQUEST_BUFFER_SIZE) {
            req_buf[req_len] = '\0';
        }
        if(http_headers_complete(req_buf, req_len)) {
            break;
        }
        if(https_buf_is_tls_lengths_echo_payload(req_buf, req_len)) {
            break;
        }
    }

    if(https_buf_is_tls_lengths_echo_payload(req_buf, req_len) &&
       !http_headers_complete(req_buf, req_len)) {
        noxtls_return_t erc;
        if(is_tls13) {
            erc = noxtls_tls13_send((tls13_context_t *)tls_ctx, req_buf, req_len);
        } else {
            erc = noxtls_tls12_send((tls12_context_t *)tls_ctx, req_buf, req_len);
        }
        free(req_buf);
        return erc == NOXTLS_RETURN_SUCCESS ? 0 : -1;
    }

    if(!http_headers_complete(req_buf, req_len)) {
        goto fail;
    }

    if(is_tls13 && req_len >= 16U && memcmp(req_buf, "GET /keyupdate ", 15U) == 0) {
        trigger_server_keyupdate = 1;
    }
    if(!is_tls13 && req_len >= 18U && memcmp(req_buf, "GET /secure/test ", 17U) == 0) {
        uint8_t reneg_dummy = 0;
        uint32_t reneg_len = 1U;
        tls12_context_t *tls12 = (tls12_context_t *)tls_ctx;
        noxtls_tls12_request_client_auth(tls12, 1);
        rc = noxtls_tls12_send_hello_request(tls12);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto fail;
        }
        rc = noxtls_tls12_recv(tls12, &reneg_dummy, &reneg_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto fail;
        }
    }

    if(trigger_server_keyupdate) {
        rc = noxtls_tls13_send_key_update((tls13_context_t *)tls_ctx, 1U);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto fail;
        }
    }

    {
        char header[HTTP_HEADER_BUFFER_SIZE];
        int header_len = snprintf(header, sizeof(header),
                                         "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: text/html; charset=UTF-8\r\n"
                                         "Connection: close\r\n"
                                         "Content-Length: %zu\r\n"
                                         "\r\n",
                                         body_len);
        if(header_len <= 0 || (size_t)header_len >= sizeof(header)) {
            goto fail;
        }
        if((size_t)header_len + body_len <= (size_t)TLS_MAX_RECORD_SIZE) {
            size_t response_len = (size_t)header_len + body_len;
            uint8_t *response = (uint8_t *)malloc(response_len);
            if(response == NULL) {
                goto fail;
            }
            memcpy(response, header, (size_t)header_len);
            memcpy(response + (size_t)header_len, body, body_len);
            if(is_tls13) {
                rc = noxtls_tls13_send((tls13_context_t *)tls_ctx, response, (uint32_t)response_len);
            } else {
                rc = noxtls_tls12_send((tls12_context_t *)tls_ctx, response, (uint32_t)response_len);
            }
            free(response);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto fail;
            }
        } else {
            if(is_tls13) {
                rc = noxtls_tls13_send((tls13_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
            } else {
                rc = noxtls_tls12_send((tls12_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
            }
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto fail;
            }
            {
                size_t sent = 0;
                while(sent < body_len) {
                    uint32_t chunk = (uint32_t)(body_len - sent);
                    if(chunk > TLS_SEND_CHUNK) {
                        chunk = TLS_SEND_CHUNK;
                    }
                    if(is_tls13) {
                        rc = noxtls_tls13_send((tls13_context_t *)tls_ctx, (const uint8_t *)body + sent, chunk);
                    } else {
                        rc = noxtls_tls12_send((tls12_context_t *)tls_ctx, (const uint8_t *)body + sent, chunk);
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        goto fail;
                    }
                    sent += chunk;
                }
            }
        }
    }

    free(req_buf);
    return 0;
fail:
    free(req_buf);
    return -1;
}

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
/**
 * @brief Serve one request unified
 *
 * @param[in] conn The connection to serve the request from
 * @param[in] body The body of the request
 * @param[in] body_len The length of the body of the request
 * @return The return code
 */
static int serve_one_request_unified(noxtls_tls_connection_t *conn, const char *body, size_t body_len)
{
    noxtls_return_t rc;
    uint8_t *req_buf = (uint8_t *)malloc(REQUEST_BUFFER_SIZE);
    uint32_t req_len = 0;

    if(req_buf == NULL) {
        return -1;
    }

    while(req_len < REQUEST_BUFFER_SIZE - 1U) {
        uint32_t space = (REQUEST_BUFFER_SIZE - 1U) - req_len;
        if(space == 0U) {
            goto fail;
        }
        uint32_t to_recv = space;
        if(to_recv > REQUEST_READ_CHUNK) {
            to_recv = REQUEST_READ_CHUNK;
        }
        rc = noxtls_tls_connection_recv(conn, req_buf + req_len, &to_recv);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto fail;
        }
        if(to_recv == 0U) {
            if(req_len > 0U) {
                break;
            }
            continue;
        }
        req_len += to_recv;
        if(req_len < REQUEST_BUFFER_SIZE) {
            req_buf[req_len] = '\0';
        }
        if(http_headers_complete(req_buf, req_len)) {
            break;
        }
        if(https_buf_is_tls_lengths_echo_payload(req_buf, req_len)) {
            break;
        }
    }

    if(https_buf_is_tls_lengths_echo_payload(req_buf, req_len) &&
       !http_headers_complete(req_buf, req_len)) {
        rc = noxtls_tls_connection_send(conn, req_buf, req_len);
        free(req_buf);
        return rc == NOXTLS_RETURN_SUCCESS ? 0 : -1;
    }

    if(!http_headers_complete(req_buf, req_len)) {
        goto fail;
    }

    {
        char header[HTTP_HEADER_BUFFER_SIZE];
        int header_len = snprintf(header, sizeof(header),
                                         "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: text/html; charset=UTF-8\r\n"
                                         "Connection: close\r\n"
                                         "Content-Length: %zu\r\n"
                                         "\r\n",
                                         body_len);
        if(header_len <= 0 || (size_t)header_len >= sizeof(header)) {
            goto fail;
        }
        if((size_t)header_len + body_len <= (size_t)TLS_MAX_RECORD_SIZE) {
            size_t response_len = (size_t)header_len + body_len;
            uint8_t *response = (uint8_t *)malloc(response_len);
            if(response == NULL) {
                goto fail;
            }
            memcpy(response, header, (size_t)header_len);
            memcpy(response + (size_t)header_len, body, body_len);
            rc = noxtls_tls_connection_send(conn, response, (uint32_t)response_len);
            free(response);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto fail;
            }
        } else {
            rc = noxtls_tls_connection_send(conn, (const uint8_t *)header, (uint32_t)header_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto fail;
            }
            {
                size_t sent = 0;
                while(sent < body_len) {
                    uint32_t chunk = (uint32_t)(body_len - sent);
                    if(chunk > TLS_SEND_CHUNK) {
                        chunk = TLS_SEND_CHUNK;
                    }
                    rc = noxtls_tls_connection_send(conn, (const uint8_t *)body + sent, chunk);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        goto fail;
                    }
                    sent += chunk;
                }
            }
        }
    }
    free(req_buf);
    return 0;
fail:
    free(req_buf);
    return -1;
}
#endif

/**
 * @brief Build the HTTP body
 *
 * @param[in] body_buf The buffer to build the HTTP body into
 * @param[in] body_buf_len The length of the buffer to build the HTTP body into
 * @param[in] tls_version The TLS version to build the HTTP body into
 * @param[in] cipher_suite The cipher suite to build the HTTP body into
 * @param[in] tls13_group The TLS 1.3 group to build the HTTP body into
 * @return The return code
 */
static int build_http_body(char *body_buf,
                                  size_t body_buf_len,
                                  uint16_t tls_version,
                                  uint16_t cipher_suite,
                                  uint16_t tls13_group)
{
    int written;
    if(body_buf == NULL || body_buf_len == 0U) {
        return -1;
    }

    written = snprintf(body_buf, body_buf_len,
                       "<!DOCTYPE html>\n"
                       "<html>\n"
                       "<head><title>NoxTLS HTTPS Server</title></head>\n"
                       "<body>\n"
                       "  <h1>NoxTLS HTTPS Server</h1>\n"
                       "  <p>NoxTLS build version: %s</p>\n"
                       "  <p>Handshake complete. Negotiated algorithm details:</p>\n"
                       "  <ul>\n"
                       "    <li><b>TLS Version:</b> %s</li>\n"
                       "    <li><b>Cipher Suite:</b> %s (0x%04X)</li>\n"
                       "    <li><b>Key Exchange:</b> %s</li>\n"
                       "    <li><b>Bulk Cipher:</b> %s</li>\n"
                       "    <li><b>Handshake Hash:</b> %s</li>\n"
                       "  </ul>\n"
                       "</body>\n"
                       "</html>\n",
                       HTTPS_SERVER_APP_VERSION,
                       tls_version_name(tls_version),
                       tls_cipher_suite_name(cipher_suite),
                       (unsigned)cipher_suite,
                       tls_kex_name_from_suite(cipher_suite, tls13_group),
                       tls_bulk_cipher_name(cipher_suite),
                       tls_hash_name(cipher_suite));

    if(written <= 0 || (size_t)written >= body_buf_len) {
        return -1;
    }
    return written;
}

/**
 * @brief Sync ECC public coordinates from the leaf certificate SPKI.
 *
 * OpenSSL-generated keys can disagree with NoxTLS's d*G reconstruction on some
 * curves (notably secp521r1); peers verify signatures against the certificate
 * public key, not our recomputed Q.
 *
 * @param[in,out] ecc ECC key whose Q coordinates are updated on success.
 * @param[in] leaf Parsed leaf certificate containing the SPKI EC point.
 * @return 1 if Q was synced, 0 if skipped or unsupported
 */
static int https_sync_ecc_public_from_cert(ecc_key_t *ecc, const x509_certificate_t *leaf)
{
    void *pub = NULL;
    uint32_t kt = 0;
    ecc_key_t *ekpub;
    uint32_t sz;

    if(ecc == NULL || ecc->curve == NULL || leaf == NULL) {
        return 0;
    }
    if(noxtls_x509_certificate_get_public_key(leaf, &pub, &kt) != NOXTLS_RETURN_SUCCESS ||
       pub == NULL || kt != 2U) {
        if(pub != NULL) {
            noxtls_ecc_key_free((ecc_key_t *)pub);
            free(pub);
        }
        return 0;
    }
    ekpub = (ecc_key_t *)pub;
    if(ekpub->curve == NULL || ekpub->curve->size != ecc->curve->size) {
        noxtls_ecc_key_free(ekpub);
        free(pub);
        return 0;
    }
    sz = ecc->curve->size;
    memcpy(ecc->Q.x, ekpub->Q.x, sz);
    memcpy(ecc->Q.y, ekpub->Q.y, sz);
    ecc->Q.size = sz;
    noxtls_ecc_key_free(ekpub);
    free(pub);
    return 1;
}

/**
 * @brief Free all loaded TLS 1.3 ECDSA matrix identity slots.
 *
 * @return void
 */
static void https_tls13_ecdsa_matrix_free_all(void)
{
    uint32_t i;

    for(i = 0; i < g_https_tls13_ecdsa_matrix_n; i++) {
        noxtls_ecc_key_free(&g_https_tls13_ecdsa_matrix[i].ecc_key);
        noxtls_x509_certificate_free(&g_https_tls13_ecdsa_matrix[i].cert);
        noxtls_x509_private_key_free(&g_https_tls13_ecdsa_matrix[i].key_pk);
        memset(&g_https_tls13_ecdsa_matrix[i], 0, sizeof(g_https_tls13_ecdsa_matrix[i]));
    }
    g_https_tls13_ecdsa_matrix_n = 0U;
}

/**
 * @brief Load the HTTPS TLS 1.3 ECDSA matrix
 *
 * @param[in] dir The directory to load the HTTPS TLS 1.3 ECDSA matrix from
 * @param[in] cert_fmt The format of the certificate to load the HTTPS TLS 1.3 ECDSA matrix from
 * @param[in] key_fmt The format of the private key to load the HTTPS TLS 1.3 ECDSA matrix from
 * @return The return code
 */
static int https_tls13_ecdsa_matrix_load(const char *dir, file_format_t cert_fmt, file_format_t key_fmt)
{
    static const char *const bases[] = {
        "prime256v1",
        "secp384r1",
        "secp521r1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1"
    };
    uint32_t bi;

    if(dir == NULL || dir[0] == '\0') {
        return 0;
    }

    https_tls13_ecdsa_matrix_free_all();

    for(bi = 0; bi < (uint32_t)(sizeof(bases) / sizeof(bases[0])); bi++) {
        char path_c[512];
        char path_k[512];
        https_tls13_ecdsa_matrix_slot_t *sl;
        int wc;
        int wk;

        if(g_https_tls13_ecdsa_matrix_n >= (uint32_t)(sizeof(g_https_tls13_ecdsa_matrix) /
                                                      sizeof(g_https_tls13_ecdsa_matrix[0]))) {
            break;
        }
        wc = snprintf(path_c, sizeof(path_c), "%s/%s.crt", dir, bases[bi]);
        wk = snprintf(path_k, sizeof(path_k), "%s/%s.key", dir, bases[bi]);
        if(wc <= 0 || (size_t)wc >= sizeof(path_c) || wk <= 0 || (size_t)wk >= sizeof(path_k)) {
            continue;
        }
#ifndef _WIN32
        if(access(path_c, R_OK) != 0 || access(path_k, R_OK) != 0) {
            continue;
        }
#else
        if(_access(path_c, 04) != 0 || _access(path_k, 04) != 0) {
            continue;
        }
#endif
        sl = &g_https_tls13_ecdsa_matrix[g_https_tls13_ecdsa_matrix_n];
        memset(sl, 0, sizeof(*sl));
        noxtls_x509_certificate_init(&sl->cert);
        noxtls_x509_private_key_init(&sl->key_pk);
        if(load_certificate_with_format(&sl->cert, path_c, cert_fmt) != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&sl->cert);
            noxtls_x509_private_key_free(&sl->key_pk);
            memset(sl, 0, sizeof(*sl));
            continue;
        }
        if(load_private_key_with_format(&sl->key_pk, path_k, key_fmt) != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&sl->cert);
            noxtls_x509_private_key_free(&sl->key_pk);
            memset(sl, 0, sizeof(*sl));
            continue;
        }
        if(noxtls_x509_private_key_to_ecc_key(&sl->key_pk, &sl->ecc_key) != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_free(&sl->cert);
            noxtls_x509_private_key_free(&sl->key_pk);
            memset(sl, 0, sizeof(*sl));
            continue;
        }
        if(!https_sync_ecc_public_from_cert(&sl->ecc_key, &sl->cert)) {
            noxtls_ecc_key_free(&sl->ecc_key);
            noxtls_x509_certificate_free(&sl->cert);
            noxtls_x509_private_key_free(&sl->key_pk);
            memset(sl, 0, sizeof(*sl));
            continue;
        }
        noxtls_x509_private_key_free(&sl->key_pk);
        memset(&sl->key_pk, 0, sizeof(sl->key_pk));
        g_https_tls13_ecdsa_matrix_n++;
    }

    if(g_https_tls13_ecdsa_matrix_n == 0U) {
        printf("ERROR: No TLS 1.3 ECDSA matrix material found in '%s' "
               "(expected prime256v1|secp384r1|secp521r1|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1 .crt/.key)\n",
               dir);
        return 0;
    }
    printf("INFO: Loaded %u TLS 1.3 ECDSA matrix identities from %s\n",
           (unsigned)g_https_tls13_ecdsa_matrix_n, dir);
    return 1;
}

/**
 * @brief Configure the ECDSA identities
 *
 * @param[in] ctx The context to configure the ECDSA identities from
 * @param[in] fallback_ecdsa The fallback ECC key to configure the ECDSA identities from
 * @return The return code
 */
static int https_tls13_configure_ecdsa_identities(tls13_context_t *ctx, ecc_key_t *fallback_ecdsa)
{
    uint32_t mi;

    if(ctx == NULL || fallback_ecdsa == NULL) {
        return 0;
    }
    if(g_https_tls13_ecdsa_matrix_n > 0U) {
        for(mi = 0; mi < g_https_tls13_ecdsa_matrix_n; mi++) {
            if(noxtls_tls13_add_server_ecdsa_identity(ctx,
                                                      g_https_tls13_ecdsa_matrix[mi].cert.raw_data,
                                                      g_https_tls13_ecdsa_matrix[mi].cert.raw_data_len,
                                                      &g_https_tls13_ecdsa_matrix[mi].ecc_key) !=
               NOXTLS_RETURN_SUCCESS) {
                return 0;
            }
        }
        return 1;
    }
    noxtls_tls13_set_server_private_ecdsa(ctx, fallback_ecdsa);
    return 1;
}

/**
 * @brief Main function
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The return code
 */
int main(int argc, char **argv)
{
    uint16_t port = DEFAULT_PORT;
    const char *bind_ip = DEFAULT_BIND_IP;
    unsigned char debug_level = 0U;
    const char *cert_file = DEFAULT_CERT_FILE;
    const char *cert_chain_files = NULL;
    const char *key_file = DEFAULT_KEY_FILE;
    const char *tls12_cert_file = NULL;
    const char *tls12_cert_chain_files = NULL;
    const char *tls12_key_file = NULL;
    const char *debug_log_file = NULL;
    file_format_t cert_format = FILE_FORMAT_AUTO;
    file_format_t key_format = FILE_FORMAT_AUTO;
    file_format_t tls12_cert_format = FILE_FORMAT_AUTO;
    file_format_t tls12_key_format = FILE_FORMAT_AUTO;
    uint16_t configured_cipher_suites[MAX_CIPHER_SUITES];
    uint32_t configured_cipher_suite_count = 0;
    char alpn_protocol_bufs[MAX_ALPN_PROTOCOLS][MAX_ALPN_PROTOCOL_LEN];
    const char *alpn_protocol_ptrs[MAX_ALPN_PROTOCOLS];
    uint32_t configured_alpn_count = DEFAULT_ALPN_PROTOCOL_COUNT;
    const char *alpn_list_text = NULL;
    const char *tls13_psk_id_text = NULL;
    const char *tls13_psk_key_hex = NULL;
    const char *tls13_psk_mode_text = "psk_dhe_ke";
    const char *tls13_ecdsa_matrix_dir = NULL;
    uint8_t tls13_psk_id[256];
    uint16_t tls13_psk_id_len = 0;
    uint8_t tls13_psk_key[64];
    uint16_t tls13_psk_key_len = 0;
    uint8_t tls13_psk_mode = TLS13_PSK_KE_MODE_PSK_DHE_KE;
    int tls13_psk_enabled = 0;
    int disable_tls13 = 0;
    int use_unified = 0;
    int request_client_cert = 0;
    int require_client_cert = 0;
    int heartbeat_enabled = 0;
    socket_t listen_sock = INVALID_SOCKET_VALUE;
    x509_certificate_t cert;
    x509_private_key_t server_key_x509;
    x509_certificate_t tls12_cert;
    x509_private_key_t tls12_key_x509;
    x509_certificate_t tls12_pss_cert;
    x509_private_key_t tls12_pss_key_x509;
    rsa_key_t server_rsa_key;
    rsa_key_t tls12_server_rsa_key;
    rsa_key_t tls12_pss_rsa_key;
    ecc_key_t server_ecc_key;
    uint8_t server_ed25519_seed[32];
    uint8_t server_ed448_seed[57];
    server_key_kind_t server_key_kind = SERVER_KEY_KIND_NONE;
    int server_rsa_key_loaded = 0;
    int tls12_server_rsa_key_loaded = 0;
    int tls12_pss_rsa_loaded = 0;
    int server_ecc_key_loaded = 0;
    uint8_t *server_cert = NULL;
    uint32_t server_cert_len = 0;
    uint8_t **server_cert_chain_data = NULL;
    uint32_t *server_cert_chain_lens = NULL;
    const uint8_t **server_cert_chain_ptrs = NULL;
    uint32_t server_cert_chain_count = 0;
    uint8_t *tls12_server_cert = NULL;
    uint32_t tls12_server_cert_len = 0;
    uint8_t **tls12_server_cert_chain_data = NULL;
    uint32_t *tls12_server_cert_chain_lens = NULL;
    const uint8_t **tls12_server_cert_chain_ptrs = NULL;
    uint32_t tls12_server_cert_chain_count = 0;
    int tls12_fallback_enabled = 0;
    int exit_code = 1;
    int i;
    char auto_tls12_cert_buf[512];
    char auto_tls12_key_buf[512];
    char auto_tls12_pss_cert_buf[512];
    char auto_tls12_pss_key_buf[512];
    char expect_client_sni_buf[256];
    const char *expect_client_sni = NULL;
    int expect_client_sni_fatal = 0;

    memset(&cert, 0, sizeof(cert));
    memset(&server_key_x509, 0, sizeof(server_key_x509));
    memset(&tls12_cert, 0, sizeof(tls12_cert));
    memset(&tls12_key_x509, 0, sizeof(tls12_key_x509));
    memset(&server_rsa_key, 0, sizeof(server_rsa_key));
    memset(&tls12_server_rsa_key, 0, sizeof(tls12_server_rsa_key));
    memset(&tls12_pss_rsa_key, 0, sizeof(tls12_pss_rsa_key));
    memset(&server_ecc_key, 0, sizeof(server_ecc_key));
    memset(server_ed25519_seed, 0, sizeof(server_ed25519_seed));
    memset(server_ed448_seed, 0, sizeof(server_ed448_seed));
    memcpy(alpn_protocol_ptrs, DEFAULT_ALPN_PROTOCOLS, sizeof(DEFAULT_ALPN_PROTOCOLS));
    noxtls_x509_certificate_init(&cert);
    noxtls_x509_private_key_init(&server_key_x509);
    noxtls_x509_certificate_init(&tls12_cert);
    noxtls_x509_private_key_init(&tls12_key_x509);
    noxtls_x509_certificate_init(&tls12_pss_cert);
    noxtls_x509_private_key_init(&tls12_pss_key_x509);
    auto_tls12_cert_buf[0] = '\0';
    auto_tls12_key_buf[0] = '\0';
    auto_tls12_pss_cert_buf[0] = '\0';
    auto_tls12_pss_key_buf[0] = '\0';
    expect_client_sni_buf[0] = '\0';

#ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#else
    /*
     * Prevent process termination on client disconnects while writing.
     * Linux send() may raise SIGPIPE unless it is ignored or suppressed.
     */
    signal(SIGPIPE, SIG_IGN);
#endif

    for(i = 1; i < argc; i++) {
        if((strcmp(argv[i], "-if") == 0 || strcmp(argv[i], "--interface") == 0) && i + 1 < argc) {
            bind_ip = argv[++i];
        } else if(strcmp(argv[i], "-v") == 0) {
            if(debug_level < 1U) {
                debug_level = 1U;
            }
        } else if(strcmp(argv[i], "-vv") == 0) {
            debug_level = 2U;
        } else if(strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if(strcmp(argv[i], "--cert-chain") == 0 && i + 1 < argc) {
            cert_chain_files = argv[++i];
        } else if(strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if(strcmp(argv[i], "--tls12-cert") == 0 && i + 1 < argc) {
            tls12_cert_file = argv[++i];
        } else if(strcmp(argv[i], "--tls12-cert-chain") == 0 && i + 1 < argc) {
            tls12_cert_chain_files = argv[++i];
        } else if(strcmp(argv[i], "--tls12-key") == 0 && i + 1 < argc) {
            tls12_key_file = argv[++i];
        } else if(strcmp(argv[i], "--cert-format") == 0 && i + 1 < argc) {
            if(!parse_format_arg(argv[++i], &cert_format)) {
                printf("ERROR: Invalid --cert-format. Use auto|pem|der.\n");
                print_usage(argv[0]);
                goto cleanup;
            }
        } else if(strcmp(argv[i], "--key-format") == 0 && i + 1 < argc) {
            if(!parse_format_arg(argv[++i], &key_format)) {
                printf("ERROR: Invalid --key-format. Use auto|pem|der.\n");
                print_usage(argv[0]);
                goto cleanup;
            }
        } else if(strcmp(argv[i], "--tls12-cert-format") == 0 && i + 1 < argc) {
            if(!parse_format_arg(argv[++i], &tls12_cert_format)) {
                printf("ERROR: Invalid --tls12-cert-format. Use auto|pem|der.\n");
                print_usage(argv[0]);
                goto cleanup;
            }
        } else if(strcmp(argv[i], "--tls12-key-format") == 0 && i + 1 < argc) {
            if(!parse_format_arg(argv[++i], &tls12_key_format)) {
                printf("ERROR: Invalid --tls12-key-format. Use auto|pem|der.\n");
                print_usage(argv[0]);
                goto cleanup;
            }
        } else if(strcmp(argv[i], "--cipher-suites") == 0 && i + 1 < argc) {
            if(!parse_cipher_suite_list(argv[++i], configured_cipher_suites, &configured_cipher_suite_count)) {
                printf("ERROR: Invalid --cipher-suites value.\n");
                print_usage(argv[0]);
                goto cleanup;
            }
        } else if(strcmp(argv[i], "--alpn") == 0 && i + 1 < argc) {
            alpn_list_text = argv[++i];
        } else if(strcmp(argv[i], "--tls13-psk-id") == 0 && i + 1 < argc) {
            tls13_psk_id_text = argv[++i];
        } else if(strcmp(argv[i], "--tls13-psk-key") == 0 && i + 1 < argc) {
            tls13_psk_key_hex = argv[++i];
        } else if(strcmp(argv[i], "--tls13-psk-mode") == 0 && i + 1 < argc) {
            tls13_psk_mode_text = argv[++i];
        } else if(strcmp(argv[i], "--tls13-ecdsa-matrix-dir") == 0 && i + 1 < argc) {
            tls13_ecdsa_matrix_dir = argv[++i];
        } else if(strcmp(argv[i], "--debug-log") == 0 && i + 1 < argc) {
            debug_log_file = argv[++i];
        } else if(strcmp(argv[i], "--unified") == 0) {
            use_unified = 1;
        } else if(strcmp(argv[i], "--disable-tls13") == 0) {
            disable_tls13 = 1;
        } else if(strcmp(argv[i], "--disable-heartbeat") == 0) {
            heartbeat_enabled = 0;
        } else if(strcmp(argv[i], "--enable-heartbeat") == 0) {
            heartbeat_enabled = 1;
        } else if(strcmp(argv[i], "--request-client-cert") == 0) {
            request_client_cert = 1;
        } else if(strcmp(argv[i], "--require-client-cert") == 0) {
            request_client_cert = 1;
            require_client_cert = 1;
        } else if(strcmp(argv[i], "--expect-client-sni") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            size_t vl = strlen(v);
            if(vl == 0U || vl >= sizeof(expect_client_sni_buf)) {
                printf("ERROR: --expect-client-sni must be 1..%u characters\n",
                       (unsigned)(sizeof(expect_client_sni_buf) - 1U));
                print_usage(argv[0]);
                goto cleanup;
            }
            memcpy(expect_client_sni_buf, v, vl + 1U);
            expect_client_sni = expect_client_sni_buf;
        } else if(strcmp(argv[i], "--expect-client-sni-fatal") == 0) {
            expect_client_sni_fatal = 1;
        } else if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit_code = 0;
            goto cleanup;
        } else if(strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            printf("https_server (NoxTLS) %s\n", HTTPS_SERVER_APP_VERSION);
            exit_code = 0;
            goto cleanup;
        } else if(argv[i][0] != '-') {
            if(!parse_port_arg(argv[i], &port)) {
                printf("ERROR: Invalid port '%s'\n", argv[i]);
                print_usage(argv[0]);
                goto cleanup;
            }
        } else {
            printf("ERROR: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            goto cleanup;
        }
    }

    if((tls13_psk_id_text != NULL && tls13_psk_key_hex == NULL) ||
       (tls13_psk_id_text == NULL && tls13_psk_key_hex != NULL)) {
        printf("ERROR: --tls13-psk-id and --tls13-psk-key must be provided together\n");
        goto cleanup;
    }
    if(tls13_psk_id_text != NULL && tls13_psk_key_hex != NULL) {
        size_t id_len = strlen(tls13_psk_id_text);
        if(id_len == 0U || id_len > sizeof(tls13_psk_id)) {
            printf("ERROR: --tls13-psk-id length must be 1..%u bytes\n", (unsigned)sizeof(tls13_psk_id));
            goto cleanup;
        }
        memcpy(tls13_psk_id, tls13_psk_id_text, id_len);
        tls13_psk_id_len = (uint16_t)id_len;
        if(!parse_hex_bytes(tls13_psk_key_hex, tls13_psk_key, &tls13_psk_key_len, (uint16_t)sizeof(tls13_psk_key))) {
            printf("ERROR: --tls13-psk-key must be valid even-length hex and <= %u bytes\n",
                   (unsigned)sizeof(tls13_psk_key));
            goto cleanup;
        }
        if(!parse_tls13_psk_mode(tls13_psk_mode_text, &tls13_psk_mode)) {
            printf("ERROR: --tls13-psk-mode must be psk_ke or psk_dhe_ke\n");
            goto cleanup;
        }
        tls13_psk_enabled = 1;
    }
    if(expect_client_sni_fatal != 0 && expect_client_sni == NULL) {
        printf("ERROR: --expect-client-sni-fatal requires --expect-client-sni\n");
        goto cleanup;
    }
    if(use_unified && request_client_cert) {
        printf("ERROR: client certificate authentication is not supported in --unified mode yet\n");
        goto cleanup;
    }

    if(alpn_list_text != NULL) {
        if(!parse_alpn_list(alpn_list_text,
                            alpn_protocol_bufs,
                            alpn_protocol_ptrs,
                            &configured_alpn_count)) {
            printf("ERROR: Invalid --alpn value. Use comma-separated protocol names.\n");
            goto cleanup;
        }
    }

    noxtls_debug_set_level(debug_level);
    if(debug_log_file != NULL && noxtls_debug_set_log_file(debug_log_file) != 0) {
        printf("ERROR: Failed to open debug log file '%s'\n", debug_log_file);
        goto cleanup;
    }

    if(load_certificate_with_format(&cert, cert_file, cert_format) != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to load certificate '%s' as %s\n", cert_file, format_name(cert_format));
        goto cleanup;
    }
    server_cert = cert.raw_data;
    server_cert_len = cert.raw_data_len;
    if(server_cert == NULL || server_cert_len == 0U) {
        printf("ERROR: Certificate has no DER raw data after parse\n");
        goto cleanup;
    }
    if(cert_chain_files != NULL) {
        uint32_t c;
        if(!load_certificate_chain_list(cert_chain_files,
                                        cert_format,
                                        &server_cert_chain_data,
                                        &server_cert_chain_lens,
                                        &server_cert_chain_count)) {
            printf("ERROR: Failed to load --cert-chain files '%s'\n", cert_chain_files);
            goto cleanup;
        }
        server_cert_chain_ptrs = (const uint8_t **)calloc(server_cert_chain_count, sizeof(uint8_t *));
        if(server_cert_chain_ptrs == NULL) {
            printf("ERROR: Out of memory while preparing --cert-chain\n");
            goto cleanup;
        }
        for(c = 0; c < server_cert_chain_count; c++) {
            server_cert_chain_ptrs[c] = server_cert_chain_data[c];
        }
    }

    if(load_private_key_with_format(&server_key_x509, key_file, key_format) != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to load private key '%s' as %s\n", key_file, format_name(key_format));
        goto cleanup;
    }
    if(server_key_x509.key_type == X509_PRIVATE_KEY_RSA) {
        if(noxtls_x509_private_key_to_rsa_key(&server_key_x509, &server_rsa_key) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: Private key conversion to RSA failed\n");
            goto cleanup;
        }
        server_rsa_key_loaded = 1;
        server_key_kind = SERVER_KEY_KIND_RSA;
    } else if(server_key_x509.key_type == X509_PRIVATE_KEY_ECC) {
        if(noxtls_x509_private_key_to_ecc_key(&server_key_x509, &server_ecc_key) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: Private key conversion to ECDSA key failed\n");
            goto cleanup;
        }
        if(server_ecc_key.curve == NULL) {
            printf("ERROR: ECDSA key has no curve parameters\n");
            goto cleanup;
        }
        if(!https_sync_ecc_public_from_cert(&server_ecc_key, &cert)) {
            printf("ERROR: Failed to sync ECDSA public key from certificate SPKI\n");
            goto cleanup;
        }
        server_ecc_key_loaded = 1;
        server_key_kind = SERVER_KEY_KIND_ECDSA;
    } else if(server_key_x509.key_type == X509_PRIVATE_KEY_ED25519) {
        uint32_t seed_len = 0;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&server_key_x509, &seed_len);
        if(seed == NULL || seed_len != sizeof(server_ed25519_seed)) {
            printf("ERROR: Failed to load Ed25519 seed from private key\n");
            goto cleanup;
        }
        memcpy(server_ed25519_seed, seed, sizeof(server_ed25519_seed));
        server_key_kind = SERVER_KEY_KIND_ED25519;
    } else if(server_key_x509.key_type == X509_PRIVATE_KEY_ED448) {
        uint32_t seed_len = 0;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&server_key_x509, &seed_len);
        if(seed == NULL || seed_len != sizeof(server_ed448_seed)) {
            printf("ERROR: Failed to load Ed448 seed from private key\n");
            goto cleanup;
        }
        memcpy(server_ed448_seed, seed, sizeof(server_ed448_seed));
        server_key_kind = SERVER_KEY_KIND_ED448;
    } else {
        printf("ERROR: Unsupported private key type in '%s'\n", key_file);
        goto cleanup;
    }

    {
        x509_private_key_type_t cert_pk_type;
        if(!https_infer_leaf_cert_public_key_type(&cert, &cert_pk_type)) {
            printf("ERROR: Could not determine public key algorithm from certificate '%s'\n", cert_file);
            goto cleanup;
        }
        if(cert_pk_type != server_key_x509.key_type) {
            printf("ERROR: Certificate '%s' does not match private key '%s'\n", cert_file, key_file);
            printf("       Certificate SPKI: %s; private key: %s.\n",
                   https_x509_private_key_type_name(cert_pk_type),
                   https_x509_private_key_type_name(server_key_x509.key_type));
            printf("       For ECDSA primary + TLS 1.2 DHE_RSA (tlsfuzzer), use the matching EC key (e.g. privkey.pem with cert.pem)\n");
            printf("       and keep tls12_rsa.crt / tls12_rsa.key beside the cert, or pass --tls12-cert / --tls12-key.\n");
            goto cleanup;
        }
    }

    if(tls13_ecdsa_matrix_dir != NULL) {
        if(server_key_kind != SERVER_KEY_KIND_ECDSA) {
            printf("ERROR: --tls13-ecdsa-matrix-dir requires an ECDSA primary private key (--key)\n");
            goto cleanup;
        }
        if(!https_tls13_ecdsa_matrix_load(tls13_ecdsa_matrix_dir, cert_format, key_format)) {
            goto cleanup;
        }
    }

#ifndef _WIN32
        if(tls12_cert_file == NULL && tls12_key_file == NULL &&
           (server_key_kind == SERVER_KEY_KIND_ECDSA ||
            server_key_kind == SERVER_KEY_KIND_ED25519 ||
            server_key_kind == SERVER_KEY_KIND_ED448)) {
            if(https_try_auto_tls12_rsa_paths(cert_file,
                                               auto_tls12_cert_buf, sizeof(auto_tls12_cert_buf),
                                               auto_tls12_key_buf, sizeof(auto_tls12_key_buf))) {
                tls12_cert_file = auto_tls12_cert_buf;
                tls12_key_file = auto_tls12_key_buf;
                printf("INFO: Auto-selected TLS 1.2 RSA fallback cert/key next to primary cert: %s / %s\n",
                       tls12_cert_file, tls12_key_file);
            }
#if defined(__linux__)
            else if(https_try_tls12_rsa_next_to_linux_exe(auto_tls12_cert_buf, sizeof(auto_tls12_cert_buf),
                                                          auto_tls12_key_buf, sizeof(auto_tls12_key_buf))) {
                tls12_cert_file = auto_tls12_cert_buf;
                tls12_key_file = auto_tls12_key_buf;
                printf("INFO: Auto-selected TLS 1.2 RSA fallback cert/key next to https_server binary: %s / %s\n",
                       tls12_cert_file, tls12_key_file);
            }
#endif
        }
#else
        (void)cert_file;
#endif

    if((tls12_cert_file != NULL && tls12_key_file == NULL) ||
       (tls12_cert_file == NULL && tls12_key_file != NULL)) {
        printf("ERROR: --tls12-cert and --tls12-key must be provided together\n");
        goto cleanup;
    }
    if(tls12_cert_chain_files != NULL && tls12_cert_file == NULL) {
        printf("ERROR: --tls12-cert-chain requires --tls12-cert/--tls12-key\n");
        goto cleanup;
    }
    if(tls12_cert_file != NULL && tls12_key_file != NULL) {
        if(load_certificate_with_format(&tls12_cert, tls12_cert_file, tls12_cert_format) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: Failed to load TLS 1.2 fallback certificate '%s' as %s\n",
                   tls12_cert_file, format_name(tls12_cert_format));
            goto cleanup;
        }
        tls12_server_cert = tls12_cert.raw_data;
        tls12_server_cert_len = tls12_cert.raw_data_len;
        if(tls12_server_cert == NULL || tls12_server_cert_len == 0U) {
            printf("ERROR: TLS 1.2 fallback certificate has no DER raw data after parse\n");
            goto cleanup;
        }
        if(tls12_cert_chain_files != NULL) {
            uint32_t c;
            if(!load_certificate_chain_list(tls12_cert_chain_files,
                                            tls12_cert_format,
                                            &tls12_server_cert_chain_data,
                                            &tls12_server_cert_chain_lens,
                                            &tls12_server_cert_chain_count)) {
                printf("ERROR: Failed to load --tls12-cert-chain files '%s'\n", tls12_cert_chain_files);
                goto cleanup;
            }
            tls12_server_cert_chain_ptrs = (const uint8_t **)calloc(tls12_server_cert_chain_count, sizeof(uint8_t *));
            if(tls12_server_cert_chain_ptrs == NULL) {
                printf("ERROR: Out of memory while preparing --tls12-cert-chain\n");
                goto cleanup;
            }
            for(c = 0; c < tls12_server_cert_chain_count; c++) {
                tls12_server_cert_chain_ptrs[c] = tls12_server_cert_chain_data[c];
            }
        }

        if(load_private_key_with_format(&tls12_key_x509, tls12_key_file, tls12_key_format) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: Failed to load TLS 1.2 fallback private key '%s' as %s\n",
                   tls12_key_file, format_name(tls12_key_format));
            goto cleanup;
        }
        if(tls12_key_x509.key_type != X509_PRIVATE_KEY_RSA) {
            printf("ERROR: TLS 1.2 fallback private key must be RSA\n");
            goto cleanup;
        }
        if(noxtls_x509_private_key_to_rsa_key(&tls12_key_x509, &tls12_server_rsa_key) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: TLS 1.2 fallback private key conversion to RSA failed\n");
            goto cleanup;
        }
        tls12_server_rsa_key_loaded = 1;
        tls12_fallback_enabled = 1;
    }

#ifndef _WIN32
    if(https_try_auto_tls12_rsa_pss_paths(cert_file,
                                           auto_tls12_pss_cert_buf, sizeof(auto_tls12_pss_cert_buf),
                                           auto_tls12_pss_key_buf, sizeof(auto_tls12_pss_key_buf))
#if defined(__linux__)
        || https_try_tls12_rsa_pss_next_to_linux_exe(auto_tls12_pss_cert_buf, sizeof(auto_tls12_pss_cert_buf),
                                                     auto_tls12_pss_key_buf, sizeof(auto_tls12_pss_key_buf))
#endif
        ) {
        if(load_certificate_with_format(&tls12_pss_cert, auto_tls12_pss_cert_buf, cert_format) == NOXTLS_RETURN_SUCCESS &&
           tls12_pss_cert.raw_data != NULL && tls12_pss_cert.raw_data_len > 0U &&
           load_private_key_with_format(&tls12_pss_key_x509, auto_tls12_pss_key_buf, key_format) == NOXTLS_RETURN_SUCCESS &&
           tls12_pss_key_x509.key_type == X509_PRIVATE_KEY_RSA &&
           noxtls_x509_private_key_to_rsa_key(&tls12_pss_key_x509, &tls12_pss_rsa_key) == NOXTLS_RETURN_SUCCESS) {
            tls12_pss_rsa_loaded = 1;
            printf("INFO: Optional TLS 1.2 RSA-PSS leaf loaded (rsa_pss_pss_* interop): %s / %s\n",
                   auto_tls12_pss_cert_buf, auto_tls12_pss_key_buf);
        }
    }
#endif

    if(disable_tls13) {
        if(tls13_psk_enabled) {
            printf("ERROR: --disable-tls13 cannot be combined with --tls13-psk-id/--tls13-psk-key\n");
            goto cleanup;
        }
        if(use_unified) {
            printf("ERROR: --disable-tls13 is not supported together with --unified\n");
            goto cleanup;
        }
        if(server_key_kind != SERVER_KEY_KIND_RSA && !tls12_fallback_enabled) {
            printf("ERROR: --disable-tls13 requires TLS 1.2 RSA; use an RSA server key or --tls12-cert/--tls12-key\n");
            goto cleanup;
        }
    }

    listen_sock = create_listen_socket(port, bind_ip);
    if(listen_sock == INVALID_SOCKET_VALUE) {
        printf("ERROR: Failed to create listen socket on %s:%u\n", bind_ip, (unsigned)port);
        goto cleanup;
    }

    printf("HTTPS server (NoxTLS %s) listening on https://%s:%u/\n",
           HTTPS_SERVER_APP_VERSION,
           bind_ip,
           (unsigned)port);
    printf("Certificate: %s (%s)\n", cert_file, format_name(cert_format));
    if(server_cert_chain_count > 0U) {
        printf("Certificate chain: %u intermediate certificate(s)\n", (unsigned)server_cert_chain_count);
    }
    printf("Private key: %s (%s)\n", key_file, format_name(key_format));
    if(debug_level == 1U) {
        printf("Debug mode: -v (standard)\n");
    } else if(debug_level >= 2U) {
        printf("Debug mode: -vv (full)\n");
    }
    if(debug_log_file != NULL) {
        printf("Debug log file: %s\n", debug_log_file);
    }
    printf("Private key algorithm: %s\n", server_key_kind_name(server_key_kind));
    if(server_key_kind != SERVER_KEY_KIND_RSA) {
        if(tls12_fallback_enabled) {
            printf("TLS 1.2 fallback enabled with RSA cert/key: %s / %s\n", tls12_cert_file, tls12_key_file);
            if(tls12_server_cert_chain_count > 0U) {
                printf("TLS 1.2 fallback chain: %u intermediate certificate(s)\n", (unsigned)tls12_server_cert_chain_count);
            }
        } else {
            printf("Non-RSA server keys currently run on TLS 1.3 only in this app path\n");
            printf("HINT: For TLS 1.2 RSA suites (e.g. tlsfuzzer), use --tls12-cert/--tls12-key, "
                   "or tls12_rsa.crt|.key next to --cert, or (Linux) next to the https_server binary.\n");
        }
    }
    if(configured_cipher_suite_count > 0U) {
        printf("Configured ciphersuite allowlist (%u):\n", (unsigned)configured_cipher_suite_count);
        for(i = 0; i < (int)configured_cipher_suite_count; i++) {
            printf("  - %s (0x%04X)\n",
                   tls_cipher_suite_name(configured_cipher_suites[i]),
                   (unsigned)configured_cipher_suites[i]);
        }
    } else {
        printf("Configured ciphersuite allowlist: library defaults\n");
    }
    if(tls13_psk_enabled) {
        printf("TLS 1.3 external PSK enabled: id_len=%u key_len=%u mode=%s\n",
               (unsigned)tls13_psk_id_len,
               (unsigned)tls13_psk_key_len,
               (tls13_psk_mode == TLS13_PSK_KE_MODE_PSK_KE) ? "psk_ke" : "psk_dhe_ke");
    }
    if(disable_tls13) {
        printf("TLS 1.3 disabled: version negotiation falls back to TLS 1.2 when the client offers it\n");
    }
    if(request_client_cert) {
        printf("Client certificate authentication: %s\n",
               require_client_cert ? "required (TLS 1.3)" : "requested");
    }
    printf("Press Ctrl+C to stop.\n\n");

    exit_code = 0;
    for(;;) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif
        socket_t client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
        if(client_sock == INVALID_SOCKET_VALUE) {
            continue;
        }
        configure_client_socket_timeouts(client_sock);

        {
            https_conn_t conn;
            conn.sock = client_sock;

            if(is_likely_plain_http_request(client_sock)) {
                if(debug_level > 0U) {
                    printf("INFO: Plain HTTP request received on HTTPS port; returning 400 hint\n");
                }
                send_https_required_response(client_sock);
                CLOSESOCK(client_sock);
                continue;
            }

            if(server_key_kind != SERVER_KEY_KIND_RSA) {
                if(tls12_fallback_enabled) {
                    tls_context_t base_ctx;
                    tls12_context_t tls12_ctx;
                    tls13_context_t tls13_ctx;
                    uint16_t negotiated_version = 0;
                    noxtls_return_t rc;
                    char body[HTTP_BODY_BUFFER_SIZE];
                    int body_len;
                    uint16_t negotiated_suite = 0;
                    uint16_t tls13_group = 0;

                    if(noxtls_tls_context_init(&base_ctx, TLS_ROLE_SERVER, 0) != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: noxtls_tls_context_init failed\n");
                        CLOSESOCK(client_sock);
                        continue;
                    }
                    noxtls_tls_set_io_callbacks(&base_ctx, https_send_cb, https_recv_cb, &conn);

                    if(noxtls_tls12_context_init(&tls12_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: noxtls_tls12_context_init failed\n");
                        noxtls_tls_context_free(&base_ctx);
                        CLOSESOCK(client_sock);
                        continue;
                    }
                    tls12_ctx.server_cert = tls12_server_cert;
                    tls12_ctx.server_cert_len = tls12_server_cert_len;
                    if(tls12_server_cert_chain_count > 0U) {
                        noxtls_tls12_set_server_certificate_chain(&tls12_ctx,
                                                                  tls12_server_cert_chain_ptrs,
                                                                  tls12_server_cert_chain_lens,
                                                                  tls12_server_cert_chain_count);
                    }
                    noxtls_tls12_set_server_private_rsa(&tls12_ctx, &tls12_server_rsa_key);
                    if(tls12_pss_rsa_loaded) {
                        noxtls_tls12_set_server_rsa_pss_leaf_material(&tls12_ctx,
                                                                      tls12_pss_cert.raw_data,
                                                                      tls12_pss_cert.raw_data_len,
                                                                      &tls12_pss_rsa_key,
                                                                      &tls12_pss_cert);
                    }
                    if(server_key_kind == SERVER_KEY_KIND_ECDSA && server_ecc_key_loaded) {
                        noxtls_tls12_set_server_private_ecdsa(&tls12_ctx, &server_ecc_key);
                        noxtls_tls12_set_server_ecdsa_leaf_certificate(&tls12_ctx, server_cert, server_cert_len);
                    }
                    if(configured_cipher_suite_count > 0U) {
                        noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                              configured_cipher_suites,
                                                              configured_cipher_suite_count);
                    } else {
                        noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                              TLS12_FALLBACK_DEFAULT_SUITES,
                                                              (uint32_t)(sizeof(TLS12_FALLBACK_DEFAULT_SUITES) /
                                                                         sizeof(TLS12_FALLBACK_DEFAULT_SUITES[0])));
                    }
                    if(configured_alpn_count > 0U) {
                        noxtls_tls12_set_server_alpn_protocols(&tls12_ctx,
                                                               alpn_protocol_ptrs,
                                                               configured_alpn_count);
                    }
                    if(request_client_cert) {
                        noxtls_tls12_request_client_auth(&tls12_ctx, 1);
                    }
                    noxtls_tls12_set_heartbeat(&tls12_ctx, heartbeat_enabled);

                    {
                        const int tls13_stack_on = !disable_tls13;
                        if(tls13_stack_on) {
                            if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                                printf("ERROR: noxtls_tls13_context_init failed\n");
                                noxtls_tls12_context_free(&tls12_ctx);
                                noxtls_tls_context_free(&base_ctx);
                                CLOSESOCK(client_sock);
                                continue;
                            }
                            tls13_ctx.server_cert = server_cert;
                            tls13_ctx.server_cert_len = server_cert_len;
                            if(server_cert_chain_count > 0U) {
                                noxtls_tls13_set_server_certificate_chain(&tls13_ctx,
                                                                          server_cert_chain_ptrs,
                                                                          server_cert_chain_lens,
                                                                          server_cert_chain_count);
                            }
                            if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                                if(!https_tls13_configure_ecdsa_identities(&tls13_ctx, &server_ecc_key)) {
                                    printf("ERROR: Failed to configure TLS 1.3 ECDSA credentials\n");
                                    noxtls_tls13_context_free(&tls13_ctx);
                                    noxtls_tls12_context_free(&tls12_ctx);
                                    noxtls_tls_context_free(&base_ctx);
                                    CLOSESOCK(client_sock);
                                    continue;
                                }
                            } else if(server_key_kind == SERVER_KEY_KIND_ED25519) {
                                rc = noxtls_tls13_set_server_private_ed25519(&tls13_ctx, server_ed25519_seed);
                                if(rc != NOXTLS_RETURN_SUCCESS) {
                                    printf("ERROR: Failed to configure Ed25519 server key: %d\n", rc);
                                    noxtls_tls13_context_free(&tls13_ctx);
                                    noxtls_tls12_context_free(&tls12_ctx);
                                    noxtls_tls_context_free(&base_ctx);
                                    CLOSESOCK(client_sock);
                                    continue;
                                }
                            } else if(server_key_kind == SERVER_KEY_KIND_ED448) {
                                rc = noxtls_tls13_set_server_private_ed448(&tls13_ctx, server_ed448_seed);
                                if(rc != NOXTLS_RETURN_SUCCESS) {
                                    printf("ERROR: Failed to configure Ed448 server key: %d\n", rc);
                                    noxtls_tls13_context_free(&tls13_ctx);
                                    noxtls_tls12_context_free(&tls12_ctx);
                                    noxtls_tls_context_free(&base_ctx);
                                    CLOSESOCK(client_sock);
                                    continue;
                                }
                            } else {
                                printf("ERROR: Unsupported server key algorithm selection\n");
                                noxtls_tls13_context_free(&tls13_ctx);
                                noxtls_tls12_context_free(&tls12_ctx);
                                noxtls_tls_context_free(&base_ctx);
                                CLOSESOCK(client_sock);
                                continue;
                            }
                            if(configured_cipher_suite_count > 0U) {
                                noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                                      configured_cipher_suites,
                                                                      configured_cipher_suite_count);
                            }
                            if(configured_alpn_count > 0U) {
                                noxtls_tls13_set_server_alpn_protocols(&tls13_ctx,
                                                                       alpn_protocol_ptrs,
                                                                       configured_alpn_count);
                            }
                            if(request_client_cert) {
                                noxtls_tls13_request_client_auth(&tls13_ctx, 1);
                                if(require_client_cert) {
                                    noxtls_tls13_require_client_auth(&tls13_ctx, 1);
                                }
                            }
                            if(tls13_psk_enabled) {
                                rc = tls13_set_external_psk(&tls13_ctx,
                                                            tls13_psk_id, tls13_psk_id_len,
                                                            tls13_psk_key, tls13_psk_key_len,
                                                            tls13_psk_mode);
                                if(rc != NOXTLS_RETURN_SUCCESS) {
                                    printf("ERROR: Failed to configure TLS 1.3 external PSK: %d\n", rc);
                                    noxtls_tls13_context_free(&tls13_ctx);
                                    noxtls_tls12_context_free(&tls12_ctx);
                                    noxtls_tls_context_free(&base_ctx);
                                    CLOSESOCK(client_sock);
                                    continue;
                                }
                            }
                        }

                        if(expect_client_sni != NULL && expect_client_sni[0] != '\0') {
                            noxtls_tls12_set_server_expected_client_sni(&tls12_ctx, expect_client_sni, expect_client_sni_fatal);
                            if(tls13_stack_on) {
                                noxtls_tls13_set_server_expected_client_sni(&tls13_ctx, expect_client_sni, expect_client_sni_fatal);
                            }
                        }

                        rc = tls_accept_auto(&base_ctx, NULL, NULL, &tls12_ctx,
                                             tls13_stack_on ? &tls13_ctx : NULL, &negotiated_version);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: TLS handshake failed: %d\n", rc);
                            if(tls13_stack_on) {
                                noxtls_tls13_context_free(&tls13_ctx);
                            }
                            noxtls_tls12_context_free(&tls12_ctx);
                            noxtls_tls_context_free(&base_ctx);
                            close_client_socket(client_sock);
                            continue;
                        }

                        if(negotiated_version == TLS_VERSION_1_3) {
                            negotiated_suite = tls13_ctx.cipher_suite;
                            tls13_group = tls13_ctx.selected_kex_group;
                        } else if(negotiated_version == TLS_VERSION_1_2) {
                            negotiated_suite = tls12_ctx.cipher_suite;
                        }
                        printf("TLS handshake complete: version=%s suite=%s (0x%04X)\n",
                               tls_version_name(negotiated_version),
                               tls_cipher_suite_name(negotiated_suite),
                               (unsigned)negotiated_suite);

                        body_len = build_http_body(body,
                                                   sizeof(body),
                                                   negotiated_version,
                                                   negotiated_suite,
                                                   tls13_group);
                        if(body_len <= 0) {
                            printf("ERROR: Failed to build response body\n");
                        } else {
                            int is_tls13 = (negotiated_version == TLS_VERSION_1_3);
                            void *tls_ctx = is_tls13 ? (void *)&tls13_ctx : (void *)&tls12_ctx;
                            if(serve_one_request(tls_ctx, is_tls13, body, (size_t)body_len) != 0) {
                                printf("ERROR: Failed to serve response\n");
                            }
                        }

                        if(negotiated_version == TLS_VERSION_1_3) {
                            noxtls_tls13_close(&tls13_ctx);
                        } else {
                            noxtls_tls12_close(&tls12_ctx);
                        }
                        if(tls13_stack_on) {
                            noxtls_tls13_context_free(&tls13_ctx);
                        }
                        noxtls_tls12_context_free(&tls12_ctx);
                        noxtls_tls_context_free(&base_ctx);
                        close_client_socket(client_sock);
                        continue;
                    }
                } else {
                    tls13_context_t tls13_ctx;
                    noxtls_return_t rc;
                    char body[HTTP_BODY_BUFFER_SIZE];
                    int body_len;
                    uint16_t suite = 0;
                    uint16_t group = 0;

                    if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: noxtls_tls13_context_init failed\n");
                        close_client_socket(client_sock);
                        continue;
                    }
                    noxtls_tls_set_io_callbacks(&tls13_ctx.base.base, https_send_cb, https_recv_cb, &conn);
                    tls13_ctx.server_cert = server_cert;
                    tls13_ctx.server_cert_len = server_cert_len;
                    if(server_cert_chain_count > 0U) {
                        noxtls_tls13_set_server_certificate_chain(&tls13_ctx,
                                                                  server_cert_chain_ptrs,
                                                                  server_cert_chain_lens,
                                                                  server_cert_chain_count);
                    }

                    if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                        if(!https_tls13_configure_ecdsa_identities(&tls13_ctx, &server_ecc_key)) {
                            printf("ERROR: Failed to configure TLS 1.3 ECDSA credentials\n");
                            noxtls_tls13_context_free(&tls13_ctx);
                            close_client_socket(client_sock);
                            continue;
                        }
                    } else if(server_key_kind == SERVER_KEY_KIND_ED25519) {
                        rc = noxtls_tls13_set_server_private_ed25519(&tls13_ctx, server_ed25519_seed);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: Failed to configure Ed25519 server key: %d\n", rc);
                            noxtls_tls13_context_free(&tls13_ctx);
                            close_client_socket(client_sock);
                            continue;
                        }
                    } else if(server_key_kind == SERVER_KEY_KIND_ED448) {
                        rc = noxtls_tls13_set_server_private_ed448(&tls13_ctx, server_ed448_seed);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: Failed to configure Ed448 server key: %d\n", rc);
                            noxtls_tls13_context_free(&tls13_ctx);
                            close_client_socket(client_sock);
                            continue;
                        }
                    } else {
                        printf("ERROR: Unsupported server key algorithm selection\n");
                        noxtls_tls13_context_free(&tls13_ctx);
                        close_client_socket(client_sock);
                        continue;
                    }

                    if(configured_cipher_suite_count > 0U) {
                        noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                              configured_cipher_suites,
                                                              configured_cipher_suite_count);
                    }
                    if(configured_alpn_count > 0U) {
                        noxtls_tls13_set_server_alpn_protocols(&tls13_ctx,
                                                               alpn_protocol_ptrs,
                                                               configured_alpn_count);
                    }
                    if(request_client_cert) {
                        noxtls_tls13_request_client_auth(&tls13_ctx, 1);
                        if(require_client_cert) {
                            noxtls_tls13_require_client_auth(&tls13_ctx, 1);
                        }
                    }
                    if(tls13_psk_enabled) {
                        rc = tls13_set_external_psk(&tls13_ctx,
                                                    tls13_psk_id, tls13_psk_id_len,
                                                    tls13_psk_key, tls13_psk_key_len,
                                                    tls13_psk_mode);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: Failed to configure TLS 1.3 external PSK: %d\n", rc);
                            noxtls_tls13_context_free(&tls13_ctx);
                            close_client_socket(client_sock);
                            continue;
                        }
                    }

                    if(expect_client_sni != NULL && expect_client_sni[0] != '\0') {
                        noxtls_tls13_set_server_expected_client_sni(&tls13_ctx, expect_client_sni, expect_client_sni_fatal);
                    }

                    rc = noxtls_tls13_accept(&tls13_ctx);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: TLS 1.3 handshake failed: %d\n", rc);
                        if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                            printf("HINT: Ensure certificate/key are ECDSA P-256 or P-384 and client supports matching TLS 1.3 signature algorithms\n");
                        }
                        noxtls_tls13_context_free(&tls13_ctx);
                        close_client_socket(client_sock);
                        continue;
                    }

                    suite = tls13_ctx.cipher_suite;
                    group = tls13_ctx.selected_kex_group;
                    printf("TLS handshake complete: version=TLS 1.3 suite=%s (0x%04X)\n",
                           tls_cipher_suite_name(suite),
                           (unsigned)suite);

                    body_len = build_http_body(body, sizeof(body), TLS_VERSION_1_3, suite, group);
                    rc = NOXTLS_RETURN_SUCCESS;
                    if(body_len <= 0) {
                        printf("ERROR: Failed to build response body\n");
                        rc = NOXTLS_RETURN_FAILED;
                    } else if(serve_one_request(&tls13_ctx, 1, body, (size_t)body_len) != 0) {
                        printf("ERROR: Failed to serve response\n");
                        rc = NOXTLS_RETURN_FAILED;
                    }

                    noxtls_tls13_close(&tls13_ctx);
                    noxtls_tls13_context_free(&tls13_ctx);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
#ifndef _WIN32
                        usleep(100000);
#endif
                    }
                    close_client_socket(client_sock);
                    continue;
                }
            }

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
            if(use_unified) {
                noxtls_tls_connection_t uconn;
                noxtls_return_t rc = noxtls_tls_connection_init(&uconn, TLS_ROLE_SERVER);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: noxtls_tls_connection_init failed\n");
                    CLOSESOCK(client_sock);
                    continue;
                }
                noxtls_tls_connection_set_io_callbacks(&uconn, https_send_cb, https_recv_cb, &conn);
                noxtls_tls_connection_set_server_cert(&uconn, server_cert, server_cert_len);
                if(server_cert_chain_count > 0U) {
                    noxtls_tls_connection_set_server_cert_chain(&uconn,
                                                                server_cert_chain_ptrs,
                                                                server_cert_chain_lens,
                                                                server_cert_chain_count);
                }
                noxtls_tls_connection_set_server_private_key(&uconn, &server_rsa_key);
                if(configured_cipher_suite_count > 0U) {
                    noxtls_tls_connection_set_server_cipher_suites(&uconn,
                                                                   configured_cipher_suites,
                                                                   configured_cipher_suite_count);
                } else {
                    noxtls_tls_connection_set_server_cipher_suites(&uconn,
                                                                   TLS12_FALLBACK_DEFAULT_SUITES,
                                                                   (uint32_t)(sizeof(TLS12_FALLBACK_DEFAULT_SUITES) /
                                                                              sizeof(TLS12_FALLBACK_DEFAULT_SUITES[0])));
                }
                if(configured_alpn_count > 0U) {
                    noxtls_tls_connection_set_server_alpn_protocols(&uconn,
                                                                    alpn_protocol_ptrs,
                                                                    configured_alpn_count);
                }

                rc = noxtls_tls_connection_accept(&uconn);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: TLS handshake failed (unified): %d\n", rc);
                    noxtls_tls_connection_free(&uconn);
                    close_client_socket(client_sock);
                    continue;
                }

                {
                    uint16_t ver = noxtls_tls_connection_get_version(&uconn);
                    uint16_t suite = 0;
                    uint16_t group = 0;
                    char body[HTTP_BODY_BUFFER_SIZE];
                    int body_len;
                    if(ver == TLS_VERSION_1_3) {
                        suite = uconn.u.tls13.cipher_suite;
                        group = uconn.u.tls13.selected_kex_group;
                    } else if(ver == TLS_VERSION_1_2) {
                        suite = uconn.u.tls12.cipher_suite;
                    }
                    printf("TLS handshake complete (unified): version=%s suite=%s (0x%04X)\n",
                           tls_version_name(ver),
                           tls_cipher_suite_name(suite),
                           (unsigned)suite);
                    body_len = build_http_body(body, sizeof(body), ver, suite, group);
                    if(body_len <= 0 || serve_one_request_unified(&uconn, body, (size_t)body_len) != 0) {
                        printf("ERROR: Failed to serve response\n");
                    }
                }

                noxtls_tls_connection_close(&uconn);
                noxtls_tls_connection_free(&uconn);
                close_client_socket(client_sock);
                continue;
            }
#endif

            {
                tls_context_t base_ctx;
                tls12_context_t tls12_ctx;
                tls13_context_t tls13_ctx;
                uint16_t negotiated_version = 0;
                noxtls_return_t rc;
                char body[HTTP_BODY_BUFFER_SIZE];
                int body_len;
                uint16_t negotiated_suite = 0;
                uint16_t tls13_group = 0;

                if(noxtls_tls_context_init(&base_ctx, TLS_ROLE_SERVER, 0) != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: noxtls_tls_context_init failed\n");
                    CLOSESOCK(client_sock);
                    continue;
                }
                noxtls_tls_set_io_callbacks(&base_ctx, https_send_cb, https_recv_cb, &conn);

                if(noxtls_tls12_context_init(&tls12_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: noxtls_tls12_context_init failed\n");
                    noxtls_tls_context_free(&base_ctx);
                    CLOSESOCK(client_sock);
                    continue;
                }
                tls12_ctx.server_cert = server_cert;
                tls12_ctx.server_cert_len = server_cert_len;
                if(server_cert_chain_count > 0U) {
                    noxtls_tls12_set_server_certificate_chain(&tls12_ctx,
                                                              server_cert_chain_ptrs,
                                                              server_cert_chain_lens,
                                                              server_cert_chain_count);
                }
                noxtls_tls12_set_server_private_rsa(&tls12_ctx, &server_rsa_key);
                if(tls12_pss_rsa_loaded) {
                    noxtls_tls12_set_server_rsa_pss_leaf_material(&tls12_ctx,
                                                                  tls12_pss_cert.raw_data,
                                                                  tls12_pss_cert.raw_data_len,
                                                                  &tls12_pss_rsa_key,
                                                                  &tls12_pss_cert);
                }
                if(configured_cipher_suite_count > 0U) {
                    noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                          configured_cipher_suites,
                                                          configured_cipher_suite_count);
                } else {
                    noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                          TLS12_FALLBACK_DEFAULT_SUITES,
                                                          (uint32_t)(sizeof(TLS12_FALLBACK_DEFAULT_SUITES) /
                                                                     sizeof(TLS12_FALLBACK_DEFAULT_SUITES[0])));
                }
                if(configured_alpn_count > 0U) {
                    noxtls_tls12_set_server_alpn_protocols(&tls12_ctx,
                                                           alpn_protocol_ptrs,
                                                           configured_alpn_count);
                }
                if(request_client_cert) {
                    noxtls_tls12_request_client_auth(&tls12_ctx, 1);
                }
                noxtls_tls12_set_heartbeat(&tls12_ctx, heartbeat_enabled);

                {
                    const int tls13_stack_on = !disable_tls13;
                    if(tls13_stack_on) {
                        if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: noxtls_tls13_context_init failed\n");
                            noxtls_tls12_context_free(&tls12_ctx);
                            noxtls_tls_context_free(&base_ctx);
                            CLOSESOCK(client_sock);
                            continue;
                        }
                        tls13_ctx.server_cert = server_cert;
                        tls13_ctx.server_cert_len = server_cert_len;
                        if(server_cert_chain_count > 0U) {
                            noxtls_tls13_set_server_certificate_chain(&tls13_ctx,
                                                                      server_cert_chain_ptrs,
                                                                      server_cert_chain_lens,
                                                                      server_cert_chain_count);
                        }
                        noxtls_tls13_set_server_private_rsa(&tls13_ctx, &server_rsa_key);
                        if(configured_cipher_suite_count > 0U) {
                            noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                                  configured_cipher_suites,
                                                                  configured_cipher_suite_count);
                        }
                        if(configured_alpn_count > 0U) {
                            noxtls_tls13_set_server_alpn_protocols(&tls13_ctx,
                                                                   alpn_protocol_ptrs,
                                                                   configured_alpn_count);
                        }
                        if(request_client_cert) {
                            noxtls_tls13_request_client_auth(&tls13_ctx, 1);
                            if(require_client_cert) {
                                noxtls_tls13_require_client_auth(&tls13_ctx, 1);
                            }
                        }
                        if(tls13_psk_enabled) {
                            rc = tls13_set_external_psk(&tls13_ctx,
                                                        tls13_psk_id, tls13_psk_id_len,
                                                        tls13_psk_key, tls13_psk_key_len,
                                                        tls13_psk_mode);
                            if(rc != NOXTLS_RETURN_SUCCESS) {
                                printf("ERROR: Failed to configure TLS 1.3 external PSK: %d\n", rc);
                                noxtls_tls13_context_free(&tls13_ctx);
                                noxtls_tls12_context_free(&tls12_ctx);
                                noxtls_tls_context_free(&base_ctx);
                                CLOSESOCK(client_sock);
                                continue;
                            }
                        }
                    }

                    if(expect_client_sni != NULL && expect_client_sni[0] != '\0') {
                        noxtls_tls12_set_server_expected_client_sni(&tls12_ctx, expect_client_sni, expect_client_sni_fatal);
                        if(tls13_stack_on) {
                            noxtls_tls13_set_server_expected_client_sni(&tls13_ctx, expect_client_sni, expect_client_sni_fatal);
                        }
                    }

                    rc = tls_accept_auto(&base_ctx, NULL, NULL, &tls12_ctx,
                                         tls13_stack_on ? &tls13_ctx : NULL, &negotiated_version);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: TLS handshake failed: %d\n", rc);
                        if(tls13_stack_on) {
                            noxtls_tls13_context_free(&tls13_ctx);
                        }
                        noxtls_tls12_context_free(&tls12_ctx);
                        noxtls_tls_context_free(&base_ctx);
                        close_client_socket(client_sock);
                        continue;
                    }

                    if(negotiated_version == TLS_VERSION_1_3) {
                        negotiated_suite = tls13_ctx.cipher_suite;
                        tls13_group = tls13_ctx.selected_kex_group;
                    } else if(negotiated_version == TLS_VERSION_1_2) {
                        negotiated_suite = tls12_ctx.cipher_suite;
                    }
                    printf("TLS handshake complete: version=%s suite=%s (0x%04X)\n",
                           tls_version_name(negotiated_version),
                           tls_cipher_suite_name(negotiated_suite),
                           (unsigned)negotiated_suite);

                    body_len = build_http_body(body,
                                               sizeof(body),
                                               negotiated_version,
                                               negotiated_suite,
                                               tls13_group);
                    if(body_len <= 0) {
                        printf("ERROR: Failed to build response body\n");
                    } else {
                        int is_tls13 = (negotiated_version == TLS_VERSION_1_3);
                        void *tls_ctx = is_tls13 ? (void *)&tls13_ctx : (void *)&tls12_ctx;
                        if(serve_one_request(tls_ctx, is_tls13, body, (size_t)body_len) != 0) {
                            printf("ERROR: Failed to serve response\n");
                        }
                    }

                    if(negotiated_version == TLS_VERSION_1_3) {
                        noxtls_tls13_close(&tls13_ctx);
                    } else {
                        noxtls_tls12_close(&tls12_ctx);
                    }
                    if(tls13_stack_on) {
                        noxtls_tls13_context_free(&tls13_ctx);
                    }
                    noxtls_tls12_context_free(&tls12_ctx);
                    noxtls_tls_context_free(&base_ctx);
                    close_client_socket(client_sock);
                }
            }
        }
    }

cleanup:
    https_tls13_ecdsa_matrix_free_all();
    noxtls_debug_set_log_file(NULL);
    if(listen_sock != INVALID_SOCKET_VALUE) {
        CLOSESOCK(listen_sock);
    }
    noxtls_x509_certificate_free(&cert);
    noxtls_x509_private_key_free(&server_key_x509);
    noxtls_x509_certificate_free(&tls12_cert);
    noxtls_x509_private_key_free(&tls12_key_x509);
    noxtls_x509_certificate_free(&tls12_pss_cert);
    noxtls_x509_private_key_free(&tls12_pss_key_x509);
    if(server_cert_chain_ptrs != NULL) {
        free((void *)server_cert_chain_ptrs);
    }
    if(tls12_server_cert_chain_ptrs != NULL) {
        free((void *)tls12_server_cert_chain_ptrs);
    }
    free_certificate_chain_buffers(server_cert_chain_data, server_cert_chain_lens, server_cert_chain_count);
    free_certificate_chain_buffers(tls12_server_cert_chain_data, tls12_server_cert_chain_lens, tls12_server_cert_chain_count);
    if(server_rsa_key_loaded) {
        noxtls_rsa_key_free(&server_rsa_key);
    }
    if(tls12_server_rsa_key_loaded) {
        noxtls_rsa_key_free(&tls12_server_rsa_key);
    }
    if(tls12_pss_rsa_loaded) {
        noxtls_rsa_key_free(&tls12_pss_rsa_key);
    }
    if(server_ecc_key_loaded) {
        noxtls_ecc_key_free(&server_ecc_key);
    }
    memset(server_ed25519_seed, 0, sizeof(server_ed25519_seed));
    memset(server_ed448_seed, 0, sizeof(server_ed448_seed));
#ifdef _WIN32
    WSACleanup();
#endif
    return exit_code;
}
