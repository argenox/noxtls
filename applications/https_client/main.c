/*
* This file is part of the NoxTLS Library.
*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Simple HTTPS client using NoxTLS TLS library.
 */
/**
 * @file main.c
 * @brief Simple HTTPS client using the NoxTLS TLS library.
 * @defgroup noxtls_app_https_client HTTPS client
 * @details
 * Parameters: URL (e.g. https://example.com/), optional port, optional tls12|tls13|auto,
 * optional keylog or tlsdump path. Port overrides URL port; tls12/tls13/auto selects TLS version.
 * @example
 * https_client https://example.com/
 * https_client https://example.com/ 443
 * https_client https://example.com/ 443 tls13
 * https_client https://example.com/ tls12
 * https_client https://example.com/ 443 tls13 keylog=/tmp/keylog.txt
 */

/* MUST be the FIRST #include: app-local noxtls_config.h (project policy)
 * MSVC searches the directory of the including header first for "..."
 * style includes; if a library header pulls in "noxtls_config.h" before
 * this app does, the top-level config wins. Hoisting our local one
 * here ensures _NOXTLS_CONFIG_H_ is set from THIS file. */
#include "noxtls_config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define CLOSESOCK close
#endif

#include "noxtls_common.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#include "noxtls-lib/certs/noxtls_x509.h"

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
 * @brief Free the workspace (no-op; arena is reset in bulk).
 *
 * @param[in] p The pointer to the workspace to free
 * @return void
 */
static void app_workspace_free(void *p) { (void)p; }

/**
 * @brief Reset the workspace and wipe allocated bytes.
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

typedef struct {
    socket_t sock;
} https_conn_t;

/**
 * @brief Print usage information and examples.
 *
 * @param[in] prog Program name (argv[0])
 * @return void
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s <https://host[:port]/path> [port] [tls12|tls13|auto] [--ca <ca_cert.pem|der>] [keylog=<path>|--keylog <path>] [tlsdump=<path>|--tlsdump <path>]\n", prog);
    printf("Example: %s https://example.com/\n", prog);
    printf("Example: %s https://example.com/ 443\n", prog);
    printf("Example: %s https://example.com/ 443 tls13\n", prog);
    printf("Example: %s https://example.com/ tls12\n", prog);
    printf("Example: %s https://example.com/ 443 tls13 --ca ./root_ca.pem\n", prog);
    printf("Example: %s https://example.com/ 443 tls13 keylog=c:/temp/tls_keylog.txt\n", prog);
    printf("Example: %s https://example.com/ 443 tls13 tlsdump=c:/temp/tls_records.txt\n", prog);
}

/**
 * @brief Load one CA certificate into the global trust store.
 * @param ca_file Path to DER/PEM certificate file.
 * @return NOXTLS_RETURN_SUCCESS on success, failure code otherwise.
 */
static noxtls_return_t https_configure_trust_store(const char *ca_file)
{
    noxtls_return_t rc;
    x509_certificate_t ca_cert;
    x509_certificate_chain_t trust_chain;

    if(ca_file == NULL || ca_file[0] == '\0') {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_x509_certificate_init(&ca_cert);
    rc = noxtls_x509_certificate_load_file(&ca_cert, ca_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(&ca_cert);
        return rc;
    }

    rc = noxtls_x509_certificate_chain_init(&trust_chain);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(&ca_cert);
        return rc;
    }

    rc = noxtls_x509_certificate_chain_add(&trust_chain, &ca_cert);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_trust_store_set(&trust_chain);
    }

    noxtls_x509_certificate_chain_free(&trust_chain);
    noxtls_x509_certificate_free(&ca_cert);
    return rc;
}

/**
 * @brief Test whether a string contains only decimal digits.
 *
 * @param[in] s String to test
 * @return 1 if @p s is non-empty and all digits, 0 otherwise
 */
static int is_number(const char *s)
{
    if(s == NULL || *s == '\0') {
        return 0;
    }
    while(*s) {
        if(*s < '0' || *s > '9') {
            return 0;
        }
        s++;
    }
    return 1;
}

typedef enum {
    TLS_MODE_1_2 = 0,
    TLS_MODE_1_3,
    TLS_MODE_AUTO
} tls_mode_t;

/**
 * @brief Parse an http(s) URL into host, path, and port.
 *
 * Accepts https:// or http:// prefixes; http:// is treated as HTTPS.
 * Default port is 443 when omitted.
 *
 * @param[in] url Input URL
 * @param[out] host Buffer for hostname
 * @param[in] host_len Size of @p host
 * @param[out] path Buffer for request path
 * @param[in] path_len Size of @p path
 * @param[out] port Parsed or default port number
 * @return 0 on success, -1 on parse error
 */
static int parse_url(const char *url, char *host, size_t host_len,
                     char *path, size_t path_len, uint16_t *port)
{
    const char *p = url;
    const char *host_start;
    const char *host_end;
    const char *path_start;

    if(url == NULL || host == NULL || path == NULL || port == NULL) {
        return -1;
    }

    if(strncmp(p, "https://", 8) == 0) {
        p += 8;
    } else if(strncmp(p, "http://", 7) == 0) {
        /* Force HTTPS even if http:// is provided */
        p += 7;
    }

    host_start = p;
    while(*p && *p != '/' && *p != ':') {
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

    *port = 443;
    if(*p == ':') {
        const char *colon;
        p++;
        colon = p;
        while(*p && *p != '/') {
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
        size_t path_start_len = strlen(path_start);
        if(path_start_len >= path_len) {
            return -1;
        }
        memcpy(path, path_start, path_start_len);
        path[path_start_len] = '\0';
    }

    return 0;
}

/**
 * @brief Open a TCP connection to @p host on @p port.
 *
 * @param[in] host Hostname or IP address
 * @param[in] port TCP port number
 * @param[out] out_sock Connected socket on success
 * @return 0 on success, -1 on failure
 */
static int connect_tcp(const char *host, uint16_t port, socket_t *out_sock)
{
    char port_str[8];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    socket_t sock = INVALID_SOCKET;

    if(host == NULL || out_sock == NULL) {
        return -1;
    }

    snprintf(port_str, sizeof(port_str), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if(getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

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
 * @brief TLS send callback; writes data to the client socket.
 *
 * @param[in] user_data https_conn_t pointer with connected socket
 * @param[in] data Bytes to send
 * @param[in] len Number of bytes to send
 * @return Number of bytes sent, or -1 on error
 */
static int32_t https_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t*)user_data;
    uint32_t sent_total = 0;

    if(conn == NULL || data == NULL) {
        return -1;
    }

    while(sent_total < len) {
        int chunk = (int)(len - sent_total);
        int sent = (int)send(conn->sock, (const char*)data + sent_total, chunk, 0);
        if(sent <= 0) {
            return -1;
        }
        sent_total += (uint32_t)sent;
    }

    return (int32_t)sent_total;
}

/**
 * @brief TLS receive callback; reads data from the client socket.
 *
 * @param[in] user_data https_conn_t pointer with connected socket
 * @param[out] data Buffer for received bytes
 * @param[in] len Number of bytes to receive
 * @return Number of bytes received, or -1 on error
 */
static int32_t https_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t*)user_data;
    uint32_t recv_total = 0;

    if(conn == NULL || data == NULL) {
        return -1;
    }

    while(recv_total < len) {
        int chunk = (int)(len - recv_total);
        int received = (int)recv(conn->sock, (char*)data + recv_total, chunk, 0);
        if(received <= 0) {
            return -1;
        }
        recv_total += (uint32_t)received;
    }

    return (int32_t)recv_total;
}

/**
 * @brief HTTPS client entry point; connects, handshakes, and fetches a URL.
 *
 * @param[in] argc Argument count
 * @param[in] argv Command-line arguments (URL, optional port, TLS mode, options)
 * @return 0 on success, 1 on error
 */
int main(int argc, char **argv)
{
    char host[256];
    char path[512];
    uint16_t port = 443;
    socket_t sock = INVALID_SOCKET;
    https_conn_t conn;
    tls12_context_t tls12_ctx;
    tls13_context_t tls13_ctx;
    tls_mode_t tls_mode = TLS_MODE_1_2;
    tls_mode_t active_mode = TLS_MODE_1_2;
    const char *ca_file = NULL;
    int trust_store_configured = 0;
    noxtls_return_t rc;

#ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    if(argc < 2) {
        print_usage(argv[0]);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if(parse_url(argv[1], host, sizeof(host), path, sizeof(path), &port) != 0) {
        printf("ERROR: Invalid URL\n");
        print_usage(argv[0]);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    if(argc >= 3) {
        if(is_number(argv[2])) {
            uint16_t override_port = (uint16_t)atoi(argv[2]);
            if(override_port == 0) {
                printf("ERROR: Invalid port override\n");
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            port = override_port;
            if(argc >= 4) {
                if(strcmp(argv[3], "tls13") == 0) {
                    tls_mode = TLS_MODE_1_3;
                } else if(strcmp(argv[3], "auto") == 0) {
                    tls_mode = TLS_MODE_AUTO;
                } else if(strcmp(argv[3], "tls12") == 0) {
                    tls_mode = TLS_MODE_1_2;
                } else {
                    printf("ERROR: Invalid TLS mode (use tls12|tls13|auto)\n");
#ifdef _WIN32
                    WSACleanup();
#endif
                    return 1;
                }
            }
        } else {
            if(strcmp(argv[2], "tls13") == 0) {
                tls_mode = TLS_MODE_1_3;
            } else if(strcmp(argv[2], "auto") == 0) {
                tls_mode = TLS_MODE_AUTO;
            } else if(strcmp(argv[2], "tls12") == 0) {
                tls_mode = TLS_MODE_1_2;
            } else {
                printf("ERROR: Invalid TLS mode (use tls12|tls13|auto)\n");
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
        }
    }

    for(int i = 2; i < argc; i++) {
        if(strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca_file = argv[i + 1];
            i++;
        } else if(strncmp(argv[i], "keylog=", 7) == 0) {
            noxtls_tls13_set_keylog_file(argv[i] + 7);
        } else if(strcmp(argv[i], "--keylog") == 0 && i + 1 < argc) {
            noxtls_tls13_set_keylog_file(argv[i + 1]);
            i++;
        } else if(strncmp(argv[i], "tlsdump=", 8) == 0) {
            noxtls_tls_set_record_dump_file(argv[i] + 8);
        } else if(strcmp(argv[i], "--tlsdump") == 0 && i + 1 < argc) {
            noxtls_tls_set_record_dump_file(argv[i + 1]);
            i++;
        }
    }

    if(ca_file == NULL) {
        if(strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0) {
            ca_file = "server.crt";
        }
    }
    if(ca_file == NULL) {
        printf("ERROR: No trust anchor configured. Use --ca <ca_cert.pem|der>.\n");
        printf("       For localhost demos, place server.crt next to the executable or pass --ca explicitly.\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    rc = https_configure_trust_store(ca_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to load trust anchor from '%s': %d\n", ca_file, rc);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    trust_store_configured = 1;

    printf("Connecting to %s:%u%s\n", host, port, path);
    if(connect_tcp(host, port, &sock) != 0) {
        printf("ERROR: Failed to connect to host\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    conn.sock = sock;

    printf("Starting TLS handshake (mode=%s)...\n",
           (tls_mode == TLS_MODE_1_3) ? "tls13" :
           (tls_mode == TLS_MODE_AUTO) ? "auto" : "tls12");
    if(tls_mode == TLS_MODE_1_3 || tls_mode == TLS_MODE_AUTO) {
        printf("Attempting TLS 1.3...\n");
        rc = noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: noxtls_tls13_context_init failed: %d\n", rc);
            if(trust_store_configured) {
                noxtls_x509_trust_store_clear();
            }
            CLOSESOCK(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        tls13_ctx.server_name = host;
        tls13_ctx.server_name_len = (uint16_t)strlen(host);

        rc = noxtls_tls_set_io_callbacks(&tls13_ctx.base.base, https_send_cb, https_recv_cb, &conn);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: noxtls_tls_set_io_callbacks failed (tls13): %d\n", rc);
            noxtls_tls13_context_free(&tls13_ctx);
            if(trust_store_configured) {
                noxtls_x509_trust_store_clear();
            }
            CLOSESOCK(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        rc = noxtls_tls13_connect(&tls13_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("WARNING: TLS 1.3 handshake failed: %d\n", rc);
            noxtls_tls13_context_free(&tls13_ctx);
            if(tls_mode == TLS_MODE_1_3) {
                if(trust_store_configured) {
                    noxtls_x509_trust_store_clear();
                }
                CLOSESOCK(sock);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            /* Auto fallback to TLS 1.2 */
            printf("Falling back to TLS 1.2...\n");
            active_mode = TLS_MODE_1_2;
        } else {
            active_mode = TLS_MODE_1_3;
        }
    }

    if(active_mode == TLS_MODE_1_2) {
        printf("Attempting TLS 1.2...\n");
        rc = noxtls_tls12_context_init(&tls12_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: noxtls_tls12_context_init failed: %d\n", rc);
            if(trust_store_configured) {
                noxtls_x509_trust_store_clear();
            }
            CLOSESOCK(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        tls12_ctx.server_name = host;
        tls12_ctx.server_name_len = (uint16_t)strlen(host);

        rc = noxtls_tls_set_io_callbacks(&tls12_ctx.base.base, https_send_cb, https_recv_cb, &conn);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: noxtls_tls_set_io_callbacks failed (tls12): %d\n", rc);
            noxtls_tls12_context_free(&tls12_ctx);
            if(trust_store_configured) {
                noxtls_x509_trust_store_clear();
            }
            CLOSESOCK(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        rc = noxtls_tls12_connect(&tls12_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: TLS 1.2 handshake failed: %d\n", rc);
            noxtls_tls12_context_free(&tls12_ctx);
            if(trust_store_configured) {
                noxtls_x509_trust_store_clear();
            }
            CLOSESOCK(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }
    printf("TLS handshake complete\n");

    /* Send HTTP GET */
    char request[1024];
    if(port != 443) {
        snprintf(request, sizeof(request),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s:%u\r\n"
                 "User-Agent: NoxTLS-https_client/0.1\r\n"
                 "Accept: */*\r\n"
                 "Accept-Encoding: identity\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 path, host, port);
    } else {
        snprintf(request, sizeof(request),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: NoxTLS-https_client/0.1\r\n"
                 "Accept: */*\r\n"
                 "Accept-Encoding: identity\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 path, host);
    }

    if(active_mode == TLS_MODE_1_3) {
        rc = noxtls_tls13_send(&tls13_ctx, (const uint8_t*)request, (uint32_t)strlen(request));
    } else {
        rc = noxtls_tls12_send(&tls12_ctx, (const uint8_t*)request, (uint32_t)strlen(request));
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to send HTTP request: %d\n", rc);
        if(active_mode == TLS_MODE_1_3) {
            noxtls_tls13_context_free(&tls13_ctx);
        } else {
            noxtls_tls12_context_free(&tls12_ctx);
        }
        if(trust_store_configured) {
            noxtls_x509_trust_store_clear();
        }
        CLOSESOCK(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("---- Response ----\n");
    while(1) {
        uint8_t buf[4096];
        uint32_t len = sizeof(buf) - 1;
        if(active_mode == TLS_MODE_1_3) {
            rc = noxtls_tls13_recv(&tls13_ctx, buf, &len);
        } else {
            rc = noxtls_tls12_recv(&tls12_ctx, buf, &len);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("TLS connection closed by peer (EOF).\n");
            break;
        }
        if(len == 0) {
            break;
        }
        buf[len] = '\0';
        fwrite(buf, 1, len, stdout);
    }
    printf("\n---- End Response ----\n");

    if(active_mode == TLS_MODE_1_3) {
        noxtls_tls13_close(&tls13_ctx);
        noxtls_tls13_context_free(&tls13_ctx);
    } else {
        noxtls_tls12_close(&tls12_ctx);
        noxtls_tls12_context_free(&tls12_ctx);
    }
    CLOSESOCK(sock);
    if(trust_store_configured) {
        noxtls_x509_trust_store_clear();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
