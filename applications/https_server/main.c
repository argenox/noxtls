/*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Simple HTTPS server using NOXTLS TLS library.
 * Listens on localhost and serves a simple index.html over TLS.
 */
/**
 * @file main.c
 * @brief Simple HTTPS server using the NoxTLS TLS library.
 * @defgroup noxtls_app_https_server HTTPS server
 * @details
 * Listens on localhost and serves a simple page over TLS. Parameters: [port] [--cert &lt;cert.pem&gt;] [--key &lt;key.pem&gt;].
 * Default port 8443, default cert server.crt and key server.key. Options: --help, -h.
 * @example
 * https_server
 * https_server 9443
 * https_server 8443 --cert server.crt --key server.key
 * https_server --help
 */

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
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
#define CLOSESOCK close
#endif

#include "noxtls_common.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"
#include "noxtls-lib/tls/noxtls_tls.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
#include "noxtls-lib/tls/noxtls_tls_unified.h"
#endif
#include "noxtls-lib/certs/noxtls_x509.h"

/* Default port and cert/key paths */
#define DEFAULT_PORT 8443
#define DEFAULT_CERT_FILE "server.crt"
#define DEFAULT_KEY_FILE  "server.key"

/* Simple index.html served by the server */
static const char INDEX_HTML[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>NOXTLS HTTPS Server</title></head>\n"
    "<body>\n"
    "  <h1>Hello from NOXTLS HTTPS Server</h1>\n"
    "  <p>This page is served over TLS from the localhost https_server application.</p>\n"
    "  <p>You can test with the <code>https_client</code> or a browser (accept the certificate warning for self-signed).</p>\n"
    "</body>\n"
    "</html>\n";

typedef struct {
    socket_t sock;
} https_conn_t;

static int32_t https_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t *)user_data;
    uint32_t sent_total = 0;

    if (conn == NULL || data == NULL) {
        return -1;
    }

    while (sent_total < len) {
        int chunk = (int)(len - sent_total);
#ifdef _WIN32
        int sent = send(conn->sock, (const char *)data + sent_total, chunk, 0);
#else
        ssize_t sent = send(conn->sock, data + sent_total, (size_t)chunk, 0);
#endif
        if (sent <= 0) {
            return -1;
        }
        sent_total += (uint32_t)sent;
    }

    return (int32_t)sent_total;
}

static int32_t https_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    https_conn_t *conn = (https_conn_t *)user_data;
    uint32_t recv_total = 0;

    if (conn == NULL || data == NULL) {
        return -1;
    }

    while (recv_total < len) {
        int chunk = (int)(len - recv_total);
#ifdef _WIN32
        int received = recv(conn->sock, (char *)data + recv_total, chunk, 0);
#else
        ssize_t received = recv(conn->sock, data + recv_total, (size_t)chunk, 0);
#endif
        if (received <= 0) {
            return -1;
        }
        recv_total += (uint32_t)received;
    }

    return (int32_t)recv_total;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [port] [--cert <cert.pem>] [--key <key.pem>] [--unified]\n", prog);
    printf("  port         Listen port (default: %u)\n", (unsigned)DEFAULT_PORT);
    printf("  --cert file  Server certificate file (default: %s)\n", DEFAULT_CERT_FILE);
    printf("  --key file   Server private key file (default: %s)\n", DEFAULT_KEY_FILE);
    printf("  --unified    Use unified TLS API (noxtls_tls_connection_t) for accept/send/recv\n");
    printf("\n");
    printf("Generate a self-signed cert for testing:\n");
    printf("  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj /CN=localhost\n");
    printf("\n");
    printf("Then open https://127.0.0.1:%u/ in a browser or use: https_client https://127.0.0.1:%u/\n",
           (unsigned)DEFAULT_PORT, (unsigned)DEFAULT_PORT);
}

static socket_t create_listen_socket(uint16_t port)
{
    socket_t listen_sock;
    struct sockaddr_in addr;
#ifdef _WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET_VALUE) {
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
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  /* 127.0.0.1 */
    addr.sin_port = htons(port);

    if (bind(listen_sock, (struct sockaddr *)&addr, addrlen) != 0) {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }

    if (listen(listen_sock, 5) != 0) {
        CLOSESOCK(listen_sock);
        return INVALID_SOCKET_VALUE;
    }

    return listen_sock;
}

static int serve_one_request(void *tls_ctx, int is_tls13, const char *body, size_t body_len)
{
    noxtls_return_t rc;
    uint8_t req_buf[4096];
    uint32_t req_len = 0;
    uint32_t want = sizeof(req_buf) - 1;

    /* Read HTTP request (until we have headers: \r\n\r\n or buffer full) */
    while (req_len < sizeof(req_buf) - 1) {
        uint32_t remaining = want - req_len;
        uint32_t to_recv = remaining;
        if(to_recv > 2048u) {
            to_recv = 2048u;
        }

        if (is_tls13) {
            rc = tls13_recv((tls13_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        } else {
            rc = tls12_recv((tls12_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        if (to_recv == 0) {
            break;
        }
        req_len += to_recv;
        req_buf[req_len] = '\0';
        if (req_len >= 4 && memchr(req_buf, '\r', req_len) != NULL) {
            if (strstr((char *)req_buf, "\r\n\r\n") != NULL) {
                break;
            }
        }
    }

    /* Build HTTP response */
    {
        char header[512];
        int header_len = snprintf(header, sizeof(header),
                                  "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/html; charset=UTF-8\r\n"
                                  "Connection: close\r\n"
                                  "Content-Length: %zu\r\n"
                                  "\r\n",
                                  body_len);

        if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
            return -1;
        }

        if (is_tls13) {
            rc = tls13_send((tls13_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
        } else {
            rc = tls12_send((tls12_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }

        /* Send body in chunks if needed (TLS record size limit) */
        size_t sent = 0;
        while (sent < body_len) {
            uint32_t chunk = (uint32_t)(body_len - sent);
            if (chunk > 16384) {
                chunk = 16384;
            }
            if (is_tls13) {
                rc = tls13_send((tls13_context_t *)tls_ctx, (const uint8_t *)body + sent, chunk);
            } else {
                rc = tls12_send((tls12_context_t *)tls_ctx, (const uint8_t *)body + sent, chunk);
            }
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return -1;
            }
            sent += chunk;
        }
    }

    return 0;
}

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
static int serve_one_request_unified(noxtls_tls_connection_t *conn, const char *body, size_t body_len)
{
    noxtls_return_t rc;
    uint8_t req_buf[4096];
    uint32_t req_len = 0;
    uint32_t want = sizeof(req_buf) - 1;

    while (req_len < sizeof(req_buf) - 1) {
        uint32_t to_recv = want - req_len;
        if (to_recv > 2048u) {
            to_recv = 2048u;
        }
        rc = noxtls_tls_connection_recv(conn, req_buf + req_len, &to_recv);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        if (to_recv == 0) {
            break;
        }
        req_len += to_recv;
        req_buf[req_len] = '\0';
        if (req_len >= 4 && memchr(req_buf, '\r', req_len) != NULL) {
            if (strstr((char *)req_buf, "\r\n\r\n") != NULL) {
                break;
            }
        }
    }

    {
        char header[512];
        int header_len = snprintf(header, sizeof(header),
                                  "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/html; charset=UTF-8\r\n"
                                  "Connection: close\r\n"
                                  "Content-Length: %zu\r\n"
                                  "\r\n",
                                  body_len);

        if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
            return -1;
        }

        rc = noxtls_tls_connection_send(conn, (const uint8_t *)header, (uint32_t)header_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }

        size_t sent = 0;
        while (sent < body_len) {
            uint32_t chunk = (uint32_t)(body_len - sent);
            if (chunk > 16384) {
                chunk = 16384;
            }
            rc = noxtls_tls_connection_send(conn, (const uint8_t *)body + sent, chunk);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return -1;
            }
            sent += chunk;
        }
    }

    return 0;
}
#endif

int main(int argc, char **argv)
{
    uint16_t port = DEFAULT_PORT;
    const char *cert_file = DEFAULT_CERT_FILE;
    const char *key_file = DEFAULT_KEY_FILE;
    int use_unified = 0;
    x509_certificate_t cert;
    uint8_t *server_cert = NULL;
    uint32_t server_cert_len = 0;
    socket_t listen_sock = INVALID_SOCKET_VALUE;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--unified") == 0) {
            use_unified = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        } else if (argv[i][0] != '-') {
            port = (uint16_t)atoi(argv[i]);
            if (port == 0) {
                printf("ERROR: Invalid port\n");
                print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
        }
    }

    /* Load server certificate */
    noxtls_x509_certificate_init(&cert);
    if (noxtls_x509_certificate_load_file(&cert, cert_file) != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to load certificate from '%s'\n", cert_file);
        printf("Generate one with: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj /CN=localhost\n");
        noxtls_x509_certificate_free(&cert);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    server_cert = cert.raw_data;
    server_cert_len = cert.raw_data_len;
    if (server_cert == NULL || server_cert_len == 0) {
        printf("ERROR: Certificate has no raw data\n");
        noxtls_x509_certificate_free(&cert);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    listen_sock = create_listen_socket(port);
    if (listen_sock == INVALID_SOCKET_VALUE) {
        printf("ERROR: Failed to create listen socket on 127.0.0.1:%u\n", (unsigned)port);
        noxtls_x509_certificate_free(&cert);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("HTTPS server listening on https://127.0.0.1:%u/\n", (unsigned)port);
    printf("Press Ctrl+C to stop.\n\n");

    volatile int keep_running = 1;
    while (keep_running) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif
        socket_t client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET_VALUE) {
            continue;
        }

        printf("Client connected\n");

        https_conn_t conn;
        conn.sock = client_sock;

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
        if (use_unified) {
            noxtls_tls_connection_t uconn;
            noxtls_return_t rc = noxtls_tls_connection_init(&uconn, TLS_ROLE_SERVER);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                printf("ERROR: noxtls_tls_connection_init failed\n");
                CLOSESOCK(client_sock);
                continue;
            }
            noxtls_tls_connection_set_io_callbacks(&uconn, https_send_cb, https_recv_cb, &conn);
            noxtls_tls_connection_set_server_cert(&uconn, server_cert, server_cert_len);

            rc = noxtls_tls_connection_accept(&uconn);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                printf("ERROR: TLS handshake failed (unified): %d\n", rc);
                noxtls_tls_connection_free(&uconn);
                CLOSESOCK(client_sock);
                continue;
            }

            {
                uint16_t ver = noxtls_tls_connection_get_version(&uconn);
                printf("TLS handshake complete (unified, version %s)\n",
                       ver == 0x0304 ? "1.3" : ver == 0x0303 ? "1.2" : "?");
            }

            {
                size_t body_len = sizeof(INDEX_HTML) - 1;
                if (serve_one_request_unified(&uconn, INDEX_HTML, body_len) != 0) {
                    printf("ERROR: Failed to serve response\n");
                }
            }

            noxtls_tls_connection_close(&uconn);
            noxtls_tls_connection_free(&uconn);
            CLOSESOCK(client_sock);
            printf("Connection closed\n\n");
            continue;
        }
#endif

        tls_context_t base_ctx;
        tls12_context_t tls12_ctx;
        tls13_context_t tls13_ctx;
        uint16_t negotiated_version = 0;
        noxtls_return_t rc;

        if (noxtls_tls_context_init(&base_ctx, TLS_ROLE_SERVER, 0) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: noxtls_tls_context_init failed\n");
            CLOSESOCK(client_sock);
            continue;
        }
        noxtls_tls_set_io_callbacks(&base_ctx, https_send_cb, https_recv_cb, &conn);

        if (tls12_context_init(&tls12_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: tls12_context_init failed\n");
            noxtls_tls_context_free(&base_ctx);
            CLOSESOCK(client_sock);
            continue;
        }
        tls12_ctx.server_cert = server_cert;
        tls12_ctx.server_cert_len = server_cert_len;

        if (tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: tls13_context_init failed\n");
            tls12_context_free(&tls12_ctx);
            noxtls_tls_context_free(&base_ctx);
            CLOSESOCK(client_sock);
            continue;
        }
        tls13_ctx.server_cert = server_cert;
        tls13_ctx.server_cert_len = server_cert_len;

        rc = tls_accept_auto(&base_ctx, NULL, NULL, &tls12_ctx, &tls13_ctx, &negotiated_version);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: TLS handshake failed: %d\n", rc);
            tls13_context_free(&tls13_ctx);
            tls12_context_free(&tls12_ctx);
            noxtls_tls_context_free(&base_ctx);
            CLOSESOCK(client_sock);
            continue;
        }

        printf("TLS handshake complete (version %s)\n",
               negotiated_version == 0x0304 ? "1.3" : negotiated_version == 0x0303 ? "1.2" : "?");

        {
            int is_tls13 = (negotiated_version == 0x0304);
            void *tls_ctx = is_tls13 ? (void *)&tls13_ctx : (void *)&tls12_ctx;
            size_t body_len = sizeof(INDEX_HTML) - 1;

            if (serve_one_request(tls_ctx, is_tls13, INDEX_HTML, body_len) != 0) {
                printf("ERROR: Failed to serve response\n");
            }

            if (is_tls13) {
                tls13_close(&tls13_ctx);
                tls13_context_free(&tls13_ctx);
            } else {
                tls12_close(&tls12_ctx);
                tls12_context_free(&tls12_ctx);
            }
        }
        noxtls_tls_context_free(&base_ctx);
        CLOSESOCK(client_sock);
        printf("Connection closed\n\n");
    }

    CLOSESOCK(listen_sock);
    noxtls_x509_certificate_free(&cert);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
