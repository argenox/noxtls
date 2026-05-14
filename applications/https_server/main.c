/*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*/
/**
 * @file main.c
 * @brief Configurable HTTPS server with negotiated-algorithm reporting.
 */

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
typedef SOCKET socket_t;
#define CLOSESOCK closesocket
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define STR_CASE_EQ(a, b) (_stricmp((a), (b)) == 0)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
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
#endif

#define DEFAULT_PORT 8443
#define DEFAULT_CERT_FILE "server.crt"
#define DEFAULT_KEY_FILE "server.key"
#define DEFAULT_BIND_IP "127.0.0.1"
#define REQUEST_BUFFER_SIZE 4096u
#define REQUEST_READ_CHUNK 2048u
#define HTTP_HEADER_BUFFER_SIZE 512u
#define HTTP_BODY_BUFFER_SIZE 4096u
#define TLS_SEND_CHUNK 16384u
#define MAX_CIPHER_SUITES 64u
static const uint16_t TLS12_FALLBACK_DEFAULT_SUITES[] = {
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
};

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

static const cipher_suite_entry_t CIPHER_NAME_TABLE[] = {
    { "TLS_RSA_WITH_3DES_EDE_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA },
    { "TLS_RSA_WITH_AES_128_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA },
    { "TLS_RSA_WITH_AES_256_CBC_SHA", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA },
    { "TLS_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_RSA_WITH_AES_256_CBC_SHA256", TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 },
    { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
    { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    { "TLS_AES_128_GCM_SHA256", TLS_CIPHER_SUITE_AES_128_GCM_SHA256 },
    { "TLS_AES_256_GCM_SHA384", TLS_CIPHER_SUITE_AES_256_GCM_SHA384 },
    { "TLS_CHACHA20_POLY1305_SHA256", TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 },
    { "TLS_AES_128_CCM_SHA256", TLS_CIPHER_SUITE_AES_128_CCM_SHA256 },
    { "TLS_AES_128_CCM_8_SHA256", TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256 }
};

static const char *format_name(file_format_t format)
{
    if(format == FILE_FORMAT_PEM) return "pem";
    if(format == FILE_FORMAT_DER) return "der";
    return "auto";
}

static const char *server_key_kind_name(server_key_kind_t kind)
{
    if(kind == SERVER_KEY_KIND_RSA) return "RSA";
    if(kind == SERVER_KEY_KIND_ECDSA) return "ECDSA";
    if(kind == SERVER_KEY_KIND_ED25519) return "Ed25519";
    if(kind == SERVER_KEY_KIND_ED448) return "Ed448";
    return "unknown";
}

static const char *tls_version_name(uint16_t version)
{
    if(version == TLS_VERSION_1_3) return "TLS 1.3";
    if(version == TLS_VERSION_1_2) return "TLS 1.2";
    if(version == TLS_VERSION_1_1) return "TLS 1.1";
    if(version == TLS_VERSION_1_0) return "TLS 1.0";
    return "unknown";
}

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
        case TLS_NAMED_GROUP_MLKEM512: return "mlkem512";
        case TLS_NAMED_GROUP_MLKEM768: return "mlkem768";
        case TLS_NAMED_GROUP_MLKEM1024: return "mlkem1024";
        case TLS_NAMED_GROUP_X25519_MLKEM512: return "x25519_mlkem512";
        case TLS_NAMED_GROUP_X25519_MLKEM768: return "x25519_mlkem768";
        case TLS_NAMED_GROUP_X25519_MLKEM1024: return "x25519_mlkem1024";
        default: return "n/a";
    }
}

static const char *tls_kex_name_from_suite(uint16_t suite, uint16_t tls13_group)
{
    if(suite >= 0x1301u && suite <= 0x13FFu) {
        return tls_group_name(tls13_group);
    }
    if(suite == TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256) {
        return "RSA";
    }
    if(suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384) {
        return "DHE_RSA";
    }
    if(suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384) {
        return "ECDHE_RSA";
    }
    if(suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
       suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
        return "ECDHE_ECDSA";
    }
    return "unknown";
}

static const char *tls_bulk_cipher_name(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            return "3DES-CBC";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
            return "AES-128-CBC";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
            return "AES-256-CBC";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
            return "AES-128-GCM";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            return "AES-256-GCM";
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
            return "AES-128-CCM";
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
            return "AES-128-CCM-8";
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            return "ChaCha20-Poly1305";
        default:
            return "unknown";
    }
}

static const char *tls_hash_name(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            return "SHA-1";
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            return "SHA-256";
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            return "SHA-384";
        default:
            return "unknown";
    }
}

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

static int parse_cipher_suite_list(const char *arg, uint16_t *out_suites, uint32_t *out_count)
{
    char *copy;
    char *cursor;
    uint32_t count = 0;
    if(arg == NULL || out_suites == NULL || out_count == NULL) {
        return 0;
    }

    copy = (char *)malloc(strlen(arg) + 1u);
    if(copy == NULL) {
        return 0;
    }
    memcpy(copy, arg, strlen(arg) + 1u);

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
    return (count > 0u) ? 1 : 0;
}

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
    read_len = fread(buf, 1u, (size_t)size, fp);
    fclose(fp);
    if(read_len != (size_t)size) {
        free(buf);
        return NOXTLS_RETURN_FAILED;
    }
    *out_buf = buf;
    *out_len = (uint32_t)size;
    return NOXTLS_RETURN_SUCCESS;
}

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

static void print_usage(const char *prog)
{
    printf("Usage: %s [port] [options]\n", prog);
    printf("  port                   Listen port (default: %u)\n", (unsigned)DEFAULT_PORT);
    printf("  -if, --interface <ip>  Bind interface IPv4 (default: %s)\n", DEFAULT_BIND_IP);
    printf("  -v                     Enable standard debug output\n");
    printf("  -vv                    Enable full debug output (includes verbose TLS13 traces)\n");
    printf("  --cert <file>          Server certificate file (default: %s)\n", DEFAULT_CERT_FILE);
    printf("  --cert-format <fmt>    Certificate format: auto|pem|der (default: auto)\n");
    printf("  --key <file>           Server private key file (default: %s)\n", DEFAULT_KEY_FILE);
    printf("  --key-format <fmt>     Private key format: auto|pem|der (default: auto)\n");
    printf("  --tls12-cert <file>    Optional RSA cert for TLS 1.2 fallback when primary key is non-RSA\n");
    printf("  --tls12-cert-format <fmt> Optional TLS 1.2 cert format: auto|pem|der (default: auto)\n");
    printf("  --tls12-key <file>     Optional RSA key for TLS 1.2 fallback when primary key is non-RSA\n");
    printf("  --tls12-key-format <fmt> Optional TLS 1.2 key format: auto|pem|der (default: auto)\n");
    printf("  --cipher-suites <lst>  Comma-separated allowlist by name or hex id (e.g. TLS_AES_128_GCM_SHA256,0x1303)\n");
    printf("  --debug-log <file>     Append noxtls debug output to log file\n");
    printf("  --unified              Use noxtls_tls_connection_t API\n");
    printf("  --help, -h             Show this help message\n");
    printf("\n");
    printf("Supported private key algorithms: RSA (TLS 1.2/1.3), ECDSA, Ed25519, Ed448 (TLS 1.3)\n");
    printf("Generate an RSA self-signed cert for testing:\n");
    printf("  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj /CN=localhost\n");
}

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
                          (unsigned)sizeof(body) - 1u);
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
    while(sent_total < (uint32_t)(sizeof(body) - 1u)) {
        int chunk = (int)((uint32_t)(sizeof(body) - 1u) - sent_total);
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

static int serve_one_request(void *tls_ctx, int is_tls13, const char *body, size_t body_len)
{
    noxtls_return_t rc;
    uint8_t req_buf[REQUEST_BUFFER_SIZE];
    uint32_t req_len = 0;
    while(req_len < REQUEST_BUFFER_SIZE - 1u) {
        uint32_t to_recv = (REQUEST_BUFFER_SIZE - 1u) - req_len;
        if(to_recv > REQUEST_READ_CHUNK) {
            to_recv = REQUEST_READ_CHUNK;
        }
        if(is_tls13) {
            rc = noxtls_tls13_recv((tls13_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        } else {
            rc = noxtls_tls12_recv((tls12_context_t *)tls_ctx, req_buf + req_len, &to_recv);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        if(to_recv == 0) {
            break;
        }
        req_len += to_recv;
        req_buf[req_len] = '\0';
        if(strstr((char *)req_buf, "\r\n\r\n") != NULL) {
            break;
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
            return -1;
        }
        if(is_tls13) {
            rc = noxtls_tls13_send((tls13_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
        } else {
            rc = noxtls_tls12_send((tls12_context_t *)tls_ctx, (const uint8_t *)header, (uint32_t)header_len);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
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
    uint8_t req_buf[REQUEST_BUFFER_SIZE];
    uint32_t req_len = 0;

    while(req_len < REQUEST_BUFFER_SIZE - 1u) {
        uint32_t to_recv = (REQUEST_BUFFER_SIZE - 1u) - req_len;
        if(to_recv > REQUEST_READ_CHUNK) {
            to_recv = REQUEST_READ_CHUNK;
        }
        rc = noxtls_tls_connection_recv(conn, req_buf + req_len, &to_recv);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        if(to_recv == 0) {
            break;
        }
        req_len += to_recv;
        req_buf[req_len] = '\0';
        if(strstr((char *)req_buf, "\r\n\r\n") != NULL) {
            break;
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
            return -1;
        }
        rc = noxtls_tls_connection_send(conn, (const uint8_t *)header, (uint32_t)header_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
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
                return -1;
            }
            sent += chunk;
        }
    }
    return 0;
}
#endif

static int build_http_body(char *body_buf,
                                  size_t body_buf_len,
                                  uint16_t tls_version,
                                  uint16_t cipher_suite,
                                  uint16_t tls13_group)
{
    int written;
    if(body_buf == NULL || body_buf_len == 0u) {
        return -1;
    }

    written = snprintf(body_buf, body_buf_len,
                       "<!DOCTYPE html>\n"
                       "<html>\n"
                       "<head><title>NOXTLS HTTPS Server</title></head>\n"
                       "<body>\n"
                       "  <h1>NOXTLS HTTPS Server</h1>\n"
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

int main(int argc, char **argv)
{
    uint16_t port = DEFAULT_PORT;
    const char *bind_ip = DEFAULT_BIND_IP;
    unsigned char debug_level = 0u;
    const char *cert_file = DEFAULT_CERT_FILE;
    const char *key_file = DEFAULT_KEY_FILE;
    const char *tls12_cert_file = NULL;
    const char *tls12_key_file = NULL;
    const char *debug_log_file = NULL;
    file_format_t cert_format = FILE_FORMAT_AUTO;
    file_format_t key_format = FILE_FORMAT_AUTO;
    file_format_t tls12_cert_format = FILE_FORMAT_AUTO;
    file_format_t tls12_key_format = FILE_FORMAT_AUTO;
    uint16_t configured_cipher_suites[MAX_CIPHER_SUITES];
    uint32_t configured_cipher_suite_count = 0;
    int use_unified = 0;
    socket_t listen_sock = INVALID_SOCKET_VALUE;
    x509_certificate_t cert;
    x509_private_key_t server_key_x509;
    x509_certificate_t tls12_cert;
    x509_private_key_t tls12_key_x509;
    rsa_key_t server_rsa_key;
    rsa_key_t tls12_server_rsa_key;
    ecc_key_t server_ecc_key;
    uint8_t server_ed25519_seed[32];
    uint8_t server_ed448_seed[57];
    server_key_kind_t server_key_kind = SERVER_KEY_KIND_NONE;
    int server_rsa_key_loaded = 0;
    int tls12_server_rsa_key_loaded = 0;
    int server_ecc_key_loaded = 0;
    uint8_t *server_cert = NULL;
    uint32_t server_cert_len = 0;
    uint8_t *tls12_server_cert = NULL;
    uint32_t tls12_server_cert_len = 0;
    int tls12_fallback_enabled = 0;
    int exit_code = 1;
    int i;

    memset(&cert, 0, sizeof(cert));
    memset(&server_key_x509, 0, sizeof(server_key_x509));
    memset(&tls12_cert, 0, sizeof(tls12_cert));
    memset(&tls12_key_x509, 0, sizeof(tls12_key_x509));
    memset(&server_rsa_key, 0, sizeof(server_rsa_key));
    memset(&tls12_server_rsa_key, 0, sizeof(tls12_server_rsa_key));
    memset(&server_ecc_key, 0, sizeof(server_ecc_key));
    memset(server_ed25519_seed, 0, sizeof(server_ed25519_seed));
    memset(server_ed448_seed, 0, sizeof(server_ed448_seed));
    noxtls_x509_certificate_init(&cert);
    noxtls_x509_private_key_init(&server_key_x509);
    noxtls_x509_certificate_init(&tls12_cert);
    noxtls_x509_private_key_init(&tls12_key_x509);

#ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    for(i = 1; i < argc; i++) {
        if((strcmp(argv[i], "-if") == 0 || strcmp(argv[i], "--interface") == 0) && i + 1 < argc) {
            bind_ip = argv[++i];
        } else if(strcmp(argv[i], "-v") == 0) {
            if(debug_level < 1u) {
                debug_level = 1u;
            }
        } else if(strcmp(argv[i], "-vv") == 0) {
            debug_level = 2u;
        } else if(strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if(strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if(strcmp(argv[i], "--tls12-cert") == 0 && i + 1 < argc) {
            tls12_cert_file = argv[++i];
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
        } else if(strcmp(argv[i], "--debug-log") == 0 && i + 1 < argc) {
            debug_log_file = argv[++i];
        } else if(strcmp(argv[i], "--unified") == 0) {
            use_unified = 1;
        } else if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
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
    if(server_cert == NULL || server_cert_len == 0u) {
        printf("ERROR: Certificate has no DER raw data after parse\n");
        goto cleanup;
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
        if(server_ecc_key.curve == NULL || (server_ecc_key.curve->size != 32u && server_ecc_key.curve->size != 48u)) {
            printf("ERROR: ECDSA key curve is unsupported for TLS 1.3 signatures in this app path (expected P-256 or P-384)\n");
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

    if((tls12_cert_file != NULL && tls12_key_file == NULL) ||
       (tls12_cert_file == NULL && tls12_key_file != NULL)) {
        printf("ERROR: --tls12-cert and --tls12-key must be provided together\n");
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
        if(tls12_server_cert == NULL || tls12_server_cert_len == 0u) {
            printf("ERROR: TLS 1.2 fallback certificate has no DER raw data after parse\n");
            goto cleanup;
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

    listen_sock = create_listen_socket(port, bind_ip);
    if(listen_sock == INVALID_SOCKET_VALUE) {
        printf("ERROR: Failed to create listen socket on %s:%u\n", bind_ip, (unsigned)port);
        goto cleanup;
    }

    printf("HTTPS server listening on https://%s:%u/\n", bind_ip, (unsigned)port);
    printf("Certificate: %s (%s)\n", cert_file, format_name(cert_format));
    printf("Private key: %s (%s)\n", key_file, format_name(key_format));
    if(debug_level == 1u) {
        printf("Debug mode: -v (standard)\n");
    } else if(debug_level >= 2u) {
        printf("Debug mode: -vv (full)\n");
    }
    if(debug_log_file != NULL) {
        printf("Debug log file: %s\n", debug_log_file);
    }
    printf("Private key algorithm: %s\n", server_key_kind_name(server_key_kind));
    if(server_key_kind != SERVER_KEY_KIND_RSA) {
        if(tls12_fallback_enabled) {
            printf("TLS 1.2 fallback enabled with RSA cert/key: %s / %s\n", tls12_cert_file, tls12_key_file);
        } else {
            printf("Non-RSA server keys currently run on TLS 1.3 only in this app path\n");
        }
    }
    if(configured_cipher_suite_count > 0u) {
        printf("Configured ciphersuite allowlist (%u):\n", (unsigned)configured_cipher_suite_count);
        for(i = 0; i < (int)configured_cipher_suite_count; i++) {
            printf("  - %s (0x%04X)\n",
                   tls_cipher_suite_name(configured_cipher_suites[i]),
                   (unsigned)configured_cipher_suites[i]);
        }
    } else {
        printf("Configured ciphersuite allowlist: library defaults\n");
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

        {
            https_conn_t conn;
            conn.sock = client_sock;

            if(is_likely_plain_http_request(client_sock)) {
                if(debug_level > 0u) {
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
                    noxtls_tls12_set_server_private_rsa(&tls12_ctx, &tls12_server_rsa_key);
                    if(configured_cipher_suite_count > 0u) {
                        noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                              configured_cipher_suites,
                                                              configured_cipher_suite_count);
                    } else {
                        noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                              TLS12_FALLBACK_DEFAULT_SUITES,
                                                              (uint32_t)(sizeof(TLS12_FALLBACK_DEFAULT_SUITES) /
                                                                         sizeof(TLS12_FALLBACK_DEFAULT_SUITES[0])));
                    }

                    if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: noxtls_tls13_context_init failed\n");
                        noxtls_tls12_context_free(&tls12_ctx);
                        noxtls_tls_context_free(&base_ctx);
                        CLOSESOCK(client_sock);
                        continue;
                    }
                    tls13_ctx.server_cert = server_cert;
                    tls13_ctx.server_cert_len = server_cert_len;
                    if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                        noxtls_tls13_set_server_private_ecdsa(&tls13_ctx, &server_ecc_key);
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
                    if(configured_cipher_suite_count > 0u) {
                        noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                              configured_cipher_suites,
                                                              configured_cipher_suite_count);
                    }

                    rc = tls_accept_auto(&base_ctx, NULL, NULL, &tls12_ctx, &tls13_ctx, &negotiated_version);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: TLS handshake failed: %d\n", rc);
                        noxtls_tls13_context_free(&tls13_ctx);
                        noxtls_tls12_context_free(&tls12_ctx);
                        noxtls_tls_context_free(&base_ctx);
                        CLOSESOCK(client_sock);
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
                    noxtls_tls13_context_free(&tls13_ctx);
                    noxtls_tls12_context_free(&tls12_ctx);
                    noxtls_tls_context_free(&base_ctx);
                    CLOSESOCK(client_sock);
                    continue;
                } else {
                    tls13_context_t tls13_ctx;
                    noxtls_return_t rc;
                    char body[HTTP_BODY_BUFFER_SIZE];
                    int body_len;
                    uint16_t suite = 0;
                    uint16_t group = 0;

                    if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: noxtls_tls13_context_init failed\n");
                        CLOSESOCK(client_sock);
                        continue;
                    }
                    noxtls_tls_set_io_callbacks(&tls13_ctx.base.base, https_send_cb, https_recv_cb, &conn);
                    tls13_ctx.server_cert = server_cert;
                    tls13_ctx.server_cert_len = server_cert_len;

                    if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                        noxtls_tls13_set_server_private_ecdsa(&tls13_ctx, &server_ecc_key);
                    } else if(server_key_kind == SERVER_KEY_KIND_ED25519) {
                        rc = noxtls_tls13_set_server_private_ed25519(&tls13_ctx, server_ed25519_seed);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: Failed to configure Ed25519 server key: %d\n", rc);
                            noxtls_tls13_context_free(&tls13_ctx);
                            CLOSESOCK(client_sock);
                            continue;
                        }
                    } else if(server_key_kind == SERVER_KEY_KIND_ED448) {
                        rc = noxtls_tls13_set_server_private_ed448(&tls13_ctx, server_ed448_seed);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            printf("ERROR: Failed to configure Ed448 server key: %d\n", rc);
                            noxtls_tls13_context_free(&tls13_ctx);
                            CLOSESOCK(client_sock);
                            continue;
                        }
                    } else {
                        printf("ERROR: Unsupported server key algorithm selection\n");
                        noxtls_tls13_context_free(&tls13_ctx);
                        CLOSESOCK(client_sock);
                        continue;
                    }

                    if(configured_cipher_suite_count > 0u) {
                        noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                              configured_cipher_suites,
                                                              configured_cipher_suite_count);
                    }

                    rc = noxtls_tls13_accept(&tls13_ctx);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        printf("ERROR: TLS 1.3 handshake failed: %d\n", rc);
                        if(server_key_kind == SERVER_KEY_KIND_ECDSA) {
                            printf("HINT: Ensure certificate/key are ECDSA P-256 or P-384 and client supports matching TLS 1.3 signature algorithms\n");
                        }
                        noxtls_tls13_context_free(&tls13_ctx);
                        CLOSESOCK(client_sock);
                        continue;
                    }

                    suite = tls13_ctx.cipher_suite;
                    group = tls13_ctx.selected_kex_group;
                    printf("TLS handshake complete: version=TLS 1.3 suite=%s (0x%04X)\n",
                           tls_cipher_suite_name(suite),
                           (unsigned)suite);

                    body_len = build_http_body(body, sizeof(body), TLS_VERSION_1_3, suite, group);
                    if(body_len <= 0) {
                        printf("ERROR: Failed to build response body\n");
                    } else if(serve_one_request(&tls13_ctx, 1, body, (size_t)body_len) != 0) {
                        printf("ERROR: Failed to serve response\n");
                    }

                    noxtls_tls13_close(&tls13_ctx);
                    noxtls_tls13_context_free(&tls13_ctx);
                    CLOSESOCK(client_sock);
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
                noxtls_tls_connection_set_server_private_key(&uconn, &server_rsa_key);
                if(configured_cipher_suite_count > 0u) {
                    noxtls_tls_connection_set_server_cipher_suites(&uconn,
                                                                   configured_cipher_suites,
                                                                   configured_cipher_suite_count);
                }

                rc = noxtls_tls_connection_accept(&uconn);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: TLS handshake failed (unified): %d\n", rc);
                    noxtls_tls_connection_free(&uconn);
                    CLOSESOCK(client_sock);
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
                CLOSESOCK(client_sock);
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
                noxtls_tls12_set_server_private_rsa(&tls12_ctx, &server_rsa_key);
                if(configured_cipher_suite_count > 0u) {
                    noxtls_tls12_set_server_cipher_suites(&tls12_ctx,
                                                          configured_cipher_suites,
                                                          configured_cipher_suite_count);
                }

                if(noxtls_tls13_context_init(&tls13_ctx, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: noxtls_tls13_context_init failed\n");
                    noxtls_tls12_context_free(&tls12_ctx);
                    noxtls_tls_context_free(&base_ctx);
                    CLOSESOCK(client_sock);
                    continue;
                }
                tls13_ctx.server_cert = server_cert;
                tls13_ctx.server_cert_len = server_cert_len;
                noxtls_tls13_set_server_private_rsa(&tls13_ctx, &server_rsa_key);
                if(configured_cipher_suite_count > 0u) {
                    noxtls_tls13_set_server_cipher_suites(&tls13_ctx,
                                                          configured_cipher_suites,
                                                          configured_cipher_suite_count);
                }

                rc = tls_accept_auto(&base_ctx, NULL, NULL, &tls12_ctx, &tls13_ctx, &negotiated_version);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    printf("ERROR: TLS handshake failed: %d\n", rc);
                    noxtls_tls13_context_free(&tls13_ctx);
                    noxtls_tls12_context_free(&tls12_ctx);
                    noxtls_tls_context_free(&base_ctx);
                    CLOSESOCK(client_sock);
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
                    noxtls_tls13_context_free(&tls13_ctx);
                    noxtls_tls12_context_free(&tls12_ctx);
                } else {
                    noxtls_tls12_close(&tls12_ctx);
                    noxtls_tls12_context_free(&tls12_ctx);
                    noxtls_tls13_context_free(&tls13_ctx);
                }
                noxtls_tls_context_free(&base_ctx);
                CLOSESOCK(client_sock);
            }
        }
    }

cleanup:
    noxtls_debug_set_log_file(NULL);
    if(listen_sock != INVALID_SOCKET_VALUE) {
        CLOSESOCK(listen_sock);
    }
    noxtls_x509_certificate_free(&cert);
    noxtls_x509_private_key_free(&server_key_x509);
    noxtls_x509_certificate_free(&tls12_cert);
    noxtls_x509_private_key_free(&tls12_key_x509);
    if(server_rsa_key_loaded) {
        noxtls_rsa_key_free(&server_rsa_key);
    }
    if(tls12_server_rsa_key_loaded) {
        noxtls_rsa_key_free(&tls12_server_rsa_key);
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
