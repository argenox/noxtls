/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    main.c
* Summary: TLS Test Application - Tests TLS encryption/decryption
*
* This application creates a TLS server and client, connects them via callbacks,
* performs a handshake, and verifies that data encryption/decryption works correctly.
*
*/

/**
 * @file main.c
 * @brief TLS test client — handshake and encryption/decryption verification.
 * @defgroup noxtls_app_tls_test TLS test
 * @details
 * In-process test: creates TLS server and client, connects via callbacks,
 * performs handshake and verifies encryption/decryption. No command-line
 * parameters required; run from project or build directory.
 * @example
 * tls_test
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls-lib/common/noxtls_debug_printf.h"
#include "noxtls_common.h"
#include "noxtls-lib/tls/noxtls_tls.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "noxtls-lib/pkc/rsa/noxtls_bignum.h"
#include "noxtls-lib/drbg/noxtls_drbg.h"
#include "noxtls-lib/tls/noxtls_tls_noxsight.h"

#if NOXTLS_CFG_ENABLE_NOXSIGHT
#include "../../../noxsight/noxsight.h"
#endif

/* Define to use fixed pre-generated primes instead of generating them */
/* Comment out to enable prime generation */
#define USE_FIXED_PRIMES

/* Buffer for simulating network connection */
typedef struct
{
    uint8_t *data;
    uint32_t len;
    uint32_t capacity;
} network_buffer_t;

/* Network connection simulation */
typedef struct
{
    network_buffer_t server_to_client;
    network_buffer_t client_to_server;
} network_connection_t;

typedef struct
{
    int show_help;
    int noxsight_enabled;
    uint8_t noxsight_level;
    uint32_t noxsight_module_mask;
    const char *noxsight_sink;
    char noxsight_file_path[260];
} tls_test_cli_options_t;

static void hex_dump(const char *label, const uint8_t *data, uint32_t len)
{
    if(label) {
        printf("%s (%u bytes): ", label, len);
    }
    for(uint32_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if(i + 1 != len) {
            printf(" ");
        }
    }
    printf("\n");
}

#if NOXTLS_CFG_ENABLE_NOXSIGHT
static FILE *g_tls_test_noxsight_file = NULL;

static void tls_test_noxsight_sink_write(void *ctx, const uint8_t *data, size_t len)
{
    FILE *out = (FILE *)ctx;
    if(out == NULL || data == NULL || len == 0u)
    {
        return;
    }

    (void)fwrite(data, 1u, len, out);
}

static void tls_test_noxsight_sink_flush(void *ctx)
{
    FILE *out = (FILE *)ctx;
    if(out != NULL)
    {
        (void)fflush(out);
    }
}

static int tls_test_parse_bool(const char *value, int *out_bool)
{
    if(value == NULL || out_bool == NULL)
    {
        return 0;
    }
    if(strcmp(value, "1") == 0 || strcmp(value, "on") == 0 || strcmp(value, "true") == 0 || strcmp(value, "yes") == 0)
    {
        *out_bool = 1;
        return 1;
    }
    if(strcmp(value, "0") == 0 || strcmp(value, "off") == 0 || strcmp(value, "false") == 0 || strcmp(value, "no") == 0)
    {
        *out_bool = 0;
        return 1;
    }
    return 0;
}

static int tls_test_parse_level(const char *value, uint8_t *out_level)
{
    if(value == NULL || out_level == NULL)
    {
        return 0;
    }
    if(strcmp(value, "error") == 0 || strcmp(value, "0") == 0) { *out_level = NOXSIGHT_SEVERITY_ERROR; return 1; }
    if(strcmp(value, "warn") == 0  || strcmp(value, "1") == 0) { *out_level = NOXSIGHT_SEVERITY_WARN;  return 1; }
    if(strcmp(value, "info") == 0  || strcmp(value, "2") == 0) { *out_level = NOXSIGHT_SEVERITY_INFO;  return 1; }
    if(strcmp(value, "debug") == 0 || strcmp(value, "3") == 0) { *out_level = NOXSIGHT_SEVERITY_DEBUG; return 1; }
    if(strcmp(value, "trace") == 0 || strcmp(value, "4") == 0) { *out_level = NOXSIGHT_SEVERITY_TRACE; return 1; }
    return 0;
}

static int tls_test_try_add_module(uint32_t *mask, const char *name)
{
    if(mask == NULL || name == NULL)
    {
        return 0;
    }
    if(strcmp(name, "handshake") == 0) { *mask |= NOXTLS_LOG_MOD_HANDSHAKE; return 1; }
    if(strcmp(name, "record") == 0)    { *mask |= NOXTLS_LOG_MOD_RECORD;    return 1; }
    if(strcmp(name, "x509") == 0)      { *mask |= NOXTLS_LOG_MOD_X509;      return 1; }
    if(strcmp(name, "crypto") == 0)    { *mask |= NOXTLS_LOG_MOD_CRYPTO;    return 1; }
    if(strcmp(name, "io") == 0)        { *mask |= NOXTLS_LOG_MOD_IO;        return 1; }
    if(strcmp(name, "session") == 0)   { *mask |= NOXTLS_LOG_MOD_SESSION;   return 1; }
    if(strcmp(name, "keysched") == 0)  { *mask |= NOXTLS_LOG_MOD_KEYSCHED;  return 1; }
    if(strcmp(name, "alert") == 0)     { *mask |= NOXTLS_LOG_MOD_ALERT;     return 1; }
    return 0;
}

static int tls_test_parse_modules(const char *value, uint32_t *out_mask)
{
    char tmp[256];
    char *token;
    uint32_t mask = 0u;

    if(value == NULL || out_mask == NULL)
    {
        return 0;
    }

    if(strcmp(value, "all") == 0)
    {
        *out_mask = NOXTLS_LOG_MOD_HANDSHAKE |
                    NOXTLS_LOG_MOD_RECORD |
                    NOXTLS_LOG_MOD_X509 |
                    NOXTLS_LOG_MOD_CRYPTO |
                    NOXTLS_LOG_MOD_IO |
                    NOXTLS_LOG_MOD_SESSION |
                    NOXTLS_LOG_MOD_KEYSCHED |
                    NOXTLS_LOG_MOD_ALERT;
        return 1;
    }
    if(strcmp(value, "none") == 0)
    {
        *out_mask = 0u;
        return 1;
    }

    if(strlen(value) >= sizeof(tmp))
    {
        return 0;
    }
    strcpy(tmp, value);

#ifdef _MSC_VER
    {
        char *next = NULL;
        token = strtok_s(tmp, ",", &next);
        while(token != NULL)
        {
            if(!tls_test_try_add_module(&mask, token))
            {
                return 0;
            }
            token = strtok_s(NULL, ",", &next);
        }
    }
#else
    {
        char *next = NULL;
        token = strtok_r(tmp, ",", &next);
        while(token != NULL)
        {
            if(!tls_test_try_add_module(&mask, token))
            {
                return 0;
            }
            token = strtok_r(NULL, ",", &next);
        }
    }
#endif

    *out_mask = mask;
    return 1;
}

static void tls_test_print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -h, --help                   Show this help\n");
    printf("  --noxsight=on|off            Enable/disable NoxSight output (default: on)\n");
    printf("  --noxsight-on                Enable NoxSight output\n");
    printf("  --noxsight-off               Disable NoxSight output\n");
    printf("  --ns-level=<name|0-4>        error|warn|info|debug|trace (default: trace)\n");
    printf("  --ns-mask=<hex|dec>          Module bitmask (overrides modules list)\n");
    printf("  --ns-modules=<csv|all|none>  e.g. handshake,record,x509,crypto,io,session,keysched,alert\n");
    printf("  --ns-sink=stdout|stderr|file Sink destination (default: stdout)\n");
    printf("  --ns-file=<path>             File path when --ns-sink=file\n");
}

static int tls_test_parse_cli(int argc, char **argv, tls_test_cli_options_t *opts)
{
    int i;
    if(opts == NULL)
    {
        return 0;
    }

    opts->show_help = 0;
    opts->noxsight_enabled = 1;
    opts->noxsight_level = NOXSIGHT_SEVERITY_TRACE;
    opts->noxsight_module_mask = NOXTLS_LOG_MOD_HANDSHAKE |
                                 NOXTLS_LOG_MOD_RECORD |
                                 NOXTLS_LOG_MOD_X509 |
                                 NOXTLS_LOG_MOD_CRYPTO |
                                 NOXTLS_LOG_MOD_IO |
                                 NOXTLS_LOG_MOD_SESSION |
                                 NOXTLS_LOG_MOD_KEYSCHED |
                                 NOXTLS_LOG_MOD_ALERT;
    opts->noxsight_sink = "stdout";
    opts->noxsight_file_path[0] = '\0';

    for(i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if(strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        {
            opts->show_help = 1;
            continue;
        }
        if(strcmp(arg, "--noxsight-on") == 0)
        {
            opts->noxsight_enabled = 1;
            continue;
        }
        if(strcmp(arg, "--noxsight-off") == 0)
        {
            opts->noxsight_enabled = 0;
            continue;
        }
        if(strncmp(arg, "--noxsight=", 11) == 0)
        {
            if(!tls_test_parse_bool(arg + 11, &opts->noxsight_enabled))
            {
                return 0;
            }
            continue;
        }
        if(strncmp(arg, "--ns-level=", 11) == 0)
        {
            if(!tls_test_parse_level(arg + 11, &opts->noxsight_level))
            {
                return 0;
            }
            continue;
        }
        if(strncmp(arg, "--ns-mask=", 10) == 0)
        {
            char *endptr = NULL;
            unsigned long v = strtoul(arg + 10, &endptr, 0);
            if(endptr == NULL || *endptr != '\0')
            {
                return 0;
            }
            opts->noxsight_module_mask = (uint32_t)v;
            continue;
        }
        if(strncmp(arg, "--ns-modules=", 13) == 0)
        {
            if(!tls_test_parse_modules(arg + 13, &opts->noxsight_module_mask))
            {
                return 0;
            }
            continue;
        }
        if(strncmp(arg, "--ns-sink=", 10) == 0)
        {
            const char *sink = arg + 10;
            if(strcmp(sink, "stdout") != 0 && strcmp(sink, "stderr") != 0 && strcmp(sink, "file") != 0)
            {
                return 0;
            }
            opts->noxsight_sink = sink;
            continue;
        }
        if(strncmp(arg, "--ns-file=", 10) == 0)
        {
            const char *path = arg + 10;
            if(strlen(path) >= sizeof(opts->noxsight_file_path))
            {
                return 0;
            }
            strcpy(opts->noxsight_file_path, path);
            continue;
        }

        return 0;
    }

    return 1;
}

static int tls_test_noxsight_init(const tls_test_cli_options_t *opts)
{
    noxsight_sink_t sink;
    FILE *out = stdout;

    if(opts == NULL)
    {
        return 0;
    }

    if(strcmp(opts->noxsight_sink, "stderr") == 0)
    {
        out = stderr;
    }
    else if(strcmp(opts->noxsight_sink, "file") == 0)
    {
        if(opts->noxsight_file_path[0] == '\0')
        {
            printf("[TLS_TEST] --ns-sink=file requires --ns-file=<path>\n");
            return 0;
        }
#ifdef _MSC_VER
        if(fopen_s(&g_tls_test_noxsight_file, opts->noxsight_file_path, "wb") != 0)
        {
            g_tls_test_noxsight_file = NULL;
        }
#else
        g_tls_test_noxsight_file = fopen(opts->noxsight_file_path, "wb");
#endif
        if(g_tls_test_noxsight_file == NULL)
        {
            printf("[TLS_TEST] Failed to open NoxSight output file: %s\n", opts->noxsight_file_path);
            return 0;
        }
        out = g_tls_test_noxsight_file;
    }

    noxsight_init();
    sink.write = tls_test_noxsight_sink_write;
    sink.flush = tls_test_noxsight_sink_flush;
    sink.ctx = out;
    noxsight_set_sink(&sink);
    noxsight_set_severity_threshold((noxsight_severity_t)opts->noxsight_level);
    noxsight_set_module_mask(opts->noxsight_module_mask);
    printf("[TLS_TEST] NoxSight enabled: level=%u mask=0x%08X sink=%s\n",
           (unsigned)opts->noxsight_level,
           (unsigned)opts->noxsight_module_mask,
           opts->noxsight_sink);
    return 1;
}

static void tls_test_noxsight_shutdown(void)
{
    if(g_tls_test_noxsight_file != NULL)
    {
        (void)fclose(g_tls_test_noxsight_file);
        g_tls_test_noxsight_file = NULL;
    }
}
#endif

/**
 * @brief Initialize network buffer
 */
static void network_buffer_init(network_buffer_t *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->capacity = 0;
}

/**
 * @brief Append data to network buffer
 */
static noxtls_return_t network_buffer_append(network_buffer_t *buf, const uint8_t *data, uint32_t len)
{
    if(buf == NULL || data == NULL)
    {
        return NOXTLS_RETURN_NULL;
    }
    
    if(buf->capacity < buf->len + len)
    {
        uint32_t new_capacity = (buf->len + len) * 2;
        if(new_capacity < 4096) new_capacity = 4096;
        
        uint8_t *new_data = (uint8_t*)noxtls_realloc(buf->data, new_capacity);
        if(new_data == NULL)
        {
            return NOXTLS_RETURN_FAILED;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Read data from network buffer
 */
static int32_t network_buffer_read(network_buffer_t *buf, uint8_t *data, uint32_t len)
{
    if(buf == NULL || data == NULL)
    {
        return -1;
    }
    
    if(buf->len == 0)
    {
        return 0;  /* No data available */
    }
    
    uint32_t to_read = (len < buf->len) ? len : buf->len;
    memcpy(data, buf->data, to_read);
    
    /* Shift remaining data */
    if(to_read < buf->len)
    {
        memmove(buf->data, buf->data + to_read, buf->len - to_read);
    }
    buf->len -= to_read;
    
    return (int32_t)to_read;
}

/**
 * @brief Free network buffer
 */
static void network_buffer_free(network_buffer_t *buf)
{
    if(buf && buf->data)
    {
        noxtls_free(buf->data);
        buf->data = NULL;
    }
    if(buf)
    {
        buf->len = 0;
        buf->capacity = 0;
    }
}

/**
 * @brief Server send callback - sends data to client
 */
static int32_t server_send_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    network_connection_t *conn = (network_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    if(network_buffer_append(&conn->server_to_client, data, len) != NOXTLS_RETURN_SUCCESS)
    {
        return -1;
    }
    
    return (int32_t)len;
}

/**
 * @brief Server receive callback - receives data from client
 */
static int32_t server_recv_callback(void *user_data, uint8_t *data, uint32_t len)
{
    network_connection_t *conn = (network_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    return network_buffer_read(&conn->client_to_server, data, len);
}

/**
 * @brief Client send callback - sends data to server
 */
static int32_t client_send_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    network_connection_t *conn = (network_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    if(network_buffer_append(&conn->client_to_server, data, len) != NOXTLS_RETURN_SUCCESS)
    {
        return -1;
    }
    
    return (int32_t)len;
}

/**
 * @brief Client receive callback - receives data from server
 */
static int32_t client_recv_callback(void *user_data, uint8_t *data, uint32_t len)
{
    network_connection_t *conn = (network_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    return network_buffer_read(&conn->server_to_client, data, len);
}

/**
 * @brief Load test certificate from file or create a minimal one
 */
static noxtls_return_t load_or_create_test_certificate(uint8_t **cert_data, uint32_t *cert_len, const rsa_key_t *key)
{
    FILE *fp;
    const char *test_cert_file = "../../data/2048b-rsa-example-cert.der";
    
    /* Try to load existing test certificate first */
#ifdef _MSC_VER
    if (fopen_s(&fp, test_cert_file, "rb") != 0)
        fp = NULL;
#else
    fp = fopen(test_cert_file, "rb");
#endif
    if(fp != NULL)
    {
        /* Get file size */
        fseek(fp, 0, SEEK_END);
        *cert_len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        if(*cert_len > 0 && *cert_len < 16384)
        {
            *cert_data = (uint8_t*)noxtls_malloc(*cert_len);
            if(*cert_data != NULL)
            {
                if(fread(*cert_data, 1, *cert_len, fp) == *cert_len)
                {
                    fclose(fp);
                    printf("Loaded test certificate from file (%u bytes)\n", *cert_len);
                    return NOXTLS_RETURN_SUCCESS;
                }
                noxtls_free(*cert_data);
                *cert_data = NULL;
            }
        }
        fclose(fp);
    }
    
    /* If loading failed, create a minimal certificate structure */
    /* Note: This is a simplified certificate for testing - not a valid DER-encoded cert */
    /* For a real test, you would need proper ASN.1 encoding */
    printf("Creating minimal test certificate structure...\n");
    printf("WARNING: This is a simplified certificate structure for testing only.\n");
    printf("         For production use, proper DER-encoded certificates are required.\n");
    
    /* Allocate space for certificate data */
    *cert_len = 1024;
    *cert_data = (uint8_t*)noxtls_malloc(*cert_len);
    if(*cert_data == NULL)
    {
        return NOXTLS_RETURN_FAILED;
    }
    
    memset(*cert_data, 0, *cert_len);
    
    /* Create a minimal structure that contains the public key */
    /* This is NOT a valid DER-encoded certificate, but sufficient for basic testing */
    uint32_t offset = 0;
    
    /* Outer SEQUENCE tag */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x82;  /* Long form length (2 bytes) */
    (*cert_data)[offset++] = 0x03;  /* Length placeholder */
    (*cert_data)[offset++] = 0xE8;  /* Length placeholder */
    
    /* TBSCertificate SEQUENCE */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x82;  /* Long form length */
    (*cert_data)[offset++] = 0x03;  /* Length placeholder */
    (*cert_data)[offset++] = 0xD4;  /* Length placeholder */
    
    /* Version [0] EXPLICIT Version DEFAULT v1 */
    (*cert_data)[offset++] = 0xA0;  /* [0] EXPLICIT */
    (*cert_data)[offset++] = 0x03;
    (*cert_data)[offset++] = 0x02;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x02;  /* Version 3 */
    
    /* Serial Number */
    (*cert_data)[offset++] = 0x02;  /* INTEGER */
    (*cert_data)[offset++] = 0x04;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x00;
    (*cert_data)[offset++] = 0x00;
    (*cert_data)[offset++] = 0x01;
    
    /* Signature Algorithm */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x0D;
    (*cert_data)[offset++] = 0x06;  /* OID */
    (*cert_data)[offset++] = 0x09;
    (*cert_data)[offset++] = 0x2A;  /* SHA256 with RSA */
    (*cert_data)[offset++] = 0x86;
    (*cert_data)[offset++] = 0x48;
    (*cert_data)[offset++] = 0x86;
    (*cert_data)[offset++] = 0xF7;
    (*cert_data)[offset++] = 0x0D;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x0B;
    (*cert_data)[offset++] = 0x05;  /* NULL */
    (*cert_data)[offset++] = 0x00;
    
    /* Issuer */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x13;
    (*cert_data)[offset++] = 0x31;  /* SET */
    (*cert_data)[offset++] = 0x11;
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x0F;
    (*cert_data)[offset++] = 0x06;  /* OID */
    (*cert_data)[offset++] = 0x03;
    (*cert_data)[offset++] = 0x55;  /* CN */
    (*cert_data)[offset++] = 0x04;
    (*cert_data)[offset++] = 0x03;
    (*cert_data)[offset++] = 0x0C;  /* UTF8String length */
    (*cert_data)[offset++] = 0x0B;
    memcpy(*cert_data + offset, "Test Server", 11);
    offset += 11;
    
    /* Validity */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x1E;
    (*cert_data)[offset++] = 0x17;  /* UTCTime */
    (*cert_data)[offset++] = 0x0D;
    memcpy(*cert_data + offset, "250101000000Z", 13);
    offset += 13;
    (*cert_data)[offset++] = 0x17;  /* UTCTime */
    (*cert_data)[offset++] = 0x0D;
    memcpy(*cert_data + offset, "260101000000Z", 13);
    offset += 13;
    
    /* Subject (same as issuer) */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x13;
    (*cert_data)[offset++] = 0x31;  /* SET */
    (*cert_data)[offset++] = 0x11;
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x0F;
    (*cert_data)[offset++] = 0x06;  /* OID */
    (*cert_data)[offset++] = 0x03;
    (*cert_data)[offset++] = 0x55;  /* CN */
    (*cert_data)[offset++] = 0x04;
    (*cert_data)[offset++] = 0x03;
    (*cert_data)[offset++] = 0x0C;  /* UTF8String length */
    (*cert_data)[offset++] = 0x0B;
    memcpy(*cert_data + offset, "Test Server", 11);
    offset += 11;
    
    /* SubjectPublicKeyInfo */
    if(key != NULL && key->n != NULL && key->e != NULL)
    {
        (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
        uint32_t spki_start = offset;
        offset += 2;  /* Length placeholder */
        
        /* Algorithm */
        (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
        (*cert_data)[offset++] = 0x0D;
        (*cert_data)[offset++] = 0x06;  /* OID */
        (*cert_data)[offset++] = 0x09;
        (*cert_data)[offset++] = 0x2A;  /* RSA */
        (*cert_data)[offset++] = 0x86;
        (*cert_data)[offset++] = 0x48;
        (*cert_data)[offset++] = 0x86;
        (*cert_data)[offset++] = 0xF7;
        (*cert_data)[offset++] = 0x0D;
        (*cert_data)[offset++] = 0x01;
        (*cert_data)[offset++] = 0x01;
        (*cert_data)[offset++] = 0x01;
        (*cert_data)[offset++] = 0x05;  /* NULL */
        (*cert_data)[offset++] = 0x00;
        
        /* SubjectPublicKey (BIT STRING) */
        (*cert_data)[offset++] = 0x03;  /* BIT STRING */
        uint32_t bitstring_start = offset;
        offset += 2;  /* Length placeholder */
        (*cert_data)[offset++] = 0x00;  /* Unused bits */
        
        /* RSA Public Key (SEQUENCE) */
        (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
        uint32_t rsa_key_start = offset;
        offset += 2;  /* Length placeholder */
        
        /* Modulus (INTEGER) */
        uint32_t n_len = key->key_bytes;
        uint32_t n_actual = n_len;
        /* Skip leading zeros */
        for(uint32_t i = 0; i < n_len; i++)
        {
            if(key->n[i] != 0)
            {
                n_actual = n_len - i;
                break;
            }
        }
        
        (*cert_data)[offset++] = 0x02;  /* INTEGER */
        if(n_actual > 127)
        {
            (*cert_data)[offset++] = 0x82;  /* Long form */
            (*cert_data)[offset++] = (n_actual >> 8) & 0xFF;
            (*cert_data)[offset++] = n_actual & 0xFF;
        }
        else
        {
            (*cert_data)[offset++] = (uint8_t)n_actual;
        }
        memcpy(*cert_data + offset, key->n + (n_len - n_actual), n_actual);
        offset += n_actual;
        
        /* Exponent (INTEGER) */
        uint32_t e_actual = 3;  /* Usually 65537 = 0x010001 */
        (*cert_data)[offset++] = 0x02;  /* INTEGER */
        (*cert_data)[offset++] = (uint8_t)e_actual;
        (*cert_data)[offset++] = 0x01;
        (*cert_data)[offset++] = 0x00;
        (*cert_data)[offset++] = 0x01;
        
        /* Update RSA key length */
        uint32_t rsa_key_len = offset - rsa_key_start - 2;
        (*cert_data)[rsa_key_start] = (rsa_key_len >> 8) & 0xFF;
        (*cert_data)[rsa_key_start + 1] = rsa_key_len & 0xFF;
        
        /* Update BIT STRING length */
        uint32_t bitstring_len = offset - bitstring_start - 2;
        (*cert_data)[bitstring_start] = (bitstring_len >> 8) & 0xFF;
        (*cert_data)[bitstring_start + 1] = bitstring_len & 0xFF;
        
        /* Update SPKI length */
        uint32_t spki_len = offset - spki_start - 2;
        (*cert_data)[spki_start] = (spki_len >> 8) & 0xFF;
        (*cert_data)[spki_start + 1] = spki_len & 0xFF;
    }
    
    /* Signature Algorithm (same as above) */
    (*cert_data)[offset++] = 0x30;  /* SEQUENCE */
    (*cert_data)[offset++] = 0x0D;
    (*cert_data)[offset++] = 0x06;  /* OID */
    (*cert_data)[offset++] = 0x09;
    (*cert_data)[offset++] = 0x2A;  /* SHA256 with RSA */
    (*cert_data)[offset++] = 0x86;
    (*cert_data)[offset++] = 0x48;
    (*cert_data)[offset++] = 0x86;
    (*cert_data)[offset++] = 0xF7;
    (*cert_data)[offset++] = 0x0D;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x0B;
    (*cert_data)[offset++] = 0x05;  /* NULL */
    (*cert_data)[offset++] = 0x00;
    
    /* Signature Value (BIT STRING) - placeholder */
    (*cert_data)[offset++] = 0x03;  /* BIT STRING */
    (*cert_data)[offset++] = 0x82;
    (*cert_data)[offset++] = 0x01;
    (*cert_data)[offset++] = 0x00;
    (*cert_data)[offset++] = 0x00;  /* Unused bits */
    /* Fill with zeros (would be actual signature) */
    memset(*cert_data + offset, 0, 256);
    offset += 256;
    
    /* Update lengths */
    uint32_t tbs_len = offset - 8;  /* After outer SEQUENCE and length bytes */
    (*cert_data)[4] = (tbs_len >> 8) & 0xFF;
    (*cert_data)[5] = tbs_len & 0xFF;
    
    uint32_t cert_total_len = offset;
    (*cert_data)[1] = ((cert_total_len - 4) >> 8) & 0xFF;
    (*cert_data)[2] = (cert_total_len - 4) & 0xFF;
    
    *cert_len = offset;
    
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef USE_FIXED_PRIMES
/**
 * @brief Create RSA key from completely pre-generated key components (for testing)
 * 
 * Uses a completely pre-generated 1024-bit RSA key with all components.
 * This avoids ALL computations - just copies the values directly.
 * These are test values only - NOT for production use!
 */
static noxtls_return_t create_fixed_rsa_key(rsa_key_t *key, rsa_key_size_t key_size)
{
    if(key == NULL || key_size != RSA_1024_BIT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_return_t rc = noxtls_rsa_key_init(key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    uint32_t prime_len = key->key_bytes / 2;  /* 64 bytes for 512-bit prime */
    uint32_t key_bytes = key->key_bytes;      /* 128 bytes for 1024-bit key */
    
    printf("Using completely pre-generated RSA key (no computations)...\n");
    
    /* NOTE: These are PLACEHOLDER values - you need to replace with actual pre-computed RSA key components */
    /* For now, we'll use zeros as placeholders - you should generate a real key once and hardcode all values */
    
    /* For testing purposes, let's just set e (public exponent) to 65537 */
    memset(key->e, 0, key_bytes);
    key->e[key_bytes - 3] = 0x01;
    key->e[key_bytes - 2] = 0x00;
    key->e[key_bytes - 1] = 0x01;
    
    /* Set all other components to zeros for now - you need to replace with actual pre-computed values */
    /* To generate these values once, you can: */
    /* 1. Comment out USE_FIXED_PRIMES, let it generate once */
    /* 2. Print out all the key components */
    /* 3. Hardcode them here */
    
    memset(key->n, 0, key_bytes);
    memset(key->d, 0, key_bytes);
    memset(key->p, 0, prime_len);
    memset(key->q, 0, prime_len);
    memset(key->dp, 0, prime_len);
    memset(key->dq, 0, prime_len);
    memset(key->qi, 0, prime_len);
    
    printf("WARNING: Using placeholder (zero) key values!\n");
    printf("         You need to replace these with actual pre-computed RSA key components.\n");
    printf("         Generate a key once, print the values, and hardcode them here.\n");
    
    return NOXTLS_RETURN_SUCCESS;
}
#endif

int main(int argc, char **argv)
{
    noxtls_return_t rc;
#if NOXTLS_CFG_ENABLE_NOXSIGHT
    tls_test_cli_options_t opts;
    int noxsight_started = 0;
#endif
    tls12_context_t server_ctx, client_ctx;
    network_connection_t network;
    rsa_key_t server_key;
    uint8_t *test_cert = NULL;
    uint32_t test_cert_len = 0;
    uint8_t client_data[] = "Hello from client!";
    uint8_t server_data[] = "Hello from server!";
    uint8_t client_received[256];
    uint8_t server_received[256];
    uint32_t client_received_len;
    uint32_t server_received_len;
    
    printf("========================================\n");
    printf("TLS Test Application\n");
    printf("========================================\n\n");

#if NOXTLS_CFG_ENABLE_NOXSIGHT
    if(!tls_test_parse_cli(argc, argv, &opts))
    {
        tls_test_print_usage((argc > 0 && argv[0] != NULL) ? argv[0] : "tls_test");
        return 1;
    }
    if(opts.show_help)
    {
        tls_test_print_usage((argc > 0 && argv[0] != NULL) ? argv[0] : "tls_test");
        return 0;
    }
    if(opts.noxsight_enabled)
    {
        if(!tls_test_noxsight_init(&opts))
        {
            return 1;
        }
        noxsight_started = 1;
    }
    else
    {
        printf("[TLS_TEST] NoxSight disabled by command line\n");
    }
#else
    if(argc > 1 && argv != NULL)
    {
        int i;
        for(i = 1; i < argc; ++i)
        {
            if(strncmp(argv[i], "--noxsight", 10) == 0 || strncmp(argv[i], "--ns-", 5) == 0)
            {
                printf("[TLS_TEST] NoxSight options were provided, but this build has NOXTLS_CFG_ENABLE_NOXSIGHT=0\n");
                break;
            }
        }
    }
#endif
    
    /* Initialize network buffers */
    network_buffer_init(&network.server_to_client);
    network_buffer_init(&network.client_to_server);
    
    do {
        /* Initialize server context */
        printf("[1/8] Initializing server context...\n");
        rc = tls12_context_init(&server_ctx, TLS_ROLE_SERVER);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to initialize server context: %d\n", rc);
            break;
        }
    
        /* Initialize client context */
        printf("[2/8] Initializing client context...\n");
        rc = tls12_context_init(&client_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to initialize client context: %d\n", rc);
            break;
        }
        
        /* Generate or load RSA key for server */
        printf("[3/8] Setting up RSA key for server...\n");
#ifdef USE_FIXED_PRIMES
        printf("Using fixed pre-generated primes (for testing only)...\n");
        rc = create_fixed_rsa_key(&server_key, RSA_1024_BIT);
#else
        printf("Generating RSA key (this may take a moment)...\n");
        rc = noxtls_rsa_key_generate(&server_key, RSA_1024_BIT);
#endif
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to set up RSA key: %d\n", rc);
            break;
        }
        printf("RSA key ready!\n");
        
        /* Load or create test certificate */
        printf("[4/8] Loading or creating test certificate...\n");
        rc = load_or_create_test_certificate(&test_cert, &test_cert_len, &server_key);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to load/create test certificate: %d\n", rc);
            break;
        }
    
        /* Set server certificate */
        server_ctx.server_cert = test_cert;
        server_ctx.server_cert_len = test_cert_len;
        
        /* Set I/O callbacks */
        printf("[5/8] Setting up I/O callbacks...\n");
        noxtls_tls_set_io_callbacks(&server_ctx.base.base, 
                            server_send_callback, 
                            server_recv_callback, 
                            &network);
        
        noxtls_tls_set_io_callbacks(&client_ctx.base.base,
                            client_send_callback, 
                            client_recv_callback, 
                            &network);
        
        /* Perform TLS handshake */
        printf("[6/8] Performing TLS 1.2 handshake...\n");
        printf("  Note: This test performs the handshake step-by-step to show progress.\n");
        printf("  In production, you would use tls12_connect() and tls12_accept().\n\n");
        
        /* Perform handshake step by step */
        printf("  Step 1: Client Hello...\n");
        rc = tls12_send_client_hello(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Client Hello: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_client_hello(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Client Hello: %d\n", rc);
            break;
        }
    
        printf("  Step 2: Server Hello...\n");
        rc = tls12_send_server_hello(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Server Hello: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_server_hello(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Server Hello: %d\n", rc);
            break;
        }
        
        printf("  Step 3: Certificate...\n");
        printf("    Server: Sending certificate...\n");
        fflush(stdout);
        rc = tls12_send_certificate(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Certificate: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("    Server: Certificate sent successfully\n");
        printf("    Debug: server_to_client buffer length after send: %u\n", network.server_to_client.len);
        fflush(stdout);
        
        noxtls_debug_printf("    Client: Receiving certificate...\n");
        noxtls_debug_printf("    Debug: server_to_client buffer length before recv: %u\n", network.server_to_client.len);
        fflush(stdout);
        rc = tls12_recv_certificate(&client_ctx);
        noxtls_debug_printf("    Debug: tls12_recv_certificate returned: %d\n", rc);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            noxtls_debug_printf("ERROR: Failed to receive Certificate: %d\n", rc);
            noxtls_debug_printf("    Debug: server_to_client buffer length after recv: %u\n", network.server_to_client.len);
            fflush(stdout);
            break;
        }
        noxtls_debug_printf("    Client: Certificate received successfully\n");
        noxtls_debug_printf("    Debug: server_to_client buffer length after recv: %u\n", network.server_to_client.len);
        fflush(stdout);
        
        printf("  Step 4: Server Key Exchange...\n");
        rc = tls12_send_server_key_exchange(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Server Key Exchange: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_server_key_exchange(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Server Key Exchange: %d\n", rc);
            break;
        }
        
        printf("  Step 5: Server Hello Done...\n");
        rc = tls12_send_server_hello_done(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Server Hello Done: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_server_hello_done(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Server Hello Done: %d\n", rc);
            break;
        }
        
        printf("  Step 6: Client Key Exchange...\n");
        rc = tls12_send_client_key_exchange(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Client Key Exchange: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_client_key_exchange(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Client Key Exchange: %d\n", rc);
            break;
        }

        /* Compute master secrets and derive keys for both client and server */
        rc = tls12_compute_master_secret(&client_ctx, client_ctx.premaster_secret, 48);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to compute client master secret: %d\n", rc);
            break;
        }
        rc = tls12_derive_keys(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to derive client keys: %d\n", rc);
            break;
        }

        rc = tls12_compute_master_secret(&server_ctx, server_ctx.premaster_secret, 48);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to compute server master secret: %d\n", rc);
            break;
        }
        rc = tls12_derive_keys(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to derive server keys: %d\n", rc);
            break;
        }

        printf("[TLS_TEST] client premaster[0..3]=%02X%02X%02X%02X master[0..3]=%02X%02X%02X%02X\n",
               client_ctx.premaster_secret[0], client_ctx.premaster_secret[1],
               client_ctx.premaster_secret[2], client_ctx.premaster_secret[3],
               client_ctx.master_secret[0], client_ctx.master_secret[1],
               client_ctx.master_secret[2], client_ctx.master_secret[3]);
        printf("[TLS_TEST] server premaster[0..3]=%02X%02X%02X%02X master[0..3]=%02X%02X%02X%02X\n",
               server_ctx.premaster_secret[0], server_ctx.premaster_secret[1],
               server_ctx.premaster_secret[2], server_ctx.premaster_secret[3],
               server_ctx.master_secret[0], server_ctx.master_secret[1],
               server_ctx.master_secret[2], server_ctx.master_secret[3]);
        printf("[TLS_TEST] client keys: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X "
               "skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
               client_ctx.client_write_key[0], client_ctx.client_write_key[1],
               client_ctx.client_write_key[2], client_ctx.client_write_key[3],
               client_ctx.client_write_iv[0], client_ctx.client_write_iv[1],
               client_ctx.client_write_iv[2], client_ctx.client_write_iv[3],
               client_ctx.server_write_key[0], client_ctx.server_write_key[1],
               client_ctx.server_write_key[2], client_ctx.server_write_key[3],
               client_ctx.server_write_iv[0], client_ctx.server_write_iv[1],
               client_ctx.server_write_iv[2], client_ctx.server_write_iv[3]);
        printf("[TLS_TEST] server keys: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X "
               "skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
               server_ctx.client_write_key[0], server_ctx.client_write_key[1],
               server_ctx.client_write_key[2], server_ctx.client_write_key[3],
               server_ctx.client_write_iv[0], server_ctx.client_write_iv[1],
               server_ctx.client_write_iv[2], server_ctx.client_write_iv[3],
               server_ctx.server_write_key[0], server_ctx.server_write_key[1],
               server_ctx.server_write_key[2], server_ctx.server_write_key[3],
               server_ctx.server_write_iv[0], server_ctx.server_write_iv[1],
               server_ctx.server_write_iv[2], server_ctx.server_write_iv[3]);
        
        printf("  Step 7: Change Cipher Spec (Client -> Server)...\n");
        rc = tls12_send_change_cipher_spec(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Change Cipher Spec: %d\n", rc);
            break;
        }
        
        rc = tls12_recv_change_cipher_spec_client(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Change Cipher Spec: %d\n", rc);
            break;
        }
        
        printf("  Step 8: Finished (Client -> Server)...\n");
        rc = tls12_send_finished(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Finished: %d\n", rc);
            break;
        }
        
        printf("[TLS_TEST] server keys pre-recv-finished: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X "
               "skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
               server_ctx.client_write_key[0], server_ctx.client_write_key[1],
               server_ctx.client_write_key[2], server_ctx.client_write_key[3],
               server_ctx.client_write_iv[0], server_ctx.client_write_iv[1],
               server_ctx.client_write_iv[2], server_ctx.client_write_iv[3],
               server_ctx.server_write_key[0], server_ctx.server_write_key[1],
               server_ctx.server_write_key[2], server_ctx.server_write_key[3],
               server_ctx.server_write_iv[0], server_ctx.server_write_iv[1],
               server_ctx.server_write_iv[2], server_ctx.server_write_iv[3]);
        rc = tls12_recv_finished_client(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Finished: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server received client Finished successfully\n");
        fflush(stdout);
        
        printf("  Step 9: Change Cipher Spec (Server -> Client)...\n");
        rc = tls12_send_change_cipher_spec_server(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Change Cipher Spec: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server sent Change Cipher Spec\n");
        fflush(stdout);
        
        rc = tls12_recv_change_cipher_spec(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Change Cipher Spec: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Client received Change Cipher Spec\n");
        fflush(stdout);
        
        printf("  Step 10: Finished (Server -> Client)...\n");
        rc = tls12_send_finished_server(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Finished: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server sent Finished\n");
        fflush(stdout);
        
        rc = tls12_recv_finished(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Finished: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Client received server Finished successfully\n");
        fflush(stdout);
        
        /* Mark contexts as connected */
        server_ctx.base.base.state = TLS_STATE_CONNECTED;
        client_ctx.base.base.state = TLS_STATE_CONNECTED;
        
        printf("\nTLS handshake completed successfully!\n");
        printf("Key derivation fully implemented - encryption/decryption ready.\n\n");
        
        /* Exchange application data */
        printf("[7/8] Exchanging application data...\n");
        
        /* Client sends data to server */
        printf("  Client: Sending data: \"%s\"\n", client_data);
        hex_dump("  Client: Sending bytes", (const uint8_t*)client_data, (uint32_t)(sizeof(client_data) - 1));
        rc = tls12_send(&client_ctx, client_data, sizeof(client_data) - 1);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send data from client: %d\n", rc);
            break;
        }
        
        printf("  Server: Receiving data...\n");
        server_received_len = sizeof(server_received);
        rc = tls12_recv(&server_ctx, server_received, &server_received_len);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive data on server: %d\n", rc);
            break;
        }
        server_received[server_received_len] = '\0';
        printf("  Server: Received: \"%s\"\n", server_received);
        hex_dump("  Server: Received bytes", server_received, server_received_len);
        
        /* Server sends data to client */
        printf("  Server: Sending data: \"%s\"\n", server_data);
        hex_dump("  Server: Sending bytes", (const uint8_t*)server_data, (uint32_t)(sizeof(server_data) - 1));
        rc = tls12_send(&server_ctx, server_data, sizeof(server_data) - 1);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send data from server: %d\n", rc);
            break;
        }
        
        printf("  Client: Receiving data...\n");
        client_received_len = sizeof(client_received);  /* in: buffer size; out: bytes received */
        rc = tls12_recv(&client_ctx, client_received, &client_received_len);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive data on client: %d\n", rc);
            break;
        }
        client_received[client_received_len] = '\0';
        printf("  Client: Received: \"%s\"\n", client_received);
        hex_dump("  Client: Received bytes", client_received, client_received_len);
        
        /* Verify data matches */
        printf("[8/8] Verifying data integrity...\n");
        
        int client_match = (memcmp(client_data, server_received, sizeof(client_data) - 1) == 0);
        int server_match = (memcmp(server_data, client_received, sizeof(server_data) - 1) == 0);
        
        if(client_match && server_match)
        {
            printf("\n========================================\n");
            printf("SUCCESS: All tests passed!\n");
            printf("========================================\n");
            printf("OK: Client data encrypted and decrypted correctly\n");
            printf("OK: Server data encrypted and decrypted correctly\n");
            printf("OK: TLS encryption/decryption is working properly\n");
            printf("========================================\n");
            rc = NOXTLS_RETURN_SUCCESS;
        }
        else
        {
            printf("\n========================================\n");
            printf("FAILURE: Data mismatch detected!\n");
            printf("========================================\n");
            if(!client_match)
            {
                printf("FAIL: Client data mismatch:\n");
                printf("  Expected: \"%s\"\n", client_data);
                printf("  Received: \"%s\"\n", server_received);
            }
            if(!server_match)
            {
                printf("FAIL: Server data mismatch:\n");
                printf("  Expected: \"%s\"\n", server_data);
                printf("  Received: \"%s\"\n", client_received);
            }
            printf("========================================\n");
            rc = NOXTLS_RETURN_FAILED;
        }
    } while(0);

    printf("\n========================================\n");
    if(rc == NOXTLS_RETURN_SUCCESS) {
        printf("FINAL RESULT: SUCCESS\n");
    } else {
        printf("FINAL RESULT: FAILURE (rc=%d)\n", rc);
    }
    printf("========================================\n");
    fflush(stdout);

#if NOXTLS_CFG_ENABLE_NOXSIGHT
    if(noxsight_started)
    {
        noxsight_flush();
        tls_test_noxsight_shutdown();
    }
#endif
    
    /* Cleanup */
    if(test_cert)
    {
        noxtls_free(test_cert);
    }
    
    noxtls_rsa_key_free(&server_key);
    tls12_context_free(&server_ctx);
    tls12_context_free(&client_ctx);
    network_buffer_free(&network.server_to_client);
    network_buffer_free(&network.client_to_server);
    
    return (rc == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

