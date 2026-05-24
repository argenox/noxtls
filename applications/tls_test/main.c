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
* This file is part of the NoxTLS Library.
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
 * @brief TLS test client â€” handshake and encryption/decryption verification.
 * @defgroup noxtls_app_tls_test TLS test
 * @details
 * In-process test: creates TLS server and client, connects via callbacks,
 * performs handshake and verifies encryption/decryption. No command-line
 * parameters required; run from project or build directory.
 * Mutual TLS with Ed25519 uses noxtls_tls13_set_client_cert_ed25519; with Ed448 (when
 * NOXTLS_CFG_FEATURE_ED448 and SHA-3 are enabled) use noxtls_tls13_set_client_cert_ed448
 * and an id-Ed448 client certificate.
 * @example
 * tls_test
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

static const char *tls_test_cert_paths[] = {
    "applications/tls_test/testdata/tls_test_server_cert.der",
    "../applications/tls_test/testdata/tls_test_server_cert.der",
    "../../applications/tls_test/testdata/tls_test_server_cert.der",
    "../../../applications/tls_test/testdata/tls_test_server_cert.der"
};

static const char *tls_test_key_paths[] = {
    "applications/tls_test/testdata/tls_test_server_key.der",
    "../applications/tls_test/testdata/tls_test_server_key.der",
    "../../applications/tls_test/testdata/tls_test_server_key.der",
    "../../../applications/tls_test/testdata/tls_test_server_key.der"
};

static const uint8_t tls_test_ocsp_response_der[] = {
    0x30, 0x03, 0x0A, 0x01, 0x00
};

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

/**
 * @brief Dump the hexadecimal data
 *
 * @param[in] label The label to dump the hexadecimal data from
 * @param[in] data The data to dump the hexadecimal data from
 * @param[in] len The length of the data to dump the hexadecimal data from
 * @return void
 */
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

/**
 * @brief Write the NoxSight sink
 *
 * @param[in] ctx The context to write the NoxSight sink from
 * @param[in] data The data to write the NoxSight sink from
 * @param[in] len The length of the data to write the NoxSight sink from
 * @return void
 */
static void tls_test_noxsight_sink_write(void *ctx, const uint8_t *data, size_t len)
{
    FILE *out = (FILE *)ctx;
    if(out == NULL || data == NULL || len == 0U)
    {
        return;
    }

    (void)fwrite(data, 1U, len, out);
}

/**
 * @brief Flush the NoxSight sink
 *
 * @param[in] ctx The context to flush the NoxSight sink from
 * @return void
 */
static void tls_test_noxsight_sink_flush(void *ctx)
{
    FILE *out = (FILE *)ctx;
    if(out != NULL)
    {
        (void)fflush(out);
    }
}

/**
 * @brief Parse the boolean value
 *
 * @param[in] value The value to parse the boolean value from
 * @param[out] out_bool The output to parse the boolean value into
 * @return The return code
 */
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

/**
 * @brief Parse the level
 *
 * @param[in] value The value to parse the level from
 * @param[out] out_level The output to parse the level into
 * @return The return code
 */
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

/**
 * @brief Try to add a module to the mask
 *
 * @param[in] mask The mask to try to add the module to
 * @param[in] name The name of the module to try to add to the mask
 * @return 1 if the module was added to the mask, 0 otherwise
 */
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

/**
 * @brief Parse the modules
 *
 * @param[in] value The value to parse the modules from
 * @param[out] out_mask The output to parse the modules into
 * @return The return code
 */
static int tls_test_parse_modules(const char *value, uint32_t *out_mask)
{
    char tmp[256];
    char *token;
    uint32_t mask = 0U;

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
        *out_mask = 0U;
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

/**
 * @brief Print the usage information
 *
 * @param[in] prog The program name
 * @return void
 */
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

/**
 * @brief Parse the command line arguments
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[out] opts The options to parse the command line arguments into
 * @return The return code
 */
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

/**
 * @brief Initialize the NoxSight
 *
 * @param[in] opts The options to initialize the NoxSight from
 * @return The return code
 */
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

/**
 * @brief Shutdown the NoxSight
 *
 * @return void
 */
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
 *
 * @param[in] buf The buffer to initialize the network buffer from
 * @return void
 */
static void network_buffer_init(network_buffer_t *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->capacity = 0;
}

/**
 * @brief Append data to network buffer
 *
 * @param[in] buf The buffer to append the data to
 * @param[in] data The data to append to the buffer
 * @param[in] len The length of the data to append to the buffer
 * @return The return code
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
 *
 * @param[in] buf The buffer to read the data from
 * @param[out] data The data to read from the buffer
 * @param[in] len The length of the data to read from the buffer
 * @return The return code
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
 *
 * @param[in] buf The buffer to free the network buffer from
 * @return void
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
 *
 * @param[in] user_data The user data to send the data to
 * @param[in] data The data to send to the client
 * @param[in] len The length of the data to send to the client
 * @return The return code
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
 *
 * @param[in] user_data The user data to receive the data from
 * @param[out] data The data to receive from the client
 * @param[in] len The length of the data to receive from the client
 * @return The return code
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
 *
 * @param[in] user_data The user data to send the data to
 * @param[in] data The data to send to the server
 * @param[in] len The length of the data to send to the server
 * @return The return code
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
 *
 * @param[in] user_data The user data to receive the data from
 * @param[out] data The data to receive from the server
 * @param[in] len The length of the data to receive from the server
 * @return The return code
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
 * @brief Check if the cipher suite uses server key exchange
 *
 * @param[in] suite The cipher suite to check if it uses server key exchange from
 * @return 1 if the cipher suite uses server key exchange, 0 otherwise
 */
static int tls_test_cipher_suite_uses_server_key_exchange(uint16_t suite)
{
    switch(suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
            return 0;
        default:
            return 1;
    }
}

/**
 * @brief Load deterministic test certificate DER bytes from configured path list.
 * @param cert_data Output DER certificate buffer (caller owns/free with noxtls_free).
 * @param cert_len Output DER certificate length.
 * @return NOXTLS_RETURN_SUCCESS on success, failure code otherwise.
 */
static noxtls_return_t tls_test_load_certificate(uint8_t **cert_data, uint32_t *cert_len)
{
    noxtls_return_t rc;
    uint32_t i;
    x509_certificate_t cert;

    if(cert_data == NULL || cert_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *cert_data = NULL;
    *cert_len = 0;

    noxtls_x509_certificate_init(&cert);
    rc = NOXTLS_RETURN_FAILED;
    for(i = 0; i < (uint32_t)(sizeof(tls_test_cert_paths) / sizeof(tls_test_cert_paths[0])); i++) {
        rc = noxtls_x509_certificate_load_file(&cert, tls_test_cert_paths[i]);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            break;
        }
    }
    if(rc != NOXTLS_RETURN_SUCCESS || cert.raw_data == NULL || cert.raw_data_len == 0) {
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_FAILED;
    }

    *cert_data = (uint8_t*)noxtls_malloc(cert.raw_data_len);
    if(*cert_data == NULL) {
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    memcpy(*cert_data, cert.raw_data, cert.raw_data_len);
    *cert_len = cert.raw_data_len;
    noxtls_x509_certificate_free(&cert);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Load deterministic RSA private key from configured PEM path list.
 * @param server_key Output RSA key used by TLS 1.2 server path.
 * @return NOXTLS_RETURN_SUCCESS on success, failure code otherwise.
 */
static noxtls_return_t tls_test_load_server_key(rsa_key_t *server_key)
{
    noxtls_return_t rc;
    uint32_t i;
    x509_private_key_t key;

    if(server_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_x509_private_key_init(&key);
    rc = NOXTLS_RETURN_FAILED;
    for(i = 0; i < (uint32_t)(sizeof(tls_test_key_paths) / sizeof(tls_test_key_paths[0])); i++) {
        rc = noxtls_x509_private_key_load_file(&key, tls_test_key_paths[i]);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            break;
        }
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_private_key_free(&key);
        return rc;
    }

    rc = noxtls_x509_private_key_to_rsa_key(&key, server_key);
    noxtls_x509_private_key_free(&key);
    return rc;
}

/**
 * @brief Main function
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
int main(int argc, char **argv)
{
    noxtls_return_t rc;
    int ocsp_only = 0;
#if NOXTLS_CFG_ENABLE_NOXSIGHT
    tls_test_cli_options_t opts;
    int noxsight_started = 0;
#endif
    tls12_context_t server_ctx;
    tls12_context_t client_ctx;
    network_connection_t network;
    rsa_key_t server_key;
    uint8_t *test_cert = NULL;
    uint32_t test_cert_len = 0;
    x509_certificate_t trust_anchor;
    x509_certificate_chain_t trust_chain;
    uint8_t trust_anchor_initialized = 0;
    uint8_t trust_chain_initialized = 0;
    uint8_t client_data[] = "Hello from client!";
    uint8_t server_data[] = "Hello from server!";
    uint8_t client_received[256];
    uint8_t server_received[256];
    uint32_t client_received_len;
    uint32_t server_received_len;
    
    printf("========================================\n");
    printf("TLS Test Application\n");
    printf("========================================\n\n");

    for(int argi = 1; argi < argc; argi++) {
        if(argv[argi] != NULL && strcmp(argv[argi], "--ocsp-only") == 0) {
            ocsp_only = 1;
        }
    }

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
        rc = noxtls_tls12_context_init(&server_ctx, TLS_ROLE_SERVER);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to initialize server context: %d\n", rc);
            break;
        }
    
        /* Initialize client context */
        printf("[2/8] Initializing client context...\n");
        rc = noxtls_tls12_context_init(&client_ctx, TLS_ROLE_CLIENT);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to initialize client context: %d\n", rc);
            break;
        }
        
        /* Generate or load RSA key for server */
        printf("[3/8] Setting up RSA key for server...\n");
        rc = tls_test_load_server_key(&server_key);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to load deterministic RSA key: %d\n", rc);
            break;
        }
        printf("RSA key loaded from testdata.\n");
        
        /* Load deterministic test certificate */
        printf("[4/8] Loading deterministic test certificate...\n");
        rc = tls_test_load_certificate(&test_cert, &test_cert_len);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to load deterministic test certificate: %d\n", rc);
            break;
        }
    
        /* Set server certificate */
        server_ctx.server_cert = test_cert;
        server_ctx.server_cert_len = test_cert_len;

        /* Configure client trust anchors (self-signed test cert is trusted explicitly). */
        noxtls_x509_certificate_init(&trust_anchor);
        trust_anchor_initialized = 1;
        rc = noxtls_x509_certificate_parse_der(&trust_anchor, test_cert, test_cert_len);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to parse test certificate for trust store: %d\n", rc);
            break;
        }
        rc = noxtls_x509_certificate_chain_init(&trust_chain);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to init trust chain: %d\n", rc);
            break;
        }
        trust_chain_initialized = 1;
        rc = noxtls_x509_certificate_chain_add(&trust_chain, &trust_anchor);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to add trust anchor: %d\n", rc);
            break;
        }
        rc = noxtls_x509_trust_store_set(&trust_chain);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to configure trust store: %d\n", rc);
            break;
        }
        
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
        noxtls_tls12_set_client_request_ocsp_status(&client_ctx, 1);
        noxtls_tls12_set_server_ocsp_response(&server_ctx,
                                              tls_test_ocsp_response_der,
                                              (uint32_t)sizeof(tls_test_ocsp_response_der));
        
        /* Perform TLS handshake */
        printf("[6/8] Performing TLS 1.2 handshake...\n");
        printf("  Note: This test performs the handshake step-by-step to show progress.\n");
        printf("  In production, you would use noxtls_tls12_connect() and noxtls_tls12_accept().\n\n");
        
        /* Perform handshake step by step */
        printf("  Step 1: Client Hello...\n");
        rc = noxtls_tls12_send_client_hello(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Client Hello: %d\n", rc);
            break;
        }
        
        rc = noxtls_tls12_recv_client_hello(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Client Hello: %d\n", rc);
            break;
        }
    
        printf("  Step 2: Server Hello...\n");
        rc = noxtls_tls12_send_server_hello(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Server Hello: %d\n", rc);
            break;
        }
        
        rc = noxtls_tls12_recv_server_hello(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Server Hello: %d\n", rc);
            break;
        }
        
        printf("  Step 3: Certificate...\n");
        printf("    Server: Sending certificate...\n");
        fflush(stdout);
        rc = noxtls_tls12_send_certificate(&server_ctx);
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
        rc = noxtls_tls12_recv_certificate(&client_ctx);
        noxtls_debug_printf("    Debug: noxtls_tls12_recv_certificate returned: %d\n", rc);
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
        {
            const uint8_t *peer_ocsp = NULL;
            uint32_t peer_ocsp_len = 0;
            rc = noxtls_tls12_get_peer_ocsp_response(&client_ctx, &peer_ocsp, &peer_ocsp_len);
            if(rc != NOXTLS_RETURN_SUCCESS ||
               peer_ocsp == NULL ||
               peer_ocsp_len != (uint32_t)sizeof(tls_test_ocsp_response_der) ||
               memcmp(peer_ocsp, tls_test_ocsp_response_der, sizeof(tls_test_ocsp_response_der)) != 0) {
                printf("ERROR: OCSP stapling regression check failed (rc=%d len=%u)\n", rc, peer_ocsp_len);
                break;
            }
            printf("    Client: OCSP stapling response received and verified (%u bytes)\n", peer_ocsp_len);
            if(ocsp_only) {
                printf("    OCSP-only mode: stopping after stapling regression check.\n");
                rc = NOXTLS_RETURN_SUCCESS;
                break;
            }
        }
        
        if(tls_test_cipher_suite_uses_server_key_exchange(client_ctx.cipher_suite)) {
            printf("  Step 4: Server Key Exchange...\n");
            rc = noxtls_tls12_send_server_key_exchange(&server_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS)
            {
                printf("ERROR: Failed to send Server Key Exchange: %d\n", rc);
                break;
            }
            
            rc = noxtls_tls12_recv_server_key_exchange(&client_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS)
            {
                printf("ERROR: Failed to receive Server Key Exchange: %d\n", rc);
                break;
            }
        } else {
            printf("  Step 4: Server Key Exchange skipped for RSA key exchange suite 0x%04X\n", client_ctx.cipher_suite);
        }
        
        printf("  Step 5: Server Hello Done...\n");
        rc = noxtls_tls12_send_server_hello_done(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Server Hello Done: %d\n", rc);
            break;
        }
        
        rc = noxtls_tls12_recv_server_hello_done(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Server Hello Done: %d\n", rc);
            break;
        }
        
        printf("  Step 6: Client Key Exchange...\n");
        rc = noxtls_tls12_send_client_key_exchange(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Client Key Exchange: %d\n", rc);
            break;
        }
        
        rc = noxtls_tls12_recv_client_key_exchange(&server_ctx);
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
        rc = noxtls_tls12_send_change_cipher_spec(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Change Cipher Spec: %d\n", rc);
            break;
        }
        
        rc = noxtls_tls12_recv_change_cipher_spec_client(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Change Cipher Spec: %d\n", rc);
            break;
        }
        
        printf("  Step 8: Finished (Client -> Server)...\n");
        rc = noxtls_tls12_send_finished(&client_ctx);
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
        rc = noxtls_tls12_recv_finished_client(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Finished: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server received client Finished successfully\n");
        fflush(stdout);
        
        printf("  Step 9: Change Cipher Spec (Server -> Client)...\n");
        rc = noxtls_tls12_send_change_cipher_spec_server(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Change Cipher Spec: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server sent Change Cipher Spec\n");
        fflush(stdout);
        
        rc = noxtls_tls12_recv_change_cipher_spec(&client_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to receive Change Cipher Spec: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Client received Change Cipher Spec\n");
        fflush(stdout);
        
        printf("  Step 10: Finished (Server -> Client)...\n");
        rc = noxtls_tls12_send_finished_server(&server_ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send Finished: %d\n", rc);
            fflush(stdout);
            break;
        }
        printf("[TLS_TEST] Server sent Finished\n");
        fflush(stdout);
        
        rc = noxtls_tls12_recv_finished(&client_ctx);
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
        rc = noxtls_tls12_send(&client_ctx, client_data, sizeof(client_data) - 1);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send data from client: %d\n", rc);
            break;
        }
        
        printf("  Server: Receiving data...\n");
        server_received_len = sizeof(server_received);
        rc = noxtls_tls12_recv(&server_ctx, server_received, &server_received_len);
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
        rc = noxtls_tls12_send(&server_ctx, server_data, sizeof(server_data) - 1);
        if(rc != NOXTLS_RETURN_SUCCESS)
        {
            printf("ERROR: Failed to send data from server: %d\n", rc);
            break;
        }
        
        printf("  Client: Receiving data...\n");
        client_received_len = sizeof(client_received);  /* in: buffer size; out: bytes received */
        rc = noxtls_tls12_recv(&client_ctx, client_received, &client_received_len);
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
    noxtls_x509_trust_store_clear();
    if(trust_chain_initialized)
    {
        noxtls_x509_certificate_chain_free(&trust_chain);
    }
    if(trust_anchor_initialized)
    {
        noxtls_x509_certificate_free(&trust_anchor);
    }
    
    noxtls_rsa_key_free(&server_key);
    noxtls_tls12_context_free(&server_ctx);
    noxtls_tls12_context_free(&client_ctx);
    network_buffer_free(&network.server_to_client);
    network_buffer_free(&network.client_to_server);
    
    return (rc == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

