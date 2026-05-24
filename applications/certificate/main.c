/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    main.c
* Summary: Certificate handling application
*
*/

/**
 * @file main.c
 * @brief Certificate handling utility (GCC/MinGW; may be excluded with MSVC).
 * @defgroup noxtls_app_certificate Certificate application
 * @details
 * Demo application that loads a sample certificate from disk and displays
 * or processes it. Options: -v version, -h help. Primarily for testing
 * certificate loading; see cert utility for full CLI operations.
 * @example
 * certificate
 * certificate -h
 * certificate -v
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
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "utility/utility.h"
#include "noxtls-lib/certs/asn1.h"
#include "utility/base64.h"
#include "noxtls-lib/certs/certificates.h"

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

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


typedef struct {
    char cmd[32];
    int (*handler)(int argc, char ** argv);
    char description[256];

} command_list_t;


command_list_t commands[]  = {
    /* {"dgst", &message_digest, "Generates the noxtls_message digest"} */
};
#define NUM_COMMANDS 0

/**
 * @brief Print usage information and supported commands.
 *
 * @param[in] name Program name (argv[0])
 * @return void
 */
void print_usage(const char * name)
{
    printf( "usage: %s [command] <parameters>\n", name);
    printf("\nSupported Commands\n\n");

    int i;
    for(i = 0; i < NUM_COMMANDS; i++)
    {
        printf("%s  \t\t\t%s\n", commands[i].cmd, commands[i].description);
    }

    printf("\nCommandline Switches\n\n");

    printf("-v \t\t\tVersion Information\n");
    printf("-h \t\t\tHelp\n");    

    printf("\n\n");
}

/**
 * @brief Print version and build information.
 *
 * @return void
 */
void print_version(void)
{
    printf("NoxTLS v%u.%u.%u\n", (unsigned int)APP_VERSION_MAJOR, (unsigned int)APP_VERSION_MINOR, (unsigned int)APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}

/**
 * @brief Certificate demo entry point; loads, converts, and writes sample certs.
 *
 * @param[in] argc Argument count (currently unused)
 * @param[in] argv Command-line arguments (currently unused)
 * @return 0 on success, -1 on allocation failure
 */
int main(int argc, char ** argv)
{
    uint8_t * buffer = NULL;

    (void)argc;
    (void)argv;

    int res = noxtls_load_file("../../data/2048b-rsa-example-cert.der", &buffer);

    printf("Result: %d\n", res);

    if(res > 0) 
        noxtls_parse_der(buffer, res);

    printf("res: \n");

    uint32_t output_len = res * 4;
    output_len /= 3;

    if(output_len < 4)
        output_len = 4;
    
    uint8_t * cert_output = NULL;
    cert_output = (uint8_t *) malloc(sizeof(uint8_t) * output_len * 2);
    if(cert_output == NULL) {
        return -1;
    }
    memset(cert_output, 0, sizeof(uint8_t) * output_len * 2);
    uint32_t pem_cert_length = 0;

    /*int pem_cert_length = noxtls_base64_encode(buffer, res, (char *)cert_output);
    if(pem_cert_length != output_len) {
        printf("Output Length Error: %d != %d\n", pem_cert_length, output_len);
    }*/


    noxtls_certificate_der_to_pem(buffer, res, cert_output, &pem_cert_length);

    noxtls_write_text_file("2048b-rsa-example-cert.pem", cert_output, pem_cert_length);
    free(buffer);

    printf("Loading PEM\n");
    res = noxtls_load_text_file("2048b-rsa-example-cert.pem", &buffer);
    uint32_t der_cert_length = 0;
    memset(cert_output, 0, sizeof(uint8_t) * output_len * 2);

    printf("Result: %d\n", res);
    noxtls_certificate_pem_to_der(buffer, res, cert_output, &der_cert_length);

    printf("DER LEngth: %u\n", (unsigned int)der_cert_length);
    noxtls_write_file("2048b-rsa-example-cert.der", cert_output, der_cert_length);
    free(buffer);



    return 0;    
}