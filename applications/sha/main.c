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
* Summary: SHA / noxtls_message digest application
*
*/

/**
 * @file main.c
 * @brief Message digest (SHA, MD5, etc.) command-line utility.
 * @defgroup noxtls_app_sha SHA utility
 * @details
 * Command-line tool to compute noxtls_message digests (hashes) using NoxTLS mdigest.
 * Parameters: specify the algorithm name, then optional switches and input
 * (string or hex).
 * Options:
 *   -v          Version information
 *   -h          Help (global); after an algorithm, interpret text input as hex
 *   -d          Enable debug output
 * Algorithms include enabled NoxTLS digests such as MD5, SHA1, SHA2, SHA3,
 * RIPEMD-160, BLAKE2, and MD4 when feature-enabled.
 * @example
 * Hash a string with SHA-256:
 *   sha SHA256 hello world
 * Hash from hex input:
 *   sha SHA256 -h 68656c6c6f
 * Show help and version:
 *   sha -h
 *   sha -v
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

#include "noxtls-lib/common/getopt_compat.h"
#include "message_digest.h"

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
 * @param[in] p The pointer to the workspace to free.
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

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


/**
 * @brief Print the usage
 * 
 * @param[in] name The name of the program.
 * @return void
 */
void print_usage(const char * name)
{
    printf("usage: %s <algorithm> [options] [text...]\n", name);
    printf("       %s <algorithm> -f <file> [options]\n", name);

    printf("\nCommandline Switches\n\n");

    printf("-v \t\t\tVersion Information\n");
    printf("-h \t\t\tHelp\n");

    printf("\n\n");
}

/**
 * @brief Print the version
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
 * @brief Main entry point
 *
 * @param[in] argc The argument count
 * @param[in] argv The argument vector
 * @return The return value
 */
int main(int argc, char ** argv)
{
    /* check for command line arguments */
    if (argc < 2)
    {
        print_digest_usage();
        return 0;
    }

    if(strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }
    if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_digest_usage();
        return 0;
    }

    return message_digest(argc - 1, &argv[1]);
}
