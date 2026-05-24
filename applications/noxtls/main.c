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
* Summary: NoxTLS Utility Main Application
*
*/

/**
 * @file main.c
 * @brief Multi-command NoxTLS CLI (e.g. noxtls_message digest).
 * @defgroup noxtls_app_noxtls NoxTLS CLI
 * @details
 * Unified CLI with subcommands. Command: dgst â€” noxtls_message digest (same as sha app).
 * Parameters: command then algorithm/options/input. Options: -v version, -h help.
 * @example
 * noxtls dgst SHA256 hello world
 * noxtls dgst MD5 -h 48656c6c6f
 * noxtls -h
 * noxtls -v
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
#include "encryption_command.h"
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

extern int noxtls_pkc_app_main(int argc, char ** argv);
extern int noxtls_cert_app_main(int argc, char ** argv);

static int pkc_command(int argc, char ** argv);
static int cert_command(int argc, char ** argv);


typedef struct {
    char cmd[32];
    int (*handler)(int argc, char ** argv);
    char description[256];

} command_list_t;


command_list_t commands[]  = {
    {"dgst", &message_digest, "Generates the noxtls_message digest"},
    {"enc", &encryption_encrypt_command, "Encrypts data"},
    {"dec", &encryption_decrypt_command, "Decrypts data"},
    {"pkc", &pkc_command, "Public/private key operations"},
    {"key", &pkc_command, "Public/private key operations"},
    {"cert", &cert_command, "X.509 certificate operations"},
    {"x509", &cert_command, "X.509 certificate operations"}
};



/**
 * @brief Print usage information and supported subcommands.
 *
 * @param[in] name Program name (argv[0])
 * @return void
 */
void print_usage(const char * name)
{
    printf( "usage: %s [command] <parameters>\n", name);
    printf("\nSupported Commands\n\n");

    size_t i = 0;
    size_t command_count = sizeof(commands) / sizeof(commands[0]);
    for(i = 0; i < command_count; i++)
    {
        printf("%s  \t\t\t%s\n", commands[i].cmd, commands[i].description);
    }

    printf("\nCommandline Switches\n\n");

    printf("-v \t\t\tVersion Information\n");
    printf("-h \t\t\tHelp\n");    

    printf("\nRun '%s dgst --help' to list available digest algorithms.\n", name);
    printf("Run '%s enc --help' or '%s dec --help' to list available encryption algorithms.\n", name, name);
    printf("Run '%s pkc --help' to list public/private key operations.\n", name);
    printf("Run '%s cert --help' to list X.509 certificate operations.\n", name);
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
 * @brief NoxTLS CLI entry point; dispatches to subcommands or global options.
 *
 * @param[in] argc Argument count
 * @param[in] argv Command-line arguments; argv[1] is the subcommand when present
 * @return Subcommand exit code, 0 for -v/-h, or -1 on missing command
 */
int main(int argc, char ** argv)
{
    int command_found = 0;

    /* check for command line arguments */
    if (argc < 2)
    {
        print_usage(argv[0]);
        return -1;
    }

    /* Find top level command */
    size_t i = 0;
    size_t command_count = sizeof(commands) / sizeof(commands[0]);
    for(i = 0; i < command_count; i++)
    {
        if(strncmp(argv[1], commands[i].cmd, strlen(commands[i].cmd)) == 0 &&
           strlen(argv[1]) == strlen(commands[i].cmd))
        {
            return commands[i].handler(argc - 2, &argv[2]);
        }
    }

    if(command_found == 0)
    {
        int c;
        while ((c = noxtls_getopt (argc, argv, "vh")) != -1)
        {
            switch (c)
            {
                case 'v':
                    print_version();
                    break;
                case 'h':
                    print_usage(argv[0]);
                    break;

            }
        }
    }

    return 0;    
}

/**
 * @brief Forward arguments to an embedded sub-application main().
 *
 * Prepends @p app_name as argv[0] before invoking @p app_main.
 *
 * @param[in] app_main Embedded sub-application main function
 * @param[in] app_name Synthetic argv[0] for the sub-application
 * @param[in] argc Number of arguments in @p argv
 * @param[in] argv Arguments to forward (excluding program name)
 * @return Return code from @p app_main, or -1 on error
 */
static int dispatch_embedded_app(
    int (*app_main)(int argc, char ** argv),
    const char * app_name,
    int argc,
    char ** argv)
{
    char ** forwarded_argv = NULL;
    int i;
    int rc;

    if(app_main == NULL || app_name == NULL) {
        return -1;
    }

    forwarded_argv = malloc(sizeof(char *) * (size_t)(argc + 1));
    if(forwarded_argv == NULL) {
        printf("Error: memory allocation failed\n");
        return -1;
    }

    forwarded_argv[0] = (char *)app_name;
    for(i = 0; i < argc; i++) {
        forwarded_argv[i + 1] = argv[i];
    }

    rc = app_main(argc + 1, forwarded_argv);
    free(forwarded_argv);
    return rc;
}

/**
 * @brief Handle the pkc/key subcommand.
 *
 * @param[in] argc Number of arguments (excluding "pkc"/"key")
 * @param[in] argv Subcommand arguments
 * @return Return code from the embedded PKC application
 */
static int pkc_command(int argc, char ** argv)
{
    char * help_argv[] = {"-h"};

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0) {
        return dispatch_embedded_app(noxtls_pkc_app_main, "noxtls pkc", 1, help_argv);
    }

    return dispatch_embedded_app(noxtls_pkc_app_main, "noxtls pkc", argc, argv);
}

/**
 * @brief Handle the cert/x509 subcommand.
 *
 * @param[in] argc Number of arguments (excluding "cert"/"x509")
 * @param[in] argv Subcommand arguments
 * @return Return code from the embedded certificate application
 */
static int cert_command(int argc, char ** argv)
{
    char * help_argv[] = {"-h"};

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0) {
        return dispatch_embedded_app(noxtls_cert_app_main, "noxtls cert", 1, help_argv);
    }

    return dispatch_embedded_app(noxtls_cert_app_main, "noxtls cert", argc, argv);
}
