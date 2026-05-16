/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    main.c
* Summary: NOXTLS Utility Main Application
*
*/

/**
 * @file main.c
 * @brief Multi-command NoxTLS CLI (e.g. noxtls_message digest).
 * @defgroup noxtls_app_noxtls NoxTLS CLI
 * @details
 * Unified CLI with subcommands. Command: dgst — noxtls_message digest (same as sha app).
 * Parameters: command then algorithm/options/input. Options: -v version, -h help.
 * @example
 * noxtls dgst SHA256 hello world
 * noxtls dgst MD5 -h 48656c6c6f
 * noxtls -h
 * noxtls -v
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls-lib/common/getopt_compat.h"
#include "encryption_command.h"
#include "message_digest.h"

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

void print_version(void)
{
    printf("NOXTLS v%u.%u.%u\n", (unsigned int)APP_VERSION_MAJOR, (unsigned int)APP_VERSION_MINOR, (unsigned int)APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}

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

static int pkc_command(int argc, char ** argv)
{
    char * help_argv[] = {"-h"};

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0) {
        return dispatch_embedded_app(noxtls_pkc_app_main, "noxtls pkc", 1, help_argv);
    }

    return dispatch_embedded_app(noxtls_pkc_app_main, "noxtls pkc", argc, argv);
}

static int cert_command(int argc, char ** argv)
{
    char * help_argv[] = {"-h"};

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0) {
        return dispatch_embedded_app(noxtls_cert_app_main, "noxtls cert", 1, help_argv);
    }

    return dispatch_embedded_app(noxtls_cert_app_main, "noxtls cert", argc, argv);
}
