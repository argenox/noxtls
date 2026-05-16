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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls-lib/common/getopt_compat.h"
#include "message_digest.h"

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


void print_usage(const char * name)
{
    printf("usage: %s <algorithm> [options] [text...]\n", name);
    printf("       %s <algorithm> -f <file> [options]\n", name);

    printf("\nCommandline Switches\n\n");

    printf("-v \t\t\tVersion Information\n");
    printf("-h \t\t\tHelp\n");    

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
