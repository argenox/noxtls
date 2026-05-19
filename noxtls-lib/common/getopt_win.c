/*
* This file is part of the NoxTLS Library.
*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Minimal noxtls_getopt implementation for Windows (MSVC).
 * Compiled only when _WIN32. Provides POSIX-like noxtls_getopt for command-line parsing.
 */

/** @addtogroup noxtls_common */

#ifdef _WIN32

#include <string.h>
#include <stdio.h>
#include "getopt_win.h"

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

static char *getopt_place = NULL;

int noxtls_getopt(int argc, char * const argv[], const char *optstring)
{
    const char *optchr;

    optarg = NULL;
    optopt = 0;

    if(argc < 1 || argv == NULL || optstring == NULL) {
        return -1;
    }

    if(getopt_place == NULL || *getopt_place == '\0') {
        if(optind >= argc) {
            return -1;
        }
        if(argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        }
        if(strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
        getopt_place = &argv[optind][1];
    }

    optopt = (unsigned char)*getopt_place;
    getopt_place++;

    optchr = strchr(optstring, optopt);
    if(optchr == NULL) {
        if(opterr && *optstring != ':') {
            (void)fprintf(stderr, "%s: unknown option -%c\n", argv[0], optopt);
        }
        return '?';
    }

    if(optchr[1] == ':') {
        if(*getopt_place != '\0') {
            optarg = (char *)getopt_place;
            getopt_place = NULL;
            optind++;
        } else {
            if(optind + 1 >= argc) {
                if(opterr && *optstring != ':') {
                    (void)fprintf(stderr, "%s: option -%c requires an argument\n", argv[0], optopt);
                }
                return (*optstring == ':') ? ':' : '?';
            }
            optarg = argv[optind + 1];
            optind += 2;
        }
        getopt_place = NULL;
    } else {
        if(*getopt_place == '\0') {
            getopt_place = NULL;
            optind++;
        }
    }

    return optopt;
}

#endif /* _WIN32 */
