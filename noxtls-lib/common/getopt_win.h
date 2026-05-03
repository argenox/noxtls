/*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Minimal getopt for Windows (MSVC). Provides getopt(), optarg, optind.
 * Use this instead of <unistd.h> when building on _WIN32.
 */

/** @addtogroup noxtls_common */
/** @{ */

#ifndef NOXTLS_GETOPT_WIN_H
#define NOXTLS_GETOPT_WIN_H

#ifdef _WIN32

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

int getopt(int argc, char * const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* NOXTLS_GETOPT_WIN_H */
