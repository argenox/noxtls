/*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* Cross-platform noxtls_getopt compatibility wrapper.
*/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef NOXTLS_GETOPT_COMPAT_H
#define NOXTLS_GETOPT_COMPAT_H

#ifdef _WIN32
#include "getopt_win.h"
#else
#include <unistd.h>
#define noxtls_getopt getopt
#endif

#endif /* NOXTLS_GETOPT_COMPAT_H */

