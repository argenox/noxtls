/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_ffdhe_params.h
* Summary: RFC 7919 FFDHE group parameters (p, g) Definitions
*
*
*****************************************************************************/

#ifndef _NOXTLS_FFDHE_PARAMS_H_
#define _NOXTLS_FFDHE_PARAMS_H_

#include <stdint.h>

#define NOXTLS_FFDHE2048_P_BYTES 256
#define NOXTLS_FFDHE3072_P_BYTES 384
#define NOXTLS_FFDHE4096_P_BYTES 512
#define NOXTLS_FFDHE6144_P_BYTES 768
#define NOXTLS_FFDHE8192_P_BYTES 1024

/* Largest built-in FFDHE modulus (FFDHE8192); shared secrets and stack buffers sized to this. */
#define NOXTLS_FFDHE_MAX_P_BYTES NOXTLS_FFDHE8192_P_BYTES

/* RFC 7919 Table 2 — minimum recommended random private exponent length (bits) per group. */
#define NOXTLS_FFDHE2048_MIN_PRIVATE_BITS  225u
#define NOXTLS_FFDHE3072_MIN_PRIVATE_BITS  275u
#define NOXTLS_FFDHE4096_MIN_PRIVATE_BITS  325u
#define NOXTLS_FFDHE6144_MIN_PRIVATE_BITS  375u
#define NOXTLS_FFDHE8192_MIN_PRIVATE_BITS  400u

extern const uint8_t noxtls_ffdhe2048_p[NOXTLS_FFDHE2048_P_BYTES];
extern const uint8_t noxtls_ffdhe3072_p[NOXTLS_FFDHE3072_P_BYTES];
extern const uint8_t noxtls_ffdhe4096_p[NOXTLS_FFDHE4096_P_BYTES];
extern const uint8_t noxtls_ffdhe6144_p[NOXTLS_FFDHE6144_P_BYTES];
extern const uint8_t noxtls_ffdhe8192_p[NOXTLS_FFDHE8192_P_BYTES];

/* Generator g=2, zero-padded to p_len for each group */
extern const uint8_t noxtls_ffdhe_g_2048[NOXTLS_FFDHE2048_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_3072[NOXTLS_FFDHE3072_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_4096[NOXTLS_FFDHE4096_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_6144[NOXTLS_FFDHE6144_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_8192[NOXTLS_FFDHE8192_P_BYTES];

#endif /* _NOXTLS_FFDHE_PARAMS_H_ */
