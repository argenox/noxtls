/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ffdhe_params.h
* Summary: RFC 7919 FFDHE group parameters (p, g)
*/

#ifndef _NOXTLS_FFDHE_PARAMS_H_
#define _NOXTLS_FFDHE_PARAMS_H_

#include <stdint.h>

#define NOXTLS_FFDHE2048_P_BYTES 256
#define NOXTLS_FFDHE3072_P_BYTES 384
#define NOXTLS_FFDHE4096_P_BYTES 512

extern const uint8_t noxtls_ffdhe2048_p[NOXTLS_FFDHE2048_P_BYTES];
extern const uint8_t noxtls_ffdhe3072_p[NOXTLS_FFDHE3072_P_BYTES];
extern const uint8_t noxtls_ffdhe4096_p[NOXTLS_FFDHE4096_P_BYTES];

/* Generator g=2, zero-padded to p_len for each group */
extern const uint8_t noxtls_ffdhe_g_2048[NOXTLS_FFDHE2048_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_3072[NOXTLS_FFDHE3072_P_BYTES];
extern const uint8_t noxtls_ffdhe_g_4096[NOXTLS_FFDHE4096_P_BYTES];

#endif /* _NOXTLS_FFDHE_PARAMS_H_ */
