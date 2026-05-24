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
* File:    noxtls_sha1.h
* Summary: Secure Hashing Algorithm SHA-1
* Defined in FIPS
*
* Note: SHA-1 is no longer recommended due to significant cryptographic weaknesses. 
* It is vulnerable to practical collision and chosen-prefix attacks, allowing attackers 
* to create different inputs with the same hash. T
* his makes SHA-1 unsuitable for security-sensitive applications.
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_SHA1_H_
#define _NOXTLS_SHA1_H_

#include "noxtls_sha.h"
#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_SHA1_OUT_LEN       (20)
#define SHA1_BLOCK_SIZE_BYTES   (64U)
#define SHA1_BLOCK_SIZE_BITS    (512U)
#define SHA1_LENGTH_FIELD_BYTES (8U)
#define SHA1_PAD_BYTE           (0x80u)
#define SHA1_ROUND_COUNT        (80u)
#define SHA1_STATE_WORDS        (5U)

noxtls_return_t noxtls_sha1_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo);
noxtls_return_t noxtls_sha1_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha1_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
noxtls_return_t noxtls_sha1_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
void noxtls_sha1_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif
