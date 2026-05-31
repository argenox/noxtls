/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#ifndef _NOXTLS_HKDF_H_
#define _NOXTLS_HKDF_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

noxtls_return_t noxtls_hkdf_extract(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *salt, uint32_t salt_len,
                                    const uint8_t *ikm, uint32_t ikm_len,
                                    uint8_t *prk, uint32_t *prk_len);

noxtls_return_t noxtls_hkdf_expand(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *prk, uint32_t prk_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *okm, uint32_t okm_len);

/* Backward-compatible aliases. */
noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                             const uint8_t *salt, uint32_t salt_len,
                             const uint8_t *ikm, uint32_t ikm_len,
                             uint8_t *prk, uint32_t *prk_len);

noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                            const uint8_t *prk, uint32_t prk_len,
                            const uint8_t *info, uint32_t info_len,
                            uint8_t *okm, uint32_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_HKDF_H_ */
