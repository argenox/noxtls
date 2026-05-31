/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#ifndef _NOXTLS_HMAC_H_
#define _NOXTLS_HMAC_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    noxtls_hash_algos_t hash_algo;
    uint8_t key[128];
    uint32_t key_len;
    uint8_t o_key_pad[128];
    uint8_t i_key_pad[128];
    void *hash_ctx;
} noxtls_hmac_context_t;

/* Backward-compatible type alias. */
typedef noxtls_hmac_context_t hmac_context_t;

noxtls_return_t noxtls_hmac_init(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len);
noxtls_return_t noxtls_hmac_update(noxtls_hmac_context_t *ctx, const uint8_t *data, uint32_t data_len);
noxtls_return_t noxtls_hmac_final(noxtls_hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len);
noxtls_return_t noxtls_hmac_free(noxtls_hmac_context_t *ctx);
noxtls_return_t noxtls_hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                                    const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len);

/* Backward-compatible function alias. */
noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_HMAC_H_ */
