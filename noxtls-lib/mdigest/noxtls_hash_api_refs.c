/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_hash_api_refs.c
* Summary: Second-TU references for public hash APIs (MISRA Rule 8.7).
*****************************************************************************/

#include <stdint.h>
#include "noxtls_misra_refs.h"

#include "noxtls_config.h"
#include "noxtls_sha.h"
#if NOXTLS_FEATURE_SHA1
#include "sha1/noxtls_sha1.h"
#endif
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
#include "sha256/noxtls_sha256.h"
#include "sha256/noxtls_sha256_backend.h"
#include "sha256/noxtls_sha256_accel_port.h"
#endif

#if NOXTLS_FEATURE_MD5
#include "md5/noxtls_md5.h"
#endif

#if NOXTLS_FEATURE_SHA3
#include "sha3/noxtls_sha3.h"
#endif

#if NOXTLS_FEATURE_SHA512 || NOXTLS_FEATURE_SHA384
#include "sha512/noxtls_sha512.h"
#endif

#if NOXTLS_FEATURE_RIPEMD160
#include "ripemd160/noxtls_ripemd160.h"
#endif
#if NOXTLS_FEATURE_BLAKE2
#include "blake2/noxtls_blake2.h"
#endif

static void noxtls_hash_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&noxtls_sha_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_sha_init);
    NOXTLS_MISRA_REF_FN(&noxtls_sha_update);
#if NOXTLS_FEATURE_SHA1
    NOXTLS_MISRA_REF_FN(&noxtls_sha1_set_debug);
    NOXTLS_MISRA_REF_FN(&noxtls_sha1_verify);
    { uint32_t v = (uint32_t)HASH_SHA1_OUT_LEN; (void)v; }
#endif
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_backend_is_cortexm7);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_backend_set_cortexm7_enabled);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_blocks_accel_port);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_round_accel_port);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_set_debug);
#endif
#if NOXTLS_FEATURE_MD5
    NOXTLS_MISRA_REF_FN(&noxtls_md5_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_md5_set_debug);
    NOXTLS_MISRA_REF_FN(&noxtls_md5_verify);
    { uint32_t v = (uint32_t)MD5_STATE_WORDS; (void)v; }
#endif
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_backend_name);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_update);
    NOXTLS_MISRA_REF_FN(&noxtls_sha256_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_sha224_verify);
    { uint32_t v = (uint32_t)SHA256_BLOCK_SIZE_BITS; (void)v; }
#endif
#if NOXTLS_FEATURE_SHA3
    NOXTLS_MISRA_REF_FN(&noxtls_sha3_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_sha3_set_debug);
    NOXTLS_MISRA_REF_FN(&noxtls_sha3_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_shake128_final);
    NOXTLS_MISRA_REF_FN(&noxtls_shake128_init);
    NOXTLS_MISRA_REF_FN(&noxtls_shake128_squeeze);
    NOXTLS_MISRA_REF_FN(&noxtls_shake128_update);
    NOXTLS_MISRA_REF_FN(&noxtls_shake256_final);
    NOXTLS_MISRA_REF_FN(&noxtls_shake256_init);
    NOXTLS_MISRA_REF_FN(&noxtls_shake256_squeeze);
    NOXTLS_MISRA_REF_FN(&noxtls_shake256_update);
    { uint32_t v = (uint32_t)SHA3_LANE_BYTES; (void)v; }
#endif
#if NOXTLS_FEATURE_SHA512 || NOXTLS_FEATURE_SHA384
    NOXTLS_MISRA_REF_FN(&noxtls_sha512_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_sha512_init);
    NOXTLS_MISRA_REF_FN(&noxtls_sha512_set_debug);
    NOXTLS_MISRA_REF_FN(&noxtls_sha512_verify);
    { uint32_t v = (uint32_t)SHA512_BLOCK_SIZE_BITS; (void)v; }
    { uint32_t v = (uint32_t)SHA512_STATE_WORDS; (void)v; }
    { uint32_t v = (uint32_t)SHA384_STATE_WORDS; (void)v; }
#endif
#if NOXTLS_FEATURE_RIPEMD160
    NOXTLS_MISRA_REF_FN(&noxtls_ripemd160_finish);
    NOXTLS_MISRA_REF_FN(&noxtls_ripemd160_verify);
    { uint32_t v = (uint32_t)RIPEMD160_BLOCK_SIZE_BITS; (void)v; }
#endif
#if NOXTLS_FEATURE_BLAKE2
    { uint32_t v = (uint32_t)HASH_BLAKE2S_256_OUT_LEN; (void)v; }
    { uint32_t v = (uint32_t)HASH_BLAKE2B_512_OUT_LEN; (void)v; }
#endif
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_hash_misra_api_refs_keep(void)
{
    noxtls_hash_misra_api_refs();
}
