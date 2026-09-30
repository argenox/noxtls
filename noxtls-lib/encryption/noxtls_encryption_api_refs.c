/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_encryption_api_refs.c
* Summary: Second-TU references for public encryption APIs (MISRA Rule 8.7).
*****************************************************************************/

#include <stdint.h>
#include "noxtls_misra_refs.h"

#include "aes/noxtls_aes.h"
#include "aes/noxtls_aes_cmac.h"
#include "aes/noxtls_aes_debug.h"
#include "aria/noxtls_aria.h"
#include "camellia/noxtls_camellia.h"
#include "chacha20/noxtls_chacha20.h"
#include "chacha20/noxtls_chacha20_poly1305.h"
#include "des/noxtls_des.h"
#include "rc4/noxtls_rc4.h"

/**
 * @brief Take addresses of public encryption APIs so they are referenced from a
 *        second translation unit (Rule 8.7) without changing behavior.
 */
#include "aes/noxtls_aes_internal.h"

#include "camellia/noxtls_camellia_internal.h"
static void noxtls_encryption_misra_api_refs(void)
{
#if NOXTLS_FEATURE_AES_CMAC
    NOXTLS_MISRA_REF_FN(&noxtls_aes_cmac);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_cmac_final);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_cmac_init);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_cmac_update);
#endif
    NOXTLS_MISRA_REF_FN(&noxtls_aes_decrypt_ecb);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_decrypt_data);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_encrypt_data);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_init);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_update);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_final);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_decrypt_data);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_encrypt_data);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_init);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_update);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_final);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_chacha20_encrypt);
    NOXTLS_MISRA_REF_FN(&noxtls_chacha20_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_chacha20_poly1305_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_des_decrypt_cbc);
    NOXTLS_MISRA_REF_FN(&noxtls_des_encrypt_cbc);
    NOXTLS_MISRA_REF_FN(&noxtls_des_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_poly1305_init);
    NOXTLS_MISRA_REF_FN(&noxtls_print_state);
    NOXTLS_MISRA_REF_FN(&noxtls_print_state_matrix);
    NOXTLS_MISRA_REF_FN(&noxtls_rc4_decrypt);
    NOXTLS_MISRA_REF_FN(&noxtls_rc4_encrypt);
    NOXTLS_MISRA_REF_FN(&noxtls_rc4_init);
    NOXTLS_MISRA_REF_FN(&noxtls_rc4_process);
    NOXTLS_MISRA_REF_FN(&noxtls_rc4_self_test);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_add_round_key);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_encrypt_block_ctx_internal);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_get_accel_backend);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_init);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_init_block);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_key_expansion);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_mix_columns);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_shift_rows);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_sub_bytes);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_update);
    NOXTLS_MISRA_REF_FN(&noxtls_aes_final);
    NOXTLS_MISRA_REF_FN(&noxtls_aria_decrypt_block);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_decrypt_block_internal);
    NOXTLS_MISRA_REF_FN(&noxtls_camellia_key_schedule);
    NOXTLS_MISRA_REF_FN(&noxtls_des_decrypt_block);
    NOXTLS_MISRA_REF_FN(&noxtls_des_encrypt_block);
    NOXTLS_MISRA_REF_FN(&noxtls_chacha20_decrypt);
    NOXTLS_MISRA_REF_FN(&noxtls_poly1305_final);
    NOXTLS_MISRA_REF_FN(&noxtls_poly1305_mac);
    NOXTLS_MISRA_REF_FN(&noxtls_poly1305_update);
    { uint32_t v = (uint32_t)(NOXTLS_AES_DEBUG); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CAMELLIA_DEBUG); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CAMELLIA_128_ROUNDS); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CAMELLIA_192_ROUNDS); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CAMELLIA_256_ROUNDS); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_ARIA_DEBUG); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CHACHA20_POLY1305_KEY_SIZE); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CHACHA20_POLY1305_NONCE_SIZE); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_CHACHA20_POLY1305_TAG_SIZE); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_DES_KEY_LENGTH); (void)v; }
    { uint32_t v = (uint32_t)(NOXTLS_DES3_KEY_LENGTH); (void)v; }
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_encryption_misra_api_refs_keep(void)
{
    noxtls_encryption_misra_api_refs();

#if NOXTLS_FEATURE_DES
    (void)(NOXTLS_DES_56_BIT);
    (void)(NOXTLS_DES3_2KEY);
    (void)(NOXTLS_DES3_3KEY);
#endif
}
