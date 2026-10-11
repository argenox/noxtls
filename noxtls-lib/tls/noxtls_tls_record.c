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
* File:    noxtls_tls_record.c
* Summary: TLS Record Layer Encryption/Decryption Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "noxtls_tls_kdf.h"
#include "mac/noxtls_hmac.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_internal.h"

static int32_t tls12_is_dtls_context(const tls12_context_t *ctx);
static uint64_t tls12_dtls_write_seq64(const tls12_context_t *ctx);
static uint64_t tls12_dtls_read_seq64(const tls12_context_t *ctx);
static int32_t tls13_is_dtls_context(const tls13_context_t *ctx);
#include "encryption/aes/noxtls_aes_gcm.h"
#include "encryption/aes/noxtls_aes_ccm.h"
#include "encryption/aria/noxtls_aria.h"
#include "encryption/des/noxtls_des.h"
#include "encryption/chacha20/noxtls_chacha20.h"
#include "encryption/chacha20/noxtls_chacha20_poly1305.h"
#include "noxtls_dtls_common.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/noxtls_hash.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_ct.h"
#if NOXTLS_FEATURE_DTLS_ECJPAKE
#include "noxtls_tls12_ecjpake.h"
#endif

static const uint64_t tls_record_s_u64_bit[64] = {
    0x0000000000000001ULL,
    0x0000000000000002ULL,
    0x0000000000000004ULL,
    0x0000000000000008ULL,
    0x0000000000000010ULL,
    0x0000000000000020ULL,
    0x0000000000000040ULL,
    0x0000000000000080ULL,
    0x0000000000000100ULL,
    0x0000000000000200ULL,
    0x0000000000000400ULL,
    0x0000000000000800ULL,
    0x0000000000001000ULL,
    0x0000000000002000ULL,
    0x0000000000004000ULL,
    0x0000000000008000ULL,
    0x0000000000010000ULL,
    0x0000000000020000ULL,
    0x0000000000040000ULL,
    0x0000000000080000ULL,
    0x0000000000100000ULL,
    0x0000000000200000ULL,
    0x0000000000400000ULL,
    0x0000000000800000ULL,
    0x0000000001000000ULL,
    0x0000000002000000ULL,
    0x0000000004000000ULL,
    0x0000000008000000ULL,
    0x0000000010000000ULL,
    0x0000000020000000ULL,
    0x0000000040000000ULL,
    0x0000000080000000ULL,
    0x0000000100000000ULL,
    0x0000000200000000ULL,
    0x0000000400000000ULL,
    0x0000000800000000ULL,
    0x0000001000000000ULL,
    0x0000002000000000ULL,
    0x0000004000000000ULL,
    0x0000008000000000ULL,
    0x0000010000000000ULL,
    0x0000020000000000ULL,
    0x0000040000000000ULL,
    0x0000080000000000ULL,
    0x0000100000000000ULL,
    0x0000200000000000ULL,
    0x0000400000000000ULL,
    0x0000800000000000ULL,
    0x0001000000000000ULL,
    0x0002000000000000ULL,
    0x0004000000000000ULL,
    0x0008000000000000ULL,
    0x0010000000000000ULL,
    0x0020000000000000ULL,
    0x0040000000000000ULL,
    0x0080000000000000ULL,
    0x0100000000000000ULL,
    0x0200000000000000ULL,
    0x0400000000000000ULL,
    0x0800000000000000ULL,
    0x1000000000000000ULL,
    0x2000000000000000ULL,
    0x4000000000000000ULL,
    0x8000000000000000ULL
};


/**
 * @brief Generate TLS 1.2 record IV from sequence number and write IV
 *
 * @param[out] iv The IV to generate
 * @param[in] write_iv The write IV
 * @param[in] iv_len The length of the IV
 * @param[in] seq_num The sequence number
 * @return void
 */
static void tls12_generate_iv(uint8_t *iv, const uint8_t *write_iv, uint32_t iv_len, uint64_t seq_num)
{
    /* Copy write IV */
    noxtls_copy_u8(iv, (size_t)(iv_len), write_iv, (size_t)(iv_len));
    
    /* XOR sequence number into last 8 bytes of IV */
    if(iv_len >= 8U) {
        iv[iv_len - 8U + 0U] ^= (uint8_t)((((uint64_t)seq_num) >> 56U) & 0xFFU);
        iv[iv_len - 8U + 1U] ^= (uint8_t)((((uint64_t)seq_num) >> 48U) & 0xFFU);
        iv[iv_len - 8U + 2U] ^= (uint8_t)((((uint64_t)seq_num) >> 40U) & 0xFFU);
        iv[iv_len - 8U + 3U] ^= (uint8_t)((((uint64_t)seq_num) >> 32U) & 0xFFU);
        iv[iv_len - 8U + 4U] ^= (uint8_t)((((uint64_t)seq_num) >> 24U) & 0xFFU);
        iv[iv_len - 8U + 5U] ^= (uint8_t)((((uint64_t)seq_num) >> 16U) & 0xFFU);
        iv[iv_len - 8U + 6U] ^= (uint8_t)((((uint64_t)seq_num) >> 8U) & 0xFFU);
        iv[iv_len - 8U + 7U] ^= (uint8_t)(seq_num & 0xFFU);
    }
}

#if NOXTLS_FEATURE_CHACHA20_POLY1305
/**
 * @brief Generate TLS 1.2 ChaCha20-Poly1305 record nonce
 *
 * @param[out] nonce The nonce to generate
 * @param[in] write_iv The write IV
 * @param[in] seq_num The sequence number
 * @return void
 *
 * RFC 7905 TLS 1.2 ChaCha20-Poly1305 record nonce: XOR the 12-byte write IV
 * with (four zero bytes || 64-bit record sequence number, big-endian).
 */
static void tls12_chacha20_poly1305_record_nonce(uint8_t *nonce,
                                                 const uint8_t *write_iv,
                                                 uint64_t seq_num)
{
    uint32_t i = 0U;
    noxtls_secure_zero((nonce), (size_t)(4U));
    nonce[4U] = (uint8_t)((((uint64_t)seq_num) >> 56U) & 0xFFU);
    nonce[5U] = (uint8_t)((((uint64_t)seq_num) >> 48U) & 0xFFU);
    nonce[6U] = (uint8_t)((((uint64_t)seq_num) >> 40U) & 0xFFU);
    nonce[7U] = (uint8_t)((((uint64_t)seq_num) >> 32U) & 0xFFU);
    nonce[8U] = (uint8_t)((((uint64_t)seq_num) >> 24U) & 0xFFU);
    nonce[9U] = (uint8_t)((((uint64_t)seq_num) >> 16U) & 0xFFU);
    nonce[10U] = (uint8_t)((((uint64_t)seq_num) >> 8U) & 0xFFU);
    nonce[11U] = (uint8_t)(seq_num & 0xFFU);
    for(i = 0U; i < 12U; i += 1U) {
        nonce[i] ^= write_iv[i];
    }
}
#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */

/**
 * @brief Compute TLS 1.2 MAC
 * MAC = HMAC_hash(MAC_write_secret, seq_num || type || version || length || fragment)
 *
 * @param[in] mac_key The MAC key
 * @param[in] mac_key_len The length of the MAC key
 * @param[in] hash_algo The hash algorithm
 * @param[in] seq_num The sequence number
 * @param[in] type The type of the record
 * @param[in] version The version of the record
 * @param[in] length The length of the record
 * @param[in] fragment The fragment of the record
 * @param[in] fragment_len The length of the fragment
 * @param[out] mac The MAC
 * @param[out] mac_len The length of the MAC
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t tls12_compute_mac(const uint8_t *mac_key, uint32_t mac_key_len,
                                           noxtls_hash_algos_t hash_algo,
                                           uint64_t seq_num,
                                           uint8_t type,
                                           uint16_t version,
                                           uint16_t length,
                                           const uint8_t *fragment,
                                           uint32_t fragment_len,
                                           uint8_t *mac,
                                           uint32_t *mac_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    hmac_context_t hmac_ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t seq_bytes[8];
    uint8_t version_bytes[2];
    uint8_t length_bytes[2];
    
    /* Convert sequence number to bytes (big-endian) */
    seq_bytes[0] = (uint8_t)(((uint64_t)seq_num >> 56U) & 0xFFU);
    seq_bytes[1] = (uint8_t)(((uint64_t)seq_num >> 48U) & 0xFFU);
    seq_bytes[2] = (uint8_t)(((uint64_t)seq_num >> 40U) & 0xFFU);
    seq_bytes[3] = (uint8_t)(((uint64_t)seq_num >> 32U) & 0xFFU);
    seq_bytes[4] = (uint8_t)(((uint64_t)seq_num >> 24U) & 0xFFU);
    seq_bytes[5] = (uint8_t)(((uint64_t)seq_num >> 16U) & 0xFFU);
    seq_bytes[6] = (uint8_t)(((uint64_t)seq_num >> 8U) & 0xFFU);
    seq_bytes[7] = (uint8_t)((uint64_t)seq_num & 0xFFU);
    
    /* Convert version to bytes (big-endian) */
    version_bytes[0] = (uint8_t)((((uint32_t)(version) >> 8U)) & 0xFFU);
    version_bytes[1] = (uint8_t)(version & 0xFFU);
    
    /* Convert length to bytes (big-endian) */
    length_bytes[0] = (uint8_t)((((uint32_t)length) >> 8U) & 0xFFU);
    length_bytes[1] = (uint8_t)(length & 0xFFU);
    
    /* Initialize HMAC */
    rc = noxtls_hmac_init(&hmac_ctx, hash_algo, mac_key, mac_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Update with sequence number */
    rc = noxtls_hmac_update(&hmac_ctx, seq_bytes, 8);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with type */
    rc = noxtls_hmac_update(&hmac_ctx, &type, 1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with version */
    rc = noxtls_hmac_update(&hmac_ctx, version_bytes, 2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with length */
    rc = noxtls_hmac_update(&hmac_ctx, length_bytes, 2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with fragment */
    if((fragment != NULL) && (fragment_len > 0U)) {
        rc = noxtls_hmac_update(&hmac_ctx, fragment, fragment_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_hmac_free(&hmac_ctx);
            return rc;
        }
    }
    
    /* Finalize MAC */
    rc = noxtls_hmac_final(&hmac_ctx, mac, mac_len);
    (void)noxtls_hmac_free(&hmac_ctx);
    
    return rc;
}

/**
 * @brief Get the length of the MAC from the hash algorithm
 *
 * @param[in] hash_algo The hash algorithm
 * @return The length of the MAC
 */
static uint32_t tls12_mac_len_from_hash(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_SHA1:
            return 20U;
        case NOXTLS_HASH_SHA_384:
            return 48U;
        case NOXTLS_HASH_SHA_256:
        default:
            return 32U;
    }
}

/**
 * @brief Check if the context should use encrypt then MAC
 *
 * @param[in] ctx The context
 * @param[in] is_gcm Whether the cipher is GCM
 * @param[in] is_tls12_ccm Whether the cipher is TLS 1.2 CCM
 * @param[in] is_tls12_chacha Whether the cipher is TLS 1.2 ChaCha20
 * @return 1 if the context should use encrypt then MAC, 0 otherwise
 */
static int32_t tls12_should_use_encrypt_then_mac(const tls12_context_t *ctx,
                                              uint8_t is_gcm,
                                              uint8_t is_tls12_ccm,
                                              uint8_t is_tls12_chacha)
{
    return ((ctx != NULL) &&
           (ctx->use_encrypt_then_mac != 0U) &&
           (is_gcm == 0U) &&
           (is_tls12_ccm == 0U) &&
           (is_tls12_chacha == 0U)) ? 1 : 0;
}

/**
 * @brief Encrypt TLS 1.2 application data record (AES-CBC with HMAC)
 *
 * @param[in] ctx The context
 * @param[in] type The type of the record
 * @param[in] plaintext The plaintext of the record
 * @param[in] plaintext_len The length of the plaintext
 * @param[out] encrypted_record The encrypted record
 * @param[out] encrypted_record_len The length of the encrypted record
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
*/
noxtls_return_t noxtls_tls12_encrypt_record(tls12_context_t *ctx, 
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
{
    const uint8_t *mac_key = NULL;
    uint32_t mac_key_len = 0U;
    const uint8_t *enc_key = NULL;
    uint32_t enc_key_len = 0U;
    const uint8_t *write_iv = NULL;
    uint32_t iv_len = 0U;
    uint64_t seq_num = 0U;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    noxtls_aes_type_t aes_type;
    uint8_t iv_enc[16];
    uint8_t mac[64];  /* Max MAC size (SHA-512) */
    uint32_t mac_len = 0U;
    uint8_t *padded_plaintext = NULL;
    uint32_t padded_len = 0U;
    uint8_t *encrypted_data = NULL;
    uint32_t encrypted_data_len = 0U;
    uint32_t record_len = 0U;
    uint32_t offset = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if((ctx == NULL) || (plaintext == NULL) || (encrypted_record == NULL) || (encrypted_record_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        mac_key = ctx->client_write_mac_key;
        enc_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 16U;
        seq_num = (tls12_is_dtls_context(ctx) != 0) ? tls12_dtls_write_seq64(ctx) : ctx->client_seq_num;
    } else {
        mac_key = ctx->server_write_mac_key;
        enc_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 16U;
        seq_num = (tls12_is_dtls_context(ctx) != 0) ? tls12_dtls_write_seq64(ctx) : ctx->server_seq_num;
    }

    /* Determine hash algorithm, MAC length, and cipher type from cipher suite */
    hash_algo = NOXTLS_HASH_SHA_256;
    mac_key_len = 32U;
    enc_key_len = 32U;
    aes_type = NOXTLS_AES_256_BIT;
    uint8_t is_aria = 0U;
    uint8_t is_gcm = 0U;
    uint8_t is_tls12_ccm = 0U;
    uint8_t is_tls12_chacha = 0U;
    uint32_t tls12_ccm_tag_len = 16U;
    uint8_t is_3des = 0U;
    noxtls_aria_type_t aria_type = NOXTLS_ARIA_256_BIT;

    switch(ctx->cipher_suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 24U;
            iv_len = 8U;
            is_3des = 1U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            is_aria = 0U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_gcm = 1U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 12U;
            is_aria = 0U;
            is_tls12_chacha = 1U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
            hash_algo = ((ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ||
                          (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)) ?
                        NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_256;
            mac_key_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 32U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            is_aria = 0U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_gcm = 1U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 16U;
            break;
#if NOXTLS_FEATURE_DTLS_ECJPAKE
        case TLS_CIPHER_SUITE_ECJPAKE_WITH_AES_128_CCM_8: /* RFC 6655 section 3 / draft-cragie-tls-ecjpake-01 */
#endif
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 8U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 16U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 8U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
            is_aria = 1U;
            aria_type = NOXTLS_ARIA_128_BIT;
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32U;
            enc_key_len = 16U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            is_aria = 1U;
            aria_type = NOXTLS_ARIA_256_BIT;
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 48U;
            enc_key_len = 32U;
            break;
        default:
            /* Defaults already set (AES-256/SHA-256) */
            break;
    }
    
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1U;
    uint32_t iv_is_zero = 1U;
    uint32_t k = 0U;
    for(k = 0U; k < enc_key_len; k += 1U) {
        if(enc_key[k] != 0U) {
            key_is_zero = 0U;
            break;
        }
    }
    for(k = 0U; k < iv_len; k += 1U) {
        if(write_iv[k] != 0U) {
            iv_is_zero = 0U;
            break;
        }
    }
    
    if((key_is_zero != 0U) || (iv_is_zero != 0U)) {
        /* Keys not initialized - key derivation must happen during handshake */
        return NOXTLS_RETURN_FAILED;
    }
    
    if((is_gcm != 0U) || (is_tls12_ccm != 0U) || (is_tls12_chacha != 0U)) {
        uint8_t nonce[12];
        uint8_t tag[16];
        uint8_t aad[13];
        uint32_t aad_len = 13U;

        /* SECURITY (NX-09): refuse to encrypt when the sequence number would wrap,
         * which would reuse an AEAD nonce with the same key. */
        if(seq_num == UINT64_MAX) {
            return NOXTLS_RETURN_FAILED;
        }

        aad[0] = (uint8_t)(((uint64_t)seq_num) >> 56U);
        aad[1] = (uint8_t)(((uint64_t)seq_num) >> 48U);
        aad[2] = (uint8_t)(((uint64_t)seq_num) >> 40U);
        aad[3] = (uint8_t)(((uint64_t)seq_num) >> 32U);
        aad[4] = (uint8_t)(((uint64_t)seq_num) >> 24U);
        aad[5] = (uint8_t)(((uint64_t)seq_num) >> 16U);
        aad[6] = (uint8_t)(((uint64_t)seq_num) >> 8U);
        aad[7] = (uint8_t)seq_num;
        aad[8] = type;
        aad[9] = (uint8_t)((uint32_t)ctx->base.base.version >> 8U);
        aad[10] = (uint8_t)(ctx->base.base.version);
        aad[11] = (uint8_t)(((uint32_t)plaintext_len) >> 8U);
        aad[12] = (uint8_t)plaintext_len;

        /* A zero-length fragment is legal (RFC 5246 6.2.1); never request a 0-byte allocation. */
        encrypted_data = (uint8_t*)NOXTLS_MALLOC((plaintext_len == 0U) ? 1U : plaintext_len);
        if(encrypted_data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }

        if(is_tls12_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
            const uint32_t tag_len = 16U;
            tls12_chacha20_poly1305_record_nonce(nonce, write_iv, seq_num);
            if(noxtls_chacha20_poly1305_encrypt(enc_key, nonce, aad, aad_len,
                                                plaintext, plaintext_len, encrypted_data, tag) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(encrypted_data);
                return NOXTLS_RETURN_FAILED;
            }
            encrypted_data_len = plaintext_len;
            record_len = encrypted_data_len + tag_len;
            if(*encrypted_record_len < record_len) {
                (void)noxtls_free(encrypted_data);
                *encrypted_record_len = record_len;
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), encrypted_data, (size_t)(encrypted_data_len));
            offset += encrypted_data_len;
            noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), tag, (size_t)(tag_len));
            offset += tag_len;
#else
            (void)noxtls_free(encrypted_data);
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else {
            uint8_t fixed_iv[4];
            uint8_t explicit_nonce[8];
            const uint32_t tag_len = (is_gcm != 0U) ? 16U : tls12_ccm_tag_len;
            explicit_nonce[0] = (uint8_t)((((uint64_t)seq_num) >> 56U) & 0xFFU);
            explicit_nonce[1] = (uint8_t)((((uint64_t)seq_num) >> 48U) & 0xFFU);
            explicit_nonce[2] = (uint8_t)((((uint64_t)seq_num) >> 40U) & 0xFFU);
            explicit_nonce[3] = (uint8_t)((((uint64_t)seq_num) >> 32U) & 0xFFU);
            explicit_nonce[4] = (uint8_t)((((uint64_t)seq_num) >> 24U) & 0xFFU);
            explicit_nonce[5] = (uint8_t)((((uint64_t)seq_num) >> 16U) & 0xFFU);
            explicit_nonce[6] = (uint8_t)((((uint64_t)seq_num) >> 8U) & 0xFFU);
            explicit_nonce[7] = (uint8_t)(seq_num & 0xFFU);
            noxtls_copy_u8(fixed_iv, sizeof(fixed_iv), write_iv, (size_t)(4U));
            noxtls_copy_u8(nonce, sizeof(nonce), fixed_iv, (size_t)(4U));
            noxtls_copy_u8(&nonce[4], sizeof(nonce) - (size_t)(4), explicit_nonce, (size_t)(8U));
            if(is_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
                if(noxtls_aes_gcm_encrypt(enc_key, aes_type, nonce, aad, aad_len,
                                   plaintext, plaintext_len, encrypted_data, tag) != NOXTLS_RETURN_SUCCESS) {
                    (void)noxtls_free(encrypted_data);
                    return NOXTLS_RETURN_FAILED;
                }
#else
                (void)noxtls_free(encrypted_data);
                return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
            } else {
                /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_AES_CCM
                if(noxtls_aes_ccm_encrypt(enc_key, aes_type, nonce, 12U, aad, aad_len,
                                   plaintext, plaintext_len, encrypted_data, tag, tag_len) != NOXTLS_RETURN_SUCCESS) {
                    (void)noxtls_free(encrypted_data);
                    return NOXTLS_RETURN_FAILED;
                }
#else
                (void)noxtls_free(encrypted_data);
                return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
            }
            encrypted_data_len = plaintext_len;

            record_len = 8U + encrypted_data_len + tag_len;
            if(*encrypted_record_len < record_len) {
                (void)noxtls_free(encrypted_data);
                *encrypted_record_len = record_len;
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), explicit_nonce, (size_t)(8U));
            offset += 8U;
            noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), encrypted_data, (size_t)(encrypted_data_len));
            offset += encrypted_data_len;
            noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), tag, (size_t)(tag_len));
            offset += tag_len;
        }
        (void)offset;
        *encrypted_record_len = record_len;

        (void)noxtls_free(encrypted_data);

        if((tls12_is_dtls_context(ctx) == 0)) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                ctx->client_seq_num += 1U;
            } else {
                /* MISRA 15.7: final else path */
                ctx->server_seq_num += 1U;
            }
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    mac_len = tls12_mac_len_from_hash(hash_algo);

    /* Pad plaintext (+ optional MAC) for CBC encryption */
    /* Padding: add 1 to 256 bytes, all with value = padding_length */
    uint32_t block_size = (uint32_t)((is_3des != 0U) ? NOXTLS_DES_BLOCK_LENGTH : NOXTLS_AES_BLOCK_LENGTH);
    int32_t use_encrypt_then_mac = tls12_should_use_encrypt_then_mac(ctx, is_gcm, is_tls12_ccm, is_tls12_chacha);
    uint32_t mac_input_len = (uint32_t)((use_encrypt_then_mac != 0) ? 0U : mac_len);
    uint8_t padding_len = (uint8_t)(block_size - ((plaintext_len + mac_input_len) % block_size) - 1U);
    
    padded_len = plaintext_len + mac_input_len + padding_len + 1U;
    padded_plaintext = (uint8_t*)NOXTLS_MALLOC(padded_len);
    if(padded_plaintext == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Copy plaintext */
    noxtls_copy_u8(padded_plaintext, (size_t)(padded_len), plaintext, (size_t)(plaintext_len));
    if(use_encrypt_then_mac == 0) {
        /* MAC-then-encrypt: MAC plaintext before CBC encryption. */
        rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num, type,
                              ctx->base.base.version, (uint16_t)plaintext_len,
                              plaintext, plaintext_len, mac, &mac_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(padded_plaintext);
            return rc;
        }
        noxtls_copy_u8(&padded_plaintext[plaintext_len], (size_t)(padded_len - plaintext_len), mac, (size_t)(mac_len));
    }
    
    /* Append padding (pad length byte is the padding length) */
    {
            uint32_t pi = 0U;
            uint32_t plen = (uint32_t)padding_len + 1U;
            for(pi = 0U; pi < plen; pi += 1U) {
                padded_plaintext[plaintext_len + mac_input_len + pi] = (uint8_t)padding_len;
            }
        }
    if((padded_len % block_size) != 0U) {
        (void)noxtls_free(padded_plaintext);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Generate IV: TLS 1.0 = implicit (last block or write_iv); TLS 1.1 = random; TLS 1.2 = generated from &write_iv[seq] */
    {
        uint16_t ver = (uint16_t)(ctx->base.base.version);
        if(ver == TLS_VERSION_1_0) {
            const uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_last_cipher_block : ctx->server_last_cipher_block;
            if(seq_num == 0U) {
                noxtls_copy_u8(iv_enc, sizeof(iv_enc), write_iv, (size_t)(iv_len));
            } else {
                noxtls_copy_u8(iv_enc, sizeof(iv_enc), last_block, (size_t)(iv_len));
            }
        } else if(ver == TLS_VERSION_1_1) {
            drbg_state_t drbg;
            if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(padded_plaintext);
                return NOXTLS_RETURN_FAILED;
            }
            if(drbg_generate(&drbg, iv_enc, iv_len * 8U, NULL, 0U) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(padded_plaintext);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            uint8_t iv[16];
            tls12_generate_iv(iv, write_iv, iv_len, seq_num);
            noxtls_copy_u8(iv_enc, sizeof(iv_enc), iv, (size_t)(iv_len));
        }
    }
    
    /* Encrypt */
    encrypted_data = (uint8_t*)NOXTLS_MALLOC(padded_len);
    if(encrypted_data == NULL) {
        (void)noxtls_free(padded_plaintext);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Encrypt using 3DES-CBC, AES-CBC, or ARIA-CBC */
    if(is_3des != 0U) {
#if NOXTLS_FEATURE_DES
        if(des3_encrypt_cbc(enc_key, 24, padded_plaintext, padded_len, iv_enc, encrypted_data) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
#else
        (void)noxtls_free(padded_plaintext);
        (void)noxtls_free(encrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(is_aria != 0U) {
#if NOXTLS_FEATURE_ARIA
        if(noxtls_aria_encrypt_cbc(enc_key, padded_plaintext, padded_len, iv_enc, encrypted_data, aria_type) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
#else
        (void)aria_type;
        (void)noxtls_free(padded_plaintext);
        (void)noxtls_free(encrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_AES_CBC
        if(noxtls_aes_encrypt_cbc(enc_key, padded_plaintext, padded_len, iv_enc, encrypted_data, aes_type) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
#else
        (void)noxtls_free(padded_plaintext);
        (void)noxtls_free(encrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    
    encrypted_data_len = padded_len;
    
    /* TLS 1.0: record = ciphertext only (implicit IV). TLS 1.1/1.2: record = IV || ciphertext */
    if(ctx->base.base.version == TLS_VERSION_1_0) {
        record_len = encrypted_data_len;
        if(*encrypted_record_len < record_len) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            *encrypted_record_len = record_len;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), encrypted_data, (size_t)(encrypted_data_len));
        /* Save last cipher block for next record */
        {
            uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_last_cipher_block : ctx->server_last_cipher_block;
            noxtls_copy_u8(last_block, (size_t)iv_len, &encrypted_data[encrypted_data_len - iv_len], (size_t)iv_len);
        }
    } else {
        record_len = iv_len + encrypted_data_len;
        if(*encrypted_record_len < record_len) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            *encrypted_record_len = record_len;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), iv_enc, (size_t)(iv_len));
        offset += iv_len;
        noxtls_copy_u8(&encrypted_record[offset], (size_t)(*encrypted_record_len), encrypted_data, (size_t)(encrypted_data_len));
    }
    if(use_encrypt_then_mac != 0) {
        uint32_t mac_out_len = (uint32_t)(mac_len);
        rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num, type,
                              ctx->base.base.version, (uint16_t)record_len,
                              encrypted_record, record_len, mac, &mac_out_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            return rc;
        }
        if((record_len + mac_out_len) > *encrypted_record_len) {
            (void)noxtls_free(padded_plaintext);
            (void)noxtls_free(encrypted_data);
            *encrypted_record_len = record_len + mac_out_len;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(&encrypted_record[record_len], (size_t)(*encrypted_record_len), mac, (size_t)(mac_out_len));
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_REC] EtM send: role=%s suite=0x%04X type=%u seq=%llu rec_len=%u mac_len=%u mac=%02X%02X%02X%02X\n",
                (ctx->base.base.role == TLS_ROLE_SERVER) ? "server" : "client",
                (uint32_t)ctx->cipher_suite,
                (uint32_t)type,
                (unsigned long long)seq_num,
                (uint32_t)record_len,
                (uint32_t)mac_out_len,
                mac[0], mac[1], mac[2], mac[3]);
        record_len += mac_out_len;
    }
    (void)offset;
    
    *encrypted_record_len = record_len;
    
    if((tls12_is_dtls_context(ctx) == 0)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->client_seq_num += 1U;
        } else {
            ctx->server_seq_num += 1U;
        }
    }
    
    (void)noxtls_free(padded_plaintext);
    (void)noxtls_free(encrypted_data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt TLS 1.2 application data record (AES-CBC with HMAC)
 *
 * @param[in] ctx The context
 * @param[in] type The type of the record
 * @param[in] encrypted_record The encrypted record
 * @param[in] encrypted_record_len The length of the encrypted record
 * @param[out] plaintext The plaintext of the record
 * @param[out] plaintext_len The length of the plaintext
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
noxtls_return_t noxtls_tls12_decrypt_record(tls12_context_t *ctx,
                                       uint8_t type,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len)
{
    const uint8_t *mac_key = NULL;
    uint32_t mac_key_len = 0U;
    const uint8_t *enc_key = NULL;
    uint32_t enc_key_len = 0U;
    const uint8_t *write_iv = NULL;
    uint32_t iv_len = 0U;
    uint64_t seq_num = 0U;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    noxtls_aes_type_t aes_type;
    uint8_t iv[16];
    uint8_t *decrypted_data = NULL;
    uint32_t decrypted_data_len = 0U;
    uint8_t mac[64];  /* Max MAC size (SHA-512) */
    uint32_t mac_len = 0U;
    uint8_t padding_len = 0U;
    uint32_t plaintext_data_len = 0U;
    uint32_t offset = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t block_size = 0U;
    uint8_t is_gcm = 0U;
    uint8_t is_tls12_ccm = 0U;
    uint8_t is_tls12_chacha = 0U;
    uint32_t tls12_ccm_tag_len = 16U;
    uint8_t is_3des = 0U;
    
    if((ctx == NULL) || (encrypted_record == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        mac_key = ctx->server_write_mac_key;  /* Receive from server */
        enc_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 16U;
        seq_num = (tls12_is_dtls_context(ctx) != 0) ? tls12_dtls_read_seq64(ctx) : ctx->server_seq_num;
    } else {
        mac_key = ctx->client_write_mac_key;  /* Receive from client */
        enc_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 16U;
        seq_num = (tls12_is_dtls_context(ctx) != 0) ? tls12_dtls_read_seq64(ctx) : ctx->client_seq_num;
    }

    /* Determine hash algorithm, MAC length, and cipher type from cipher suite */
    hash_algo = NOXTLS_HASH_SHA_256;
    mac_key_len = 32U;
    enc_key_len = 32U;
    aes_type = NOXTLS_AES_256_BIT;
    uint8_t is_aria = 0U;
    noxtls_aria_type_t aria_type = NOXTLS_ARIA_256_BIT;

    switch(ctx->cipher_suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 24U;
            iv_len = 8U;
            is_3des = 1U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            is_3des = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            is_aria = 0U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_gcm = 1U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 12U;
            is_aria = 0U;
            is_tls12_chacha = 1U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            is_3des = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
            hash_algo = ((ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ||
                          (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)) ?
                        NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_256;
            mac_key_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 32U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            is_aria = 0U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384:
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_gcm = 1U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 16U;
            break;
#if NOXTLS_FEATURE_DTLS_ECJPAKE
        case TLS_CIPHER_SUITE_ECJPAKE_WITH_AES_128_CCM_8: /* RFC 6655 section 3 / draft-cragie-tls-ecjpake-01 */
#endif
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 16U;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 8U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 16U;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0U;
            enc_key_len = 32U;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4U;
            is_aria = 0U;
            is_tls12_ccm = 1U;
            tls12_ccm_tag_len = 8U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
            is_aria = 1U;
            aria_type = NOXTLS_ARIA_128_BIT;
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32U;
            enc_key_len = 16U;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            is_aria = 1U;
            aria_type = NOXTLS_ARIA_256_BIT;
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 48U;
            enc_key_len = 32U;
            break;
        default:
            /* Defaults already set (AES-256/SHA-256) */
            break;
    }
    
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1U;
    uint32_t iv_is_zero = 1U;
    uint32_t k = 0U;
    for(k = 0U; k < enc_key_len; k += 1U) {
        if(enc_key[k] != 0U) {
            key_is_zero = 0U;
            break;
        }
    }
    for(k = 0U; k < iv_len; k += 1U) {
        if(write_iv[k] != 0U) {
            iv_is_zero = 0U;
            break;
        }
    }
    
    if((key_is_zero != 0U) || (iv_is_zero != 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if((is_gcm != 0U) || (is_tls12_ccm != 0U) || (is_tls12_chacha != 0U)) {
        uint8_t nonce[12];
        uint8_t aad[13];
        uint8_t tag[16];
        uint32_t aad_len = 13U;
        uint32_t ciphertext_len = 0U;
        const uint8_t *ciphertext = NULL;
        const uint8_t *tag_in = NULL;
        uint32_t tag_len = 0U;
        if((is_tls12_chacha != 0U) || (is_gcm != 0U)) {
            tag_len = 16U;
        } else {
            tag_len = tls12_ccm_tag_len;
        }

        if(is_tls12_chacha != 0U) {
            if(encrypted_record_len < tag_len) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            ciphertext_len = encrypted_record_len - tag_len;
            ciphertext = encrypted_record;
            tag_in = &encrypted_record[ciphertext_len];
#if NOXTLS_FEATURE_CHACHA20_POLY1305
            tls12_chacha20_poly1305_record_nonce(nonce, write_iv, seq_num);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else {
            /* MISRA 15.7: final else path */
            if(encrypted_record_len < (8U + tag_len)) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            {
                uint8_t fixed_iv[4];
                uint8_t explicit_nonce[8];
                noxtls_copy_u8(explicit_nonce, sizeof(explicit_nonce), encrypted_record, (size_t)(8U));
                noxtls_copy_u8(fixed_iv, sizeof(fixed_iv), write_iv, (size_t)(4U));
                noxtls_copy_u8(nonce, sizeof(nonce), fixed_iv, (size_t)(4U));
                noxtls_copy_u8(&nonce[4], sizeof(nonce) - (size_t)(4), explicit_nonce, (size_t)(8U));
            }
            ciphertext_len = encrypted_record_len - 8U - tag_len;
            ciphertext = &encrypted_record[8];
            tag_in = &encrypted_record[8U + ciphertext_len];
        }

        aad[0] = (uint8_t)(((uint64_t)seq_num) >> 56U);
        aad[1] = (uint8_t)(((uint64_t)seq_num) >> 48U);
        aad[2] = (uint8_t)(((uint64_t)seq_num) >> 40U);
        aad[3] = (uint8_t)(((uint64_t)seq_num) >> 32U);
        aad[4] = (uint8_t)(((uint64_t)seq_num) >> 24U);
        aad[5] = (uint8_t)(((uint64_t)seq_num) >> 16U);
        aad[6] = (uint8_t)(((uint64_t)seq_num) >> 8U);
        aad[7] = (uint8_t)seq_num;
        aad[8] = type;
        aad[9] = (uint8_t)((uint32_t)ctx->base.base.version >> 8U);
        aad[10] = (uint8_t)(ctx->base.base.version);
        aad[11] = (uint8_t)(((uint32_t)ciphertext_len) >> 8U);
        aad[12] = (uint8_t)ciphertext_len;

        noxtls_copy_u8(tag, sizeof(tag), tag_in, (size_t)(tag_len));
        if(type == TLS_RECORD_APPLICATION_DATA) {
            uint32_t max_pl = (uint32_t)((ctx->max_record_payload > 0U) ? (uint32_t)ctx->max_record_payload : (uint32_t)TLS_MAX_RECORD_SIZE);
            if(ciphertext_len > max_pl) {
                return NOXTLS_RETURN_RECORD_OVERFLOW;
            }
        }
        if(*plaintext_len < ciphertext_len) {
            *plaintext_len = ciphertext_len;
            return NOXTLS_RETURN_FAILED;
        }
        if(is_tls12_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
            if(noxtls_chacha20_poly1305_decrypt(enc_key, nonce, aad, aad_len,
                                                ciphertext, ciphertext_len, tag, plaintext) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_BAD_DATA;
            }
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else if(is_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
            if(noxtls_aes_gcm_decrypt(enc_key, aes_type, nonce, aad, aad_len,
                               ciphertext, ciphertext_len, tag, plaintext) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_BAD_DATA;
            }
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else {
            /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_AES_CCM
            if(noxtls_aes_ccm_decrypt(enc_key, aes_type, nonce, 12U, aad, aad_len,
                               ciphertext, ciphertext_len, tag, tag_len, plaintext) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_BAD_DATA;
            }
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        }
        *plaintext_len = ciphertext_len;

        if((tls12_is_dtls_context(ctx) == 0)) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                ctx->server_seq_num += 1U;
            } else {
                /* MISRA 15.7: final else path */
                ctx->client_seq_num += 1U;
            }
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    
    block_size = (uint32_t)((is_3des != 0U) ? NOXTLS_DES_BLOCK_LENGTH : NOXTLS_AES_BLOCK_LENGTH);
    mac_len = tls12_mac_len_from_hash(hash_algo);
    int32_t use_encrypt_then_mac = tls12_should_use_encrypt_then_mac(ctx, is_gcm, is_tls12_ccm, is_tls12_chacha);
    /* For MAC-then-encrypt, the full record is encrypted.  Encrypt-then-MAC
     * leaves the outer MAC after the encrypted portion and overrides this
     * value below. */
    uint32_t encrypted_part_len = (uint32_t)(encrypted_record_len);

    if(use_encrypt_then_mac != 0) {
        uint8_t received_outer_mac[64];
        uint8_t computed_outer_mac[64];
        uint32_t computed_outer_mac_len = (uint32_t)(mac_len);
        if(encrypted_record_len < (mac_len + block_size)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        encrypted_part_len = encrypted_record_len - mac_len;
        noxtls_copy_u8(received_outer_mac, sizeof(received_outer_mac), &encrypted_record[encrypted_part_len], (size_t)(mac_len));
        rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num, type,
                              ctx->base.base.version, (uint16_t)encrypted_part_len,
                              encrypted_record, encrypted_part_len,
                              computed_outer_mac, &computed_outer_mac_len);
        if((rc != NOXTLS_RETURN_SUCCESS) || (computed_outer_mac_len != mac_len)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(noxtls_secret_memcmp(received_outer_mac, computed_outer_mac, (size_t)(mac_len)) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    /* TLS 1.0: no leading IV (implicit); TLS 1.1/1.2: IV at start of record */
    uint32_t encrypted_data_len = 0U;
    if(ctx->base.base.version == TLS_VERSION_1_0) {
        uint64_t read_seq = (uint64_t)((ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_seq_num : ctx->client_seq_num);
        const uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_last_cipher_block : ctx->client_last_cipher_block;
        if(read_seq == 0U) {
            noxtls_copy_u8(iv, sizeof(iv), write_iv, (size_t)(iv_len));
        } else {
            noxtls_copy_u8(iv, sizeof(iv), last_block, (size_t)(iv_len));
        }
        encrypted_data_len = encrypted_part_len;
        offset = 0U;
    } else {
        /* MISRA 15.7: final else path */
        if(encrypted_part_len < iv_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        noxtls_copy_u8(iv, sizeof(iv), encrypted_record, (size_t)(iv_len));
        offset += iv_len;
        encrypted_data_len = encrypted_part_len - iv_len;
    }
    
    /* Encrypted payload length check */
    if((encrypted_data_len < block_size) || ((encrypted_data_len % block_size) != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate buffer for decrypted data */
    decrypted_data = (uint8_t*)NOXTLS_MALLOC(encrypted_data_len);
    if(decrypted_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Decrypt using AES-CBC or ARIA-CBC */
    if(is_3des != 0U) {
#if NOXTLS_FEATURE_DES
        if(des3_decrypt_cbc(enc_key, 24U, &encrypted_record[offset], encrypted_data_len, iv, decrypted_data) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
#else
        (void)noxtls_free(decrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(is_aria != 0U) {
#if NOXTLS_FEATURE_ARIA
        if(noxtls_aria_decrypt_cbc(enc_key, &encrypted_record[offset], encrypted_data_len, iv, decrypted_data, aria_type) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
#else
        (void)aria_type;
        (void)noxtls_free(decrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_AES_CBC
        if(noxtls_aes_decrypt_cbc(enc_key, &encrypted_record[offset], encrypted_data_len, iv, decrypted_data, aes_type) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
#else
        (void)noxtls_free(decrypted_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    
    decrypted_data_len = encrypted_data_len;
    
    /* TLS 1.0: save last cipher block for next record's IV */
    if((ctx->base.base.version == TLS_VERSION_1_0) && (encrypted_data_len >= iv_len)) {
        uint8_t *save_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_last_cipher_block : ctx->client_last_cipher_block;
        const uint8_t *ct = (offset > 0U) ? (&encrypted_record[offset]) : encrypted_record;
        noxtls_copy_u8(save_block, (size_t)iv_len, &ct[encrypted_data_len - iv_len], (size_t)iv_len);
    }
    
    /* Validate and remove padding with a unified bad-record path. */
    uint32_t bad_record = 0U;
    uint32_t pad_bytes = 0U;
    uint32_t pad_scan_len = 0U;
    uint32_t body_len = 0U;
    uint32_t i = 0U;
    uint8_t computed_mac[64];
    uint32_t computed_mac_len = 0U;

    bad_record = 0U;
    uint8_t bad_padding = 0U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
    /* Diagnostic-only detail for the bad_record trace below; bad_record alone decides. */
    uint8_t bad_inner_mac = 0U;
    uint8_t bad_length = 0U;
#endif
    pad_bytes = 1U;
    noxtls_secure_zero((mac), sizeof(mac));
    noxtls_secure_zero((computed_mac), sizeof(computed_mac));

    if(decrypted_data_len == 0U) {
        bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
        bad_length = 1U;
#endif
        padding_len = 0U;
    } else {
        padding_len = decrypted_data[decrypted_data_len - 1U];
        pad_bytes = (uint32_t)padding_len + 1U;
    }

  /* TLS CBC padding may be up to 255 bytes (length byte value 0..255). */
    if(pad_bytes > decrypted_data_len) {
        bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
        bad_length = 1U;
#endif
        pad_bytes = 1U; /* keep bounds-safe for scan and length math */
    }

    /* TLS requires every padding byte to match the length field. Scanning
     * only one cipher block misses invalid padding when pad_bytes > block_size
     * (e.g. tlsfuzzer test_fuzzed_padding with min_length=20 on AES-CBC).
     * The scan always covers the largest possible padding region (256 bytes,
     * bounded by the record) and masks bytes outside the claimed padding, so
     * the loop count and branches do not depend on the decrypted length byte. */
    pad_scan_len = (decrypted_data_len < 256U) ? decrypted_data_len : 256U;
    {
        uint8_t pad_diff = 0U;
        for(i = 0U; i < pad_scan_len; i += 1U) {
            uint8_t tail = decrypted_data[decrypted_data_len - 1U - i];
            /* in_pad = 1 when i < pad_bytes (both < 2^31: the difference wraps). */
            uint32_t in_pad = (uint32_t)((i - pad_bytes) >> 31U);
            uint8_t mask = (uint8_t)((0U - in_pad) & 0xFFU);
            pad_diff |= (uint8_t)((tail ^ padding_len) & mask);
        }
        bad_padding = (uint8_t)((((uint32_t)pad_diff + 0xFFU) >> 8U) & 1U);
        bad_record |= (uint32_t)bad_padding;
    }

    body_len = decrypted_data_len - pad_bytes;
    if(use_encrypt_then_mac != 0) {
        plaintext_data_len = body_len;
    } else {
        if(body_len < mac_len) {
            bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
            bad_length = 1U;
#endif
            plaintext_data_len = 0U;
        } else {
            plaintext_data_len = body_len - mac_len;
        }

        if(body_len >= mac_len) {
            noxtls_copy_u8(mac, sizeof(mac), &decrypted_data[plaintext_data_len], (size_t)(mac_len));
        }

        computed_mac_len = mac_len;
        rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num,
                              type,
                              ctx->base.base.version, (uint16_t)plaintext_data_len,
                              decrypted_data, plaintext_data_len,
                              computed_mac, &computed_mac_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
            bad_inner_mac = 1U;
#endif
        }

        if(computed_mac_len != mac_len) {
            bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
            bad_inner_mac = 1U;
#endif
        } else if(noxtls_secret_memcmp(mac, computed_mac, (size_t)(mac_len)) != 0) {
            bad_record = 1U;
#if NOXTLS_DEBUG_PRINTF_ENABLED
            bad_inner_mac = 1U;
#endif
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }
    }
    /*
     * Padding, length and MAC failures all end in the same bad_record_mac result
     * (RFC 5246 6.2.3.2, RFC 7366). The record_overflow check uses a length derived
     * from the (unauthenticated) padding byte, so it is only evaluated after the
     * record authenticated; reporting it first turned the error code into a
     * padding oracle.
     */
    if(bad_record != 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS12_REC] decrypt bad_record: suite=0x%04X type=%u seq=%llu etm=%d pad=%u inner_mac=%u len=%u dec_len=%u pad_len=%u body=%u mac_len=%u\n",
                            (uint32_t)ctx->cipher_suite,
                            (uint32_t)type,
                            (unsigned long long)seq_num,
                            use_encrypt_then_mac,
                            (uint32_t)bad_padding,
                            (uint32_t)bad_inner_mac,
                            (uint32_t)bad_length,
                            (uint32_t)decrypted_data_len,
                            (uint32_t)padding_len,
                            (uint32_t)body_len,
                            (uint32_t)mac_len);
        (void)noxtls_free(decrypted_data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(type == TLS_RECORD_APPLICATION_DATA) {
        uint32_t max_pl = (uint32_t)((ctx->max_record_payload > 0U)
            ? (uint32_t)ctx->max_record_payload
            : (uint32_t)TLS_MAX_RECORD_SIZE);
        if(plaintext_data_len > max_pl) {
            (void)noxtls_free(decrypted_data);
            return NOXTLS_RETURN_RECORD_OVERFLOW;
        }
    }

    /* Copy plaintext to output */
    if(*plaintext_len < plaintext_data_len) {
        (void)noxtls_free(decrypted_data);
        *plaintext_len = plaintext_data_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_copy_u8(plaintext, (size_t)plaintext_data_len, decrypted_data, (size_t)plaintext_data_len);
    *plaintext_len = plaintext_data_len;
    
    (void)noxtls_free(decrypted_data);
    
    /* Update sequence number */
    if((tls12_is_dtls_context(ctx) == 0)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->server_seq_num += 1U;
        } else {
            ctx->client_seq_num += 1U;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate TLS 1.3 nonce from sequence number
 * nonce = client_write_iv XOR (0...0 || seq_num)
 *
 * @param[out] nonce The nonce to generate
 * @param[in] write_iv The write IV
 * @param[in] iv_len The length of the IV
 * @param[in] seq_num The sequence number
 * @return void
 */
static void tls13_generate_nonce(uint8_t *nonce, const uint8_t *write_iv, uint32_t iv_len, uint64_t seq_num)
{
    /* Copy write IV */
    noxtls_copy_u8(nonce, (size_t)iv_len, write_iv, (size_t)iv_len);
    
    /* XOR sequence number into last 8 bytes */
    if(iv_len >= 8U) {
        nonce[iv_len - 8U + 0U] ^= (uint8_t)((((uint64_t)seq_num) >> 56U) & 0xFFU);
        nonce[iv_len - 8U + 1U] ^= (uint8_t)((((uint64_t)seq_num) >> 48U) & 0xFFU);
        nonce[iv_len - 8U + 2U] ^= (uint8_t)((((uint64_t)seq_num) >> 40U) & 0xFFU);
        nonce[iv_len - 8U + 3U] ^= (uint8_t)((((uint64_t)seq_num) >> 32U) & 0xFFU);
        nonce[iv_len - 8U + 4U] ^= (uint8_t)((((uint64_t)seq_num) >> 24U) & 0xFFU);
        nonce[iv_len - 8U + 5U] ^= (uint8_t)((((uint64_t)seq_num) >> 16U) & 0xFFU);
        nonce[iv_len - 8U + 6U] ^= (uint8_t)((((uint64_t)seq_num) >> 8U) & 0xFFU);
        nonce[iv_len - 8U + 7U] ^= (uint8_t)(seq_num & 0xFFU);
    }
}

/**
 * @brief Check if the context is a DTLS 1.2 context
 *
 * @param[in] ctx The context
 * @return 1 if the context is a DTLS 1.2 context, 0 otherwise
 */
static int32_t tls12_is_dtls_context(const tls12_context_t *ctx) { return (((ctx != NULL) && (ctx->base.base.version == DTLS_VERSION_1_2)) ? 1 : 0); }

/**
 * @brief DTLS 1.2 write sequence number for the MAC / AEAD input.
 *
 * RFC 6347 4.1.2.1: the 64-bit seq_num of the TLS MAC (and of the RFC 5246 AEAD additional
 * data / explicit nonce, RFC 7905 nonce) is epoch(16) || sequence_number(48) of the record.
 *
 * @param[in] ctx The DTLS 1.2 context.
 * @return epoch || write sequence number.
 */
static uint64_t tls12_dtls_write_seq64(const tls12_context_t *ctx)
{
    return (((uint64_t)ctx->base.epoch) << 48U) | (ctx->base.write_seq_num & DTLS_SEQ_NUM_MASK);
}

/**
 * @brief DTLS 1.2 read sequence number (current read epoch || sequence number of the record).
 *
 * The record layer only delivers records of the current read epoch (noxtls_dtls_recv_record).
 *
 * @param[in] ctx The DTLS 1.2 context.
 * @return epoch || read sequence number.
 */
static uint64_t tls12_dtls_read_seq64(const tls12_context_t *ctx)
{
    return (((uint64_t)ctx->base.read_epoch) << 48U) | (ctx->base.read_seq_num & DTLS_SEQ_NUM_MASK);
}

/**
 * @brief Check if the context is a DTLS 1.3 context
 *
 * @param[in] ctx The context
 * @return 1 if the context is a DTLS 1.3 context, 0 otherwise
 */
static int32_t tls13_is_dtls_context(const tls13_context_t *ctx) { return (((ctx != NULL) && (ctx->base.base.version == DTLS_VERSION_1_3)) ? 1 : 0); }

/**
 * @brief Check if the connection ID matches or promotes the context
 *
 * @param[in] ctx The context
 * @param[in] cid The connection ID
 * @param[in] cid_len The length of the connection ID
 * @return 1 if the connection ID matches or promotes the context, 0 otherwise
 */
static int tls13_dtls_cid_matches_or_promotes(tls13_context_t *ctx, const uint8_t *cid, uint32_t cid_len)
{
    if((ctx == NULL) || (cid == NULL) || (cid_len == 0U) || (cid_len > 32U)) {
        return 0;
    }
    if(ctx->own_connection_id_len == cid_len) {
        if(noxtls_ct_equal(cid, ctx->own_connection_id, (size_t)cid_len) != 0) {
            return 1;
        }
    }
    for(uint8_t i = 0U; i < ctx->own_spare_connection_id_count; i += 1U) {
        if(ctx->own_spare_connection_id_lens[i] == cid_len) {
            if(noxtls_ct_equal(cid, ctx->own_spare_connection_ids[i], (size_t)cid_len) != 0) {
                noxtls_copy_u8(ctx->own_connection_id, sizeof(ctx->own_connection_id), ctx->own_spare_connection_ids[i], (size_t)cid_len);
                ctx->own_connection_id_len = (uint8_t)cid_len;
                for(uint8_t j = (uint8_t)(i + 1U); j < ctx->own_spare_connection_id_count; j += 1U) {
                    noxtls_copy_u8(ctx->own_spare_connection_ids[j - 1U], sizeof(ctx->own_spare_connection_ids[j - 1U]), ctx->own_spare_connection_ids[j], 32U);
                    ctx->own_spare_connection_id_lens[j - 1U] = ctx->own_spare_connection_id_lens[j];
                }
                ctx->own_spare_connection_id_count--;
                noxtls_secure_zero((ctx->own_spare_connection_ids[ctx->own_spare_connection_id_count]), (size_t)(32U));
                ctx->own_spare_connection_id_lens[ctx->own_spare_connection_id_count] = 0U;
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief Check if the sequence number is in the replay window
 *
 * @param[in] window The replay window
 * @param[in] sequence_number The sequence number
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
static noxtls_return_t dtls13_replay_check_window(const dtls_replay_window_t *window, uint64_t sequence_number)
{
    uint64_t last_seq = 0U;
    uint64_t diff = 0U;

    if(window == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    last_seq = window->last_seq;
    if(sequence_number > last_seq) {
        return NOXTLS_RETURN_SUCCESS;
    }

    diff = last_seq - sequence_number;
    if(diff >= DTLS_REPLAY_WINDOW_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }
    if((window->window_bitmap & tls_record_s_u64_bit[diff & 63U]) != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update the replay window
 *
 * @param[in] window The replay window
 * @param[in] sequence_number The sequence number
 * @return void
 */
static void dtls13_replay_update_window(dtls_replay_window_t *window, uint64_t sequence_number)
{
    uint64_t last_seq = 0U;
    uint64_t diff = 0U;

    if(window == NULL) {
        return;
    }

    last_seq = window->last_seq;
    if(sequence_number > last_seq) {
        diff = sequence_number - last_seq;
        if(diff >= DTLS_REPLAY_WINDOW_SIZE) {
            window->window_bitmap = 1U;
        } else {
            window->window_bitmap <<= (diff & 63U);
            window->window_bitmap |= 1U;
        }
        window->last_seq = sequence_number;
        return;
    }

    diff = last_seq - sequence_number;
    if(diff < DTLS_REPLAY_WINDOW_SIZE) {
        window->window_bitmap |= tls_record_s_u64_bit[diff & 63U];
    }
}

/**
 * @brief Reconstruct the record number
 *
 * @param[in] ctx The context
 * @param[in] epoch_low The epoch low
 * @param[in] truncated The truncated value
 * @param[in] truncated_bits The truncated bits
 * @return The reconstructed record number
 */
static uint64_t dtls13_reconstruct_record_number(const dtls_context_t *ctx, uint8_t epoch_low,
                                                 uint16_t truncated, uint8_t truncated_bits)
{
    uint64_t window = tls_record_s_u64_bit[truncated_bits & 63U];
    uint64_t half_window = (uint64_t)(window >> 1U);
    uint64_t candidate = 0U;
    uint64_t expected = 0U;
    uint8_t idx = (uint8_t)(epoch_low & DTLS13_UNIFIED_EPOCH_MASK);

    if((ctx == NULL) || (ctx->highest_recv_seq_valid[idx] == 0U)) {
        return truncated;
    }

    expected = ctx->highest_recv_seq[idx] + 1U;
    candidate = (expected & ~(window - 1U)) | (uint64_t)truncated;
    if((candidate + half_window) <= expected) {
        candidate += window;
    } else if((candidate > (expected + half_window)) && (candidate >= window)) {
        candidate -= window;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }
    return candidate;
}

/**
 * @brief Get the record cipher parameters
 *
 * @param[in] cipher_suite The cipher suite
 * @param[out] use_aes_gcm Whether to use AES-GCM
 * @param[out] use_aes_ccm Whether to use AES-CCM
 * @param[out] use_chacha Whether to use ChaCha20
 * @param[out] aes_type The AES type
 * @param[out] tag_len The tag length
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the output parameters are NULL, or 
 *         NOXTLS_RETURN_INVALID_PARAM if the cipher suite is invalid
 */
static noxtls_return_t tls13_get_record_cipher_params(uint16_t cipher_suite,
                                                uint8_t *use_aes_gcm,
                                                uint8_t *use_aes_ccm,
                                                uint8_t *use_chacha,
                                                noxtls_aes_type_t *aes_type,
                                                uint32_t *tag_len)
{
    if((use_aes_gcm == NULL) || (use_aes_ccm == NULL) || (use_chacha == NULL) || (aes_type == NULL) || (tag_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    *use_aes_gcm = 0U;
    *use_aes_ccm = 0U;
    *use_chacha = 0U;
    *aes_type = NOXTLS_AES_128_BIT;
    *tag_len = 16U;

    switch(cipher_suite) {
#if NOXTLS_FEATURE_AES_GCM
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
            *use_aes_gcm = 1U;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            *use_aes_gcm = 1U;
            *aes_type = NOXTLS_AES_256_BIT;
            *tag_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_AES_CCM
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
            *use_aes_ccm = 1U;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
            *use_aes_ccm = 1U;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 8U;
            return NOXTLS_RETURN_SUCCESS;
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            *use_chacha = 1U;
            *tag_len = 16U;
            return NOXTLS_RETURN_SUCCESS;
#endif
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Encrypt TLS 1.3 application data record (AEAD)
 *
 * @param[in] ctx The context
 * @param[in] type The type of the record
 * @param[in] plaintext The plaintext of the record
 * @param[in] plaintext_len The length of the plaintext
 * @param[out] encrypted_record The encrypted record
 * @param[out] encrypted_record_len The length of the encrypted record
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_tls13_encrypt_record(tls13_context_t *ctx,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    const uint8_t *write_key = NULL;
    const uint8_t *write_iv = NULL;
    uint32_t iv_len = 0U;
    uint64_t seq_num = 0U;
    uint8_t nonce[12];
    uint8_t aad[5];  /* Additional Authenticated Data: type || version || length */
    uint8_t tag[16];
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16U;
    uint32_t record_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if((ctx == NULL) || (plaintext == NULL) || (encrypted_record == NULL) || (encrypted_record_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        write_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 12U;
        seq_num = (tls13_is_dtls_context(ctx) != 0) ? ctx->base.write_seq_num : ctx->client_seq_num;
    } else {
        write_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 12U;
        seq_num = (tls13_is_dtls_context(ctx) != 0) ? ctx->base.write_seq_num : ctx->server_seq_num;
    }

    /* SECURITY (NX-09): refuse to encrypt once the record sequence number is
     * exhausted. Incrementing past UINT64_MAX would wrap and reuse an AEAD nonce
     * with the same key. RFC 8446 requires a key update / termination here. */
    if(seq_num == UINT64_MAX) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Generate nonce */
    tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
    
    rc = tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Record format: encrypted_data || tag */
    record_len = plaintext_len + tag_len;  /* &plaintext[tag] */
    
    /* Build AAD: type || version || length */
    /* AAD length field is the encrypted_content length (&ciphertext[tag]) */
    aad[0] = type;
    aad[1] = (uint8_t)(((uint32_t)ctx->base.base.version >> 8U) & 0xFFU);
    aad[2] = (uint8_t)(ctx->base.base.version & 0xFFU);
    aad[3] = (uint8_t)((((uint32_t)record_len) >> 8U) & 0xFFU);
    aad[4] = (uint8_t)(record_len & 0xFFU);
    
    if(*encrypted_record_len < record_len) {
        *encrypted_record_len = record_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, aad, 5U,
                             plaintext, plaintext_len,
                             encrypted_record, tag);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_aes_ccm != 0U) {
#if NOXTLS_FEATURE_AES_CCM
        rc = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12U, aad, 5U,
                             plaintext, plaintext_len, encrypted_record, tag, tag_len);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc = noxtls_chacha20_poly1305_encrypt(write_key, nonce, aad, 5U,
                                       plaintext, plaintext_len,
                                       encrypted_record, tag);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    /* Append tag to ciphertext */
    noxtls_copy_u8(&encrypted_record[plaintext_len], (size_t)(*encrypted_record_len), tag, (size_t)(tag_len));
    
    *encrypted_record_len = record_len;
    
    /* Update sequence number */
    if((tls13_is_dtls_context(ctx) == 0)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->client_seq_num += 1U;
        } else {
            ctx->server_seq_num += 1U;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 9147: Send one DTLS 1.3 encrypted record (DTLSCiphertext with unified header + record number encryption).
 * inner_plaintext is the DTLSInnerPlaintext (content || content_type || padding).
 */
/* Unified header worst case: 1 flags + 2 seq + 2 length + 255 CID (RFC 9146/9147 CID length is 0..255). */
#define DTLS13_MAX_HEADER_LEN  (1U + 2U + 2U + 255U)

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/**
 * @brief Send one DTLS 1.3 encrypted record (DTLSCiphertext with unified header + record number encryption).
 *
 * @param[in] ctx The context
 * @param[in] use_handshake_keys Whether to use handshake keys
 * @param[in] content_type The content type
 * @param[in] inner_plaintext The inner plaintext
 * @param[in] inner_len The length of the inner plaintext
 * @param[in] omit_length Whether to omit the length
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */
noxtls_return_t noxtls_tls13_send_dtls13_encrypted_record(tls13_context_t *ctx,
                                       int32_t use_handshake_keys,
                                       uint8_t content_type,
                                       const uint8_t *inner_plaintext,
                                       uint32_t inner_len,
                                       int32_t omit_length)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    (void)content_type;
    uint8_t header[DTLS13_MAX_HEADER_LEN];
    uint32_t header_len = 0U;
    uint32_t seq_offset = 0U;
    uint32_t seq_len = 0U;
    uint32_t len_offset = 0U;
    uint32_t cid_offset = 0U;
    uint8_t *ciphertext = NULL;
    uint8_t *padded_inner = NULL;
    const uint8_t *aead_inner = inner_plaintext;
    uint32_t aead_inner_len = (uint32_t)(inner_len);
    uint32_t record_len = 0U;
    uint64_t seq_num = 0U;
    uint16_t epoch = 0U;
    const uint8_t *write_key = NULL;
    const uint8_t *write_iv = NULL;
    const uint8_t *sn_key = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t mask[DTLS13_RECORD_NUMBER_ENC_LEN];
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16U;
    noxtls_return_t rc_aead = NOXTLS_RETURN_FAILED;
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    noxtls_chacha20_context_t chacha_ctx;
#endif

    if((ctx == NULL) || (inner_plaintext == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(tls13_is_dtls_context(ctx) == 0) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    record_len = aead_inner_len + tag_len;  /* &ciphertext[tag] */
    if(record_len < DTLS13_RECORD_NUMBER_ENC_LEN) {
        uint32_t padded_len = (uint32_t)(DTLS13_RECORD_NUMBER_ENC_LEN - tag_len);
        if(padded_len < aead_inner_len) {
            return NOXTLS_RETURN_FAILED;
        }
        padded_inner = (uint8_t*)NOXTLS_MALLOC(padded_len);
        if(padded_inner == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        noxtls_copy_u8(padded_inner, (size_t)inner_len, inner_plaintext, (size_t)inner_len);
        noxtls_secure_zero((&padded_inner[inner_len]), ((size_t)(padded_len - inner_len)));
        aead_inner = padded_inner;
        aead_inner_len = padded_len;
        record_len = aead_inner_len + tag_len;
    }

    epoch = ctx->base.epoch;
    seq_num = ctx->base.write_seq_num;

    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] send_dtls13_record: hs=%d epoch=%u seq=%llu inner_len=%u content_type=0x%02X omit_length=%d\n",
                        use_handshake_keys,
                        (uint32_t)epoch,
                        (unsigned long long)seq_num,
                        inner_len,
                        content_type,
                        omit_length);

    /*
     * The write key / IV always hold the current write epoch's traffic keys. RFC 9147 4.2.3:
     * the record number is encrypted with the sn_key of the epoch the record is sent in, so
     * the key is chosen from the write epoch (handshake epoch 2 vs. application epochs >= 3);
     * use_handshake_keys is only a caller hint and cannot select a key of another epoch.
     */
    write_key = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_write_key : ctx->server_write_key;
    write_iv  = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_write_iv  : ctx->server_write_iv;
    if(epoch == (uint16_t)DTLS13_EPOCH_HANDSHAKE) {
        sn_key = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_handshake_sn_key : ctx->server_handshake_sn_key;
    } else {
        sn_key = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_sn_key : ctx->server_sn_key;
    }

    /*
     * Unified header (RFC 9147 4, Figure 3): 001 C S L EE, optional CID, encrypted 8- or 16-bit
     * sequence number, optional 16-bit length.
     */
    seq_len = ((seq_num & ~0xFFULL) != 0U) ? 2U : 1U;
    cid_offset = 1U;
    seq_offset = cid_offset + (uint32_t)ctx->peer_connection_id_len;
    len_offset = seq_offset + seq_len;
    header_len = len_offset + ((omit_length != 0) ? 0U : 2U);
    if((header_len > (uint32_t)sizeof(header)) ||
       ((uint32_t)ctx->peer_connection_id_len > (uint32_t)sizeof(ctx->peer_connection_id))) {
        if(padded_inner != NULL) {
            (void)noxtls_free(padded_inner);
        }
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    header[0] = (uint8_t)(DTLS13_UNIFIED_FIXED_BITS | (epoch & DTLS13_UNIFIED_EPOCH_MASK));
    if(seq_len == 2U) {
        header[0] |= DTLS13_UNIFIED_S_BIT;
        header[seq_offset] = (uint8_t)((((uint64_t)seq_num) >> 8U) & 0xFFU);
        header[seq_offset + 1U] = (uint8_t)(seq_num & 0xFFU);
    } else {
        header[seq_offset] = (uint8_t)(seq_num & 0xFFU);
    }
    if(omit_length == 0) {
        header[0] |= DTLS13_UNIFIED_L_BIT;
        header[len_offset] = (uint8_t)((((uint32_t)record_len) >> 8U) & 0xFFU);
        header[len_offset + 1U] = (uint8_t)(record_len & 0xFFU);
    }
    if(ctx->peer_connection_id_len > 0U) {
        header[0] |= DTLS13_UNIFIED_CID_BIT;
        noxtls_copy_u8(&header[cid_offset], sizeof(header) - (size_t)(cid_offset), ctx->peer_connection_id, (size_t)(ctx->peer_connection_id_len));
    }

    ciphertext = (uint8_t*)NOXTLS_MALLOC(record_len);
    if(ciphertext == NULL) {
        if(padded_inner != NULL) {
            (void)noxtls_free(padded_inner);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    tls13_generate_nonce(nonce, write_iv, 12U, seq_num);

    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc_aead = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, header, header_len,
                                  aead_inner, aead_inner_len, ciphertext, tag);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_aes_ccm != 0U) {
#if NOXTLS_FEATURE_AES_CCM
        rc_aead = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12U, header, header_len,
                                  aead_inner, aead_inner_len, ciphertext, tag, tag_len);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc_aead = noxtls_chacha20_poly1305_encrypt(write_key, nonce, header, header_len,
                                            aead_inner, aead_inner_len, ciphertext, tag);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        if(padded_inner != NULL) {
            (void)noxtls_free(padded_inner);
        }
        (void)noxtls_free(ciphertext);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rc_aead != NOXTLS_RETURN_SUCCESS) {
        if(padded_inner != NULL) {
            (void)noxtls_free(padded_inner);
        }
        (void)noxtls_free(ciphertext);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(&ciphertext[aead_inner_len], (size_t)(record_len), tag, (size_t)(tag_len));
    if(padded_inner != NULL) {
        (void)noxtls_free(padded_inner);
        padded_inner = NULL;
    }

    /* Record number encryption (RFC 9147 §4.2.3): mask the leading sequence octets. */
    if((use_aes_gcm != 0U) || (use_aes_ccm != 0U)) {
        if(noxtls_aes_encrypt_data(sn_key, ciphertext, DTLS13_RECORD_NUMBER_ENC_LEN, NULL, mask, aes_type, NOXTLS_AES_ECB) != NOXTLS_RETURN_SUCCESS) {
            if(padded_inner != NULL) {
                (void)noxtls_free(padded_inner);
            }
            (void)noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        static const uint8_t zeros_16[16] = { 0 };
        uint32_t counter32 = (uint32_t)ciphertext[0] | ((uint32_t)ciphertext[1] << 8U) | ((uint32_t)ciphertext[2] << 16U) | ((uint32_t)ciphertext[3] << 24U);
        uint64_t counter = (uint64_t)counter32;
        if(noxtls_chacha20_init(&chacha_ctx, sn_key, &ciphertext[4], counter) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_chacha20_process(&chacha_ctx, zeros_16, mask, DTLS13_RECORD_NUMBER_ENC_LEN) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
#else
        (void)noxtls_free(ciphertext);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    if(seq_len == 2U) {
        header[seq_offset] = (uint8_t)(((seq_num >> 8U) & 0xFFU) ^ mask[0]);
        header[seq_offset + 1U] = (uint8_t)((seq_num & 0xFFU) ^ mask[1]);
    } else {
        header[seq_offset] = (uint8_t)((seq_num & 0xFFU) ^ mask[0]);
    }

    {
        uint32_t total = (uint32_t)(header_len + record_len);
        uint8_t *out = (uint8_t*)NOXTLS_MALLOC(total);
        if(out == NULL) {
            (void)noxtls_free(ciphertext);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] send_dtls13_record: header_len=%u record_len=%u total=%u first_hdr=0x%02X\n",
                            header_len, record_len, total, header[0]);
        noxtls_copy_u8(out, (size_t)header_len, header, (size_t)header_len);
        noxtls_copy_u8(&out[header_len], (size_t)record_len, ciphertext, (size_t)record_len);
        (void)noxtls_free(ciphertext);
        int32_t sent = ctx->base.base.send_callback(ctx->base.base.user_data, out, total);
        (void)noxtls_free(out);
        if(sent != (int32_t)total) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    ctx->base.write_seq_num += 1U;
    ctx->base.bytes_sent += (uint64_t)header_len;
    ctx->base.bytes_sent += (uint64_t)record_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 9147: Return byte length of the first DTLSCiphertext record in raw (for multiple records per datagram).
 *
 * Unified header layout (RFC 9147 section 4): 001CSLEE || CID (C set, negotiated length)
 * || sequence number (1 or 2 bytes) || length (2 bytes, L set) || encrypted record.
 * own_connection_id_len is from ctx->own_connection_id_len. Returns 0 if the header is invalid
 * or the record (including its encrypted part) does not fit entirely in raw_len bytes, so a
 * non-zero result can always be passed as the record length to noxtls_tls13_decrypt_dtls13_record().
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
uint32_t noxtls_tls13_dtls13_record_size(const uint8_t *raw, uint32_t raw_len, uint8_t own_connection_id_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t cid_len = 0U;
    uint32_t seq_len = 0U;
    uint32_t len_offset = 0U;
    uint32_t aad_len = 0U;
    uint32_t ciphertext_len = 0U;
    uint32_t record_len = 0U;
    if((raw == NULL) || (raw_len < 2U)) {
        return 0U;
    }
    if((raw[0] & 0xE0U) != DTLS13_UNIFIED_FIXED_BITS) {
        return 0U;
    }
    if(((raw[0] & DTLS13_UNIFIED_CID_BIT) != 0U) && (own_connection_id_len == 0U)) {
        return 0U;
    }
    cid_len = ((raw[0] & DTLS13_UNIFIED_CID_BIT) != 0U) ? (uint32_t)own_connection_id_len : 0U;
    seq_len = ((raw[0] & DTLS13_UNIFIED_S_BIT) != 0U) ? 2U : 1U;
    len_offset = 1U + cid_len + seq_len;
    if((raw[0] & DTLS13_UNIFIED_L_BIT) != 0U) {
        aad_len = len_offset + 2U;
        if(raw_len < (aad_len + 16U)) {
            return 0U;
        }
        ciphertext_len = ((uint32_t)raw[len_offset] << 8U) | (uint32_t)raw[len_offset + 1U];
        if(ciphertext_len < 16U) {
            return 0U;
        }
        record_len = aad_len + ciphertext_len;
        /* The 16-bit length is attacker controlled: never report a record that extends past the datagram. */
        if(record_len > raw_len) {
            return 0U;
        }
        return record_len;
    }
    aad_len = len_offset;
    if(raw_len < (aad_len + 16U)) {
        return 0U;
    }
    /* No length field: the record extends to the end of the datagram. */
    return raw_len;
}

/**
 * @brief RFC 9147: Decrypt one DTLS 1.3 DTLSCiphertext (unified header + record number decryption + AEAD).
 * raw = full packet (unified_hdr || encrypted_record). On success: out_content_type and out_plaintext filled; out_plaintext_len set to content length.
 *
 * @param[in] ctx The context
 * @param[in] raw The raw data
 * @param[in] raw_len The length of the raw data
 * @param[out] out_content_type The content type
 * @param[out] out_plaintext The plaintext
 * @param[out] out_plaintext_len The length of the plaintext
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED on failure
 */

noxtls_return_t noxtls_tls13_decrypt_dtls13_record(tls13_context_t *ctx,
                                       const uint8_t *raw, uint32_t raw_len,
                                       uint8_t *out_content_type, uint8_t *out_plaintext, uint32_t *out_plaintext_len)
{
    uint8_t epoch = 0U;
    uint32_t aad_len = 0U;
    uint32_t ciphertext_len = 0U;
    uint32_t inner_len = 0U;
    uint32_t tag_len = 0U;
    const uint8_t *ciphertext = NULL;
    uint16_t seq_enc = 0U;
    uint16_t seq_truncated = 0U;
    uint8_t seq_len = 0U;
    uint32_t seq_offset = 0U;
    uint32_t len_offset = 0U;
    uint64_t full_seq = 0U;
    uint8_t aad[DTLS13_MAX_HEADER_LEN];
    const uint8_t *read_key = NULL;
    const uint8_t *read_iv = NULL;
    const uint8_t *sn_key = NULL;
    uint8_t nonce[12];
    uint8_t mask[DTLS13_RECORD_NUMBER_ENC_LEN];
    uint8_t tag[16];
    uint8_t use_handshake = 0U;
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    noxtls_return_t rc_aead = NOXTLS_RETURN_FAILED;
    uint32_t i = 0U;
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    noxtls_chacha20_context_t chacha_ctx;
    static const uint8_t zeros_16[16] = { 0 };
#endif

    if((ctx == NULL) || (raw == NULL) || (out_content_type == NULL) || (out_plaintext == NULL) || (out_plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((tls13_is_dtls_context(ctx) == 0) || (raw_len < (4U + 8U + 1U))) {
        return NOXTLS_RETURN_BAD_DATA;  /* unified header + minimum AEAD &tag[at] least 1 byte inner */
    }
    if((raw[0] & 0xE0U) != DTLS13_UNIFIED_FIXED_BITS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (((raw[0] & DTLS13_UNIFIED_CID_BIT) != 0U) && (ctx->own_connection_id_len == 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    epoch = raw[0] & DTLS13_UNIFIED_EPOCH_MASK;
    /*
     * RFC 9147 4.2.3: unmask with the sn_key of the record's epoch. The header carries only the
     * low two epoch bits, and records never arrive from an epoch above the current read epoch,
     * so low bits 2 denote the handshake epoch until the read epoch reaches 6 (then 6, 10, ...).
     */
    use_handshake = ((epoch == DTLS13_EPOCH_HANDSHAKE) &&
                     (ctx->base.read_connection_epoch < (uint64_t)(DTLS13_EPOCH_HANDSHAKE + 4U))) ? 1U : 0U;
    seq_len = ((raw[0] & DTLS13_UNIFIED_S_BIT) != 0U) ? 2U : 1U;
    {
        /*
         * RFC 9147 4 (Figure 3): 001CSLEE || CID || sequence number || length. The CID field
         * carries the full negotiated connection ID (0..255 bytes) right after the first byte.
         */
        uint32_t cid_len = (uint32_t)(((raw[0U] & DTLS13_UNIFIED_CID_BIT) != 0U) ? (uint32_t)ctx->own_connection_id_len : 0U);
        uint32_t cid_offset = 1U;
        seq_offset = cid_offset + cid_len;
        len_offset = seq_offset + seq_len;
        aad_len = (uint32_t)(len_offset + (((raw[0U] & DTLS13_UNIFIED_L_BIT) != 0U) ? 2U : 0U));
        if(aad_len > (sizeof(aad)) ){
            return NOXTLS_RETURN_BAD_DATA;  /* never copy more than the AAD buffer holds */
        }
        if(raw_len < (aad_len + 16U)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(seq_len == 2U) {
            seq_enc = (uint16_t)(((uint16_t)raw[seq_offset] << 8U) | (uint16_t)raw[seq_offset + 1U]);
        } else {
            seq_enc = raw[seq_offset];
        }
        if ((raw[0] & DTLS13_UNIFIED_L_BIT) != 0U) {
            {
            uint32_t len_hi = (uint32_t)raw[len_offset];
            uint32_t len_lo = (uint32_t)raw[len_offset + 1U];
            ciphertext_len = (len_hi << 8U) | len_lo;
        }
            if(raw_len < (aad_len + ciphertext_len)) {
                (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: raw_len=%u aad_len=%u ciphertext_len=%u incomplete\n",
                                    raw_len, aad_len, ciphertext_len);
                return NOXTLS_RETURN_BAD_DATA;
            }
        } else {
            ciphertext_len = raw_len - aad_len;
        }
        /* RFC 9147 4.2.3: the record number mask is taken from the first 16 ciphertext bytes. */
        if(ciphertext_len < DTLS13_RECORD_NUMBER_ENC_LEN) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        ciphertext = &raw[aad_len];
        if(cid_len > 0U) {
            uint8_t cid_ok = 1U;
            if(cid_len > (raw_len - cid_offset)) {
                cid_ok = 0U;
            } else if(tls13_dtls_cid_matches_or_promotes(ctx, &raw[cid_offset], cid_len) == 0) {
                cid_ok = 0U;
            } else {
                /* CID accepted or promoted. */
            }
            if(cid_ok == 0U) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
    }

    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        read_key = ctx->server_write_key;
        read_iv  = ctx->server_write_iv;
        sn_key   = (use_handshake != 0U) ? ctx->server_handshake_sn_key : ctx->server_sn_key;
    } else {
        read_key = ctx->client_write_key;
        read_iv  = ctx->client_write_iv;
        sn_key   = (use_handshake != 0U) ? ctx->client_handshake_sn_key : ctx->client_sn_key;
    }

    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ciphertext_len <= tag_len) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: ciphertext_len=%u tag_len=%u too small\n",
                            ciphertext_len, tag_len);
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Record number decryption (reverse of send path) */
    if((use_aes_gcm != 0U) || (use_aes_ccm != 0U)) {
        if(noxtls_aes_encrypt_data(sn_key, ciphertext, DTLS13_RECORD_NUMBER_ENC_LEN, NULL, mask, aes_type, NOXTLS_AES_ECB) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        uint32_t counter32 = (uint32_t)ciphertext[0] | ((uint32_t)ciphertext[1] << 8U) | ((uint32_t)ciphertext[2] << 16U) | ((uint32_t)ciphertext[3] << 24U);
        uint64_t counter = (uint64_t)counter32;
        if(noxtls_chacha20_init(&chacha_ctx, sn_key, &ciphertext[4], counter) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_chacha20_process(&chacha_ctx, zeros_16, mask, DTLS13_RECORD_NUMBER_ENC_LEN) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    if(seq_len == 2U) {
        seq_truncated = (uint16_t)(seq_enc ^ (uint16_t)(((uint16_t)mask[0] << 8U) | (uint16_t)mask[1]));
    } else {
        seq_truncated = (uint16_t)(seq_enc ^ mask[0]);
    }
    full_seq = dtls13_reconstruct_record_number(&ctx->base, epoch, seq_truncated, (seq_len == 2U) ? 16U : 8U);
    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: epoch=%u use_hs=%d raw_len=%u aad_len=%u ctext_len=%u seq_len=%u seq_trunc=%u full_seq=%llu\n",
                        epoch,
                        use_handshake,
                        raw_len,
                        aad_len,
                        ciphertext_len,
                        seq_len,
                        (uint32_t)seq_truncated,
                        (unsigned long long)full_seq);
    if(dtls13_replay_check_window(&ctx->base.replay_windows[epoch & DTLS13_UNIFIED_EPOCH_MASK], full_seq) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: replay reject epoch=%u seq=%llu\n",
                            epoch, (unsigned long long)full_seq);
        return NOXTLS_RETURN_FAILED;
    }

    if(*out_plaintext_len < (ciphertext_len - tag_len)) {
        *out_plaintext_len = ciphertext_len - tag_len;
        return NOXTLS_RETURN_FAILED;
    }
    tls13_generate_nonce(nonce, read_iv, 12, full_seq);
    noxtls_copy_u8(aad, sizeof(aad), raw, (size_t)(aad_len));
    if(seq_len == 2U) {
        aad[seq_offset] = (uint8_t)((((uint32_t)(seq_truncated) >> 8U)) & 0xFFU);
        aad[seq_offset + 1U] = (uint8_t)(seq_truncated & 0xFFU);
    } else {
        aad[seq_offset] = (uint8_t)(seq_truncated & 0xFFU);
    }
    noxtls_copy_u8(tag, sizeof(tag), &ciphertext[ciphertext_len - tag_len], (size_t)(tag_len));
    inner_len = ciphertext_len - tag_len;

    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc_aead = noxtls_aes_gcm_decrypt(read_key, aes_type, nonce, aad, aad_len,
                                  ciphertext, inner_len, tag, out_plaintext);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_aes_ccm != 0U) {
#if NOXTLS_FEATURE_AES_CCM
        rc_aead = noxtls_aes_ccm_decrypt(read_key, aes_type, nonce, 12U, aad, aad_len,
                                  ciphertext, inner_len, tag, tag_len, out_plaintext);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc_aead = noxtls_chacha20_poly1305_decrypt(read_key, nonce, aad, aad_len,
                                            ciphertext, inner_len, tag, out_plaintext);
#else
        rc_aead = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    if(rc_aead != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: AEAD decrypt failed rc=%d epoch=%u seq=%llu\n",
                            rc_aead, epoch, (unsigned long long)full_seq);
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Inner plaintext: content || content_type || zero padding. */
    for(i = inner_len - 1U; (i != UINT32_MAX) && (out_plaintext[i] == 0U); i -= 1U) {
        /* skip padding */
    }
    if(i == UINT32_MAX) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: all-padding inner plaintext\n");
        return NOXTLS_RETURN_BAD_DATA;
    }
    *out_content_type = out_plaintext[i];
    *out_plaintext_len = i;
    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_dtls13_record: success inner_type=0x%02X inner_len=%u\n",
                        *out_content_type, *out_plaintext_len);
    dtls13_replay_update_window(&ctx->base.replay_windows[epoch & DTLS13_UNIFIED_EPOCH_MASK], full_seq);
    if((ctx->base.highest_recv_seq_valid[(epoch & DTLS13_UNIFIED_EPOCH_MASK)] == 0U) ||
       (full_seq > ctx->base.highest_recv_seq[(epoch & DTLS13_UNIFIED_EPOCH_MASK)])) {
        ctx->base.highest_recv_seq[(epoch & DTLS13_UNIFIED_EPOCH_MASK)] = full_seq;
        ctx->base.highest_recv_seq_valid[(epoch & DTLS13_UNIFIED_EPOCH_MASK)] = 1U;
    }
    ctx->base.read_seq_num = full_seq + 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt TLS 1.3 0-RTT (early data) record using early_write_key/iv/seq.
 * cipher_suite is the ticket's cipher (e.g. ctx->ticket_cipher_suite on client).
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_tls13_encrypt_record_early(tls13_context_t *ctx,
                                       uint16_t cipher_suite,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    const uint8_t *write_key = NULL;
    const uint8_t *write_iv = NULL;
    uint64_t seq_num = 0U;
    uint8_t nonce[12];
    uint8_t aad[5];
    uint8_t tag[16];
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16U;
    uint32_t record_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((ctx == NULL) || (plaintext == NULL) || (encrypted_record == NULL) || (encrypted_record_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    write_key = ctx->early_write_key;
    write_iv = ctx->early_write_iv;
    seq_num = ctx->early_seq_num;
    tls13_generate_nonce(nonce, write_iv, 12U, seq_num);

    if(tls13_get_record_cipher_params(cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    record_len = plaintext_len + tag_len;
    aad[0] = type;
    aad[1] = (uint8_t)(((uint32_t)ctx->base.base.version >> 8U) & 0xFFU);
    aad[2] = (uint8_t)(ctx->base.base.version & 0xFFU);
    aad[3] = (uint8_t)((((uint32_t)record_len) >> 8U) & 0xFFU);
    aad[4] = (uint8_t)(record_len & 0xFFU);

    if(*encrypted_record_len < record_len) {
        *encrypted_record_len = record_len;
        return NOXTLS_RETURN_FAILED;
    }

    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, aad, 5U,
                             plaintext, plaintext_len,
                             encrypted_record, tag);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_aes_ccm != 0U) {
#if NOXTLS_FEATURE_AES_CCM
        rc = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12U, aad, 5U,
                             plaintext, plaintext_len, encrypted_record, tag, tag_len);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc = noxtls_chacha20_poly1305_encrypt(write_key, nonce, aad, 5U,
                                       plaintext, plaintext_len,
                                       encrypted_record, tag);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_copy_u8(&encrypted_record[plaintext_len], (size_t)(*encrypted_record_len), tag, (size_t)(tag_len));
    *encrypted_record_len = record_len;
    ctx->early_seq_num += 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt TLS 1.3 0-RTT (early data) record using early_write_key/iv/seq (server read path).
 */
noxtls_return_t noxtls_tls13_decrypt_record_early(tls13_context_t *ctx,
                                       uint16_t cipher_suite,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len)
{
    const uint8_t *write_key = NULL;
    const uint8_t *write_iv = NULL;
    uint64_t seq_num = 0U;
    uint8_t nonce[12];
    uint8_t aad[5];
    uint8_t tag[16];
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16U;
    uint32_t ciphertext_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((ctx == NULL) || (encrypted_record == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(encrypted_record_len < 8U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    write_key = ctx->early_write_key;
    write_iv = ctx->early_write_iv;
    seq_num = ctx->early_seq_num;
    tls13_generate_nonce(nonce, write_iv, 12U, seq_num);
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1] = (uint8_t)(((uint32_t)ctx->base.base.version >> 8U) & 0xFFU);
    aad[2] = (uint8_t)(ctx->base.base.version & 0xFFU);
    aad[3] = (uint8_t)((((uint32_t)encrypted_record_len) >> 8U) & 0xFFU);
    aad[4] = (uint8_t)(encrypted_record_len & 0xFFU);

    if(tls13_get_record_cipher_params(cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(encrypted_record_len <= tag_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    ciphertext_len = encrypted_record_len - tag_len;
    noxtls_copy_u8(tag, sizeof(tag), &encrypted_record[ciphertext_len], (size_t)(tag_len));

    if(*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return NOXTLS_RETURN_FAILED;
    }
    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc = noxtls_aes_gcm_decrypt(write_key, aes_type, nonce, aad, 5U,
                             encrypted_record, ciphertext_len, tag, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_aes_ccm != 0U) {
         /* MISRA 15.7: final else path */
#if NOXTLS_FEATURE_AES_CCM
        rc = noxtls_aes_ccm_decrypt(write_key, aes_type, nonce, 12U, aad, 5U,
                             encrypted_record, ciphertext_len, tag, tag_len, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc = noxtls_chacha20_poly1305_decrypt(write_key, nonce, aad, 5U,
                                       encrypted_record, ciphertext_len, tag, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *plaintext_len = ciphertext_len;
    ctx->early_seq_num += 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt TLS 1.3 application data record (AEAD)
 */
noxtls_return_t noxtls_tls13_decrypt_record(tls13_context_t *ctx,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len)
{
    uint8_t *write_key = NULL;
    uint8_t *write_iv = NULL;
    uint32_t iv_len = 0U;
    uint64_t seq_num = 0U;
    uint8_t nonce[12];
    uint8_t aad[5];  /* Additional Authenticated Data: type || version || length */
    uint8_t tag[16];
    uint8_t use_aes_gcm = 0U;
    uint8_t use_aes_ccm = 0U;
    uint8_t use_chacha = 0U;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16U;
    uint32_t ciphertext_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if((ctx == NULL) || (encrypted_record == NULL) || (plaintext == NULL) || (plaintext_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(encrypted_record_len > TLS13_MAX_ENCRYPTED_RECORD_SIZE) {
        return NOXTLS_RETURN_RECORD_OVERFLOW;
    }
    if(encrypted_record_len < 8U) {
        return NOXTLS_RETURN_BAD_DATA;  /* Need at least tag */
    }
    
    /*
     * RFC 8446 5.2 / RFC 9147 4: records are only ever deprotected with the peer's write
     * (our read) traffic key and the read sequence number. A record that fails AEAD
     * deprotection is rejected (bad_record_mac); in particular there is no retry with this
     * endpoint's own write key, which would accept the endpoint's own records reflected
     * back to it.
     */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        write_key = ctx->server_write_key;  /* Receive from server */
        write_iv = ctx->server_write_iv;
        iv_len = 12U;
        seq_num = (tls13_is_dtls_context(ctx) != 0) ? ctx->base.read_seq_num : ctx->server_seq_num;
    } else {
        write_key = ctx->client_write_key;  /* Receive from client */
        write_iv = ctx->client_write_iv;
        iv_len = 12U;
        seq_num = (tls13_is_dtls_context(ctx) != 0) ? ctx->base.read_seq_num : ctx->client_seq_num;
    }
    
    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(encrypted_record_len <= tag_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Extract tag */
    ciphertext_len = encrypted_record_len - tag_len;
    if(ciphertext_len > (uint32_t)(TLS_MAX_RECORD_SIZE + 1U)) {
        return NOXTLS_RETURN_RECORD_OVERFLOW;
    }
    noxtls_copy_u8(tag, sizeof(tag), &encrypted_record[ciphertext_len], (size_t)(tag_len));
    if(ciphertext_len >= 4U) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_record: tag[0..3]=%02X%02X%02X%02X ct_len=%u\n",
                              tag[0], tag[1], tag[2], tag[3], ciphertext_len);
    }
    
    /* Generate nonce */
    tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
    
    /* Build AAD: type || version || length */
    /* For TLS 1.3, AAD uses the encrypted_content length (&ciphertext[tag]) */
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1] = (uint8_t)(((uint32_t)ctx->base.base.version >> 8U) & 0xFFU);
    aad[2] = (uint8_t)(ctx->base.base.version & 0xFFU);
    aad[3] = (uint8_t)((((uint32_t)encrypted_record_len) >> 8U) & 0xFFU);
    aad[4] = (uint8_t)(encrypted_record_len & 0xFFU);
    
    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_record: suite=0x%04X seq=%llu len=%u\n",
                          ctx->cipher_suite, (unsigned long long)seq_num, encrypted_record_len);
    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_record: key[0..3]=%02X%02X%02X%02X iv[0..3]=%02X%02X%02X%02X\n",
                          write_key[0], write_key[1], write_key[2], write_key[3],
                          write_iv[0], write_iv[1], write_iv[2], write_iv[3]);
    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_record: nonce[0..3]=%02X%02X%02X%02X aad[0..4]=%02X%02X%02X%02X%02X\n",
                          nonce[0], nonce[1], nonce[2], nonce[3],
                          aad[0], aad[1], aad[2], aad[3], aad[4]);
    /* Decrypt using AEAD */
    if(*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return NOXTLS_RETURN_FAILED;
    }

    if(use_aes_gcm != 0U) {
#if NOXTLS_FEATURE_AES_GCM
        rc = noxtls_aes_gcm_decrypt(write_key, aes_type, nonce, aad, 5U,
                             encrypted_record, ciphertext_len,
                             tag, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_aes_ccm != 0U) {
#if NOXTLS_FEATURE_AES_CCM
        rc = noxtls_aes_ccm_decrypt(write_key, aes_type, nonce, 12U, aad, 5U,
                             encrypted_record, ciphertext_len, tag, tag_len, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(use_chacha != 0U) {
#if NOXTLS_FEATURE_CHACHA20_POLY1305
        rc = noxtls_chacha20_poly1305_decrypt(write_key, nonce, aad, 5U,
                                       encrypted_record, ciphertext_len,
                                       tag, plaintext);
#else
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* AEAD tag verification failed: no sequence number is consumed (bad_record_mac). */
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] decrypt_record: AEAD open failed rc=%d\n", rc);
        noxtls_secure_zero(plaintext, (size_t)ciphertext_len);
        return NOXTLS_RETURN_BAD_DATA;
    }

    *plaintext_len = ciphertext_len;

    /* Update the read sequence number (DTLS tracks the per-record sequence number in the record layer). */
    if(tls13_is_dtls_context(ctx) == 0) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->server_seq_num += 1U;
        } else {
            ctx->client_seq_num += 1U;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}
