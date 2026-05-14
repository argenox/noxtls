/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls_record.c
* Summary: TLS Record Layer Encryption/Decryption Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "noxtls_tls_kdf.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_internal.h"

static int tls12_is_dtls_context(const tls12_context_t *ctx);
static int tls13_is_dtls_context(const tls13_context_t *ctx);
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

/**
 * @brief Generate TLS 1.2 record IV from sequence number and write IV
 */
static void tls12_generate_iv(uint8_t *iv, const uint8_t *write_iv, uint32_t iv_len, uint64_t seq_num)
{
    /* Copy write IV */
    memcpy(iv, write_iv, iv_len);
    
    /* XOR sequence number into last 8 bytes of IV */
    if(iv_len >= 8) {
        for(uint32_t i = 0; i < 8; i++) {
            iv[iv_len - 8 + i] ^= (uint8_t)((seq_num >> (56 - (i << 3))) & 0xFF);
        }
    }
}

/**
 * @brief Compute TLS 1.2 MAC
 * MAC = HMAC_hash(MAC_write_secret, seq_num || type || version || length || fragment)
 */
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
{
    hmac_context_t hmac_ctx;
    noxtls_return_t rc;
    uint8_t seq_bytes[8];
    uint8_t version_bytes[2];
    uint8_t length_bytes[2];
    uint32_t i;
    
    /* Convert sequence number to bytes (big-endian) */
    for(i = 0; i < 8; i++) {
        seq_bytes[i] = (uint8_t)((seq_num >> (56 - (i << 3))) & 0xFF);
    }
    
    /* Convert version to bytes (big-endian) */
    version_bytes[0] = (version >> 8) & 0xFF;
    version_bytes[1] = version & 0xFF;
    
    /* Convert length to bytes (big-endian) */
    length_bytes[0] = (length >> 8) & 0xFF;
    length_bytes[1] = length & 0xFF;
    
    /* Initialize HMAC */
    rc = noxtls_hmac_init(&hmac_ctx, hash_algo, mac_key, mac_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Update with sequence number */
    rc = noxtls_hmac_update(&hmac_ctx, seq_bytes, 8);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with type */
    rc = noxtls_hmac_update(&hmac_ctx, &type, 1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with version */
    rc = noxtls_hmac_update(&hmac_ctx, version_bytes, 2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with length */
    rc = noxtls_hmac_update(&hmac_ctx, length_bytes, 2);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_hmac_free(&hmac_ctx);
        return rc;
    }
    
    /* Update with fragment */
    if(fragment != NULL && fragment_len > 0) {
        rc = noxtls_hmac_update(&hmac_ctx, fragment, fragment_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_hmac_free(&hmac_ctx);
            return rc;
        }
    }
    
    /* Finalize MAC */
    rc = noxtls_hmac_final(&hmac_ctx, mac, mac_len);
    noxtls_hmac_free(&hmac_ctx);
    
    return rc;
}

/**
 * @brief Encrypt TLS 1.2 application data record (AES-CBC with HMAC)
 */
noxtls_return_t noxtls_tls12_encrypt_record(tls12_context_t *ctx, 
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
{
    const uint8_t *mac_key;
    uint32_t mac_key_len;
    uint8_t *enc_key;
    uint32_t enc_key_len;
    const uint8_t *write_iv;
    uint32_t iv_len;
    uint64_t seq_num;
    noxtls_hash_algos_t hash_algo;
    noxtls_aes_type_t aes_type;
    uint8_t iv[16];
    uint8_t iv_enc[16];
    uint8_t mac[64];  /* Max MAC size (SHA-512) */
    uint32_t mac_len;
    uint8_t *padded_plaintext = NULL;
    uint32_t padded_len;
    uint8_t *encrypted_data = NULL;
    uint32_t encrypted_data_len;
    uint32_t record_len;
    uint32_t offset = 0;
    noxtls_return_t rc;
    
    if(ctx == NULL || plaintext == NULL || encrypted_record == NULL || encrypted_record_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        mac_key = ctx->client_write_mac_key;
        enc_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 16;
        seq_num = tls12_is_dtls_context(ctx) ? ctx->base.write_seq_num : ctx->client_seq_num;
    } else {
        mac_key = ctx->server_write_mac_key;
        enc_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 16;
        seq_num = tls12_is_dtls_context(ctx) ? ctx->base.write_seq_num : ctx->server_seq_num;
    }

    /* Determine hash algorithm, MAC length, and cipher type from cipher suite */
    hash_algo = NOXTLS_HASH_SHA_256;
    mac_key_len = 32;
    enc_key_len = 32;
    aes_type = NOXTLS_AES_256_BIT;
    int is_aria = 0;
    int is_gcm = 0;
    int is_3des = 0;
    noxtls_aria_type_t aria_type = NOXTLS_ARIA_256_BIT;

    switch(ctx->cipher_suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 24;
            iv_len = 8;
            is_3des = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            is_aria = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4;
            is_aria = 0;
            is_gcm = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
            hash_algo = (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ?
                        NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_256;
            mac_key_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : 32;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            is_aria = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 0;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4;
            is_aria = 0;
            is_gcm = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
            is_aria = 1;
            aria_type = NOXTLS_ARIA_128_BIT;
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;
            enc_key_len = 16;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            is_aria = 1;
            aria_type = NOXTLS_ARIA_256_BIT;
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 48;
            enc_key_len = 32;
            break;
        default:
            /* Defaults already set (AES-256/SHA-256) */
            break;
    }
    
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1;
    uint32_t iv_is_zero = 1;
    uint32_t k;
    for(k = 0; k < enc_key_len; k++) {
        if(enc_key[k] != 0) {
            key_is_zero = 0;
            break;
        }
    }
    for(k = 0; k < iv_len; k++) {
        if(write_iv[k] != 0) {
            iv_is_zero = 0;
            break;
        }
    }
    
    if(key_is_zero || iv_is_zero) {
        /* Keys not initialized - key derivation must happen during handshake */
        return NOXTLS_RETURN_FAILED;
    }
    
    if(is_gcm) {
        uint8_t fixed_iv[4];
        uint8_t explicit_nonce[8];
        uint8_t nonce[12];
        uint8_t tag[16];
        uint8_t aad[13];
        uint32_t aad_len = 13;
        for(uint32_t i = 0; i < 8; i++) {
            explicit_nonce[i] = (uint8_t)((seq_num >> (56 - (i << 3))) & 0xFF);
        }
        memcpy(fixed_iv, write_iv, 4);
        memcpy(nonce, fixed_iv, 4);
        memcpy(nonce + 4, explicit_nonce, 8);
        aad[0] = (uint8_t)(seq_num >> 56);
        aad[1] = (uint8_t)(seq_num >> 48);
        aad[2] = (uint8_t)(seq_num >> 40);
        aad[3] = (uint8_t)(seq_num >> 32);
        aad[4] = (uint8_t)(seq_num >> 24);
        aad[5] = (uint8_t)(seq_num >> 16);
        aad[6] = (uint8_t)(seq_num >> 8);
        aad[7] = (uint8_t)(seq_num);
        aad[8] = type;
        aad[9] = (uint8_t)(ctx->base.base.version >> 8);
        aad[10] = (uint8_t)(ctx->base.base.version);
        aad[11] = (uint8_t)(plaintext_len >> 8);
        aad[12] = (uint8_t)(plaintext_len);

        encrypted_data = (uint8_t*)noxtls_malloc(plaintext_len);
        if(encrypted_data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_aes_gcm_encrypt(enc_key, aes_type, nonce, aad, aad_len,
                           plaintext, plaintext_len, encrypted_data, tag) != 0) {
            noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
        encrypted_data_len = plaintext_len;

        record_len = 8 + encrypted_data_len + 16;
        if(*encrypted_record_len < record_len) {
            noxtls_free(encrypted_data);
            *encrypted_record_len = record_len;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(encrypted_record + offset, explicit_nonce, 8);
        offset += 8;
        memcpy(encrypted_record + offset, encrypted_data, encrypted_data_len);
        offset += encrypted_data_len;
        memcpy(encrypted_record + offset, tag, 16);
        offset += 16;
        (void)offset;
        *encrypted_record_len = record_len;

        noxtls_free(encrypted_data);

        if(!tls12_is_dtls_context(ctx)) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                ctx->client_seq_num++;
            } else {
                ctx->server_seq_num++;
            }
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Compute MAC */
    mac_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : (hash_algo == NOXTLS_HASH_SHA1) ? 20 : 32;
    rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num, type,
                          ctx->base.base.version, (uint16_t)plaintext_len,
                          plaintext, plaintext_len, mac, &mac_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Pad plaintext + MAC for CBC encryption */
    /* Padding: add 1 to 256 bytes, all with value = padding_length */
    uint32_t block_size = is_3des ? NOXTLS_DES_BLOCK_LENGTH : (is_aria ? NOXTLS_ARIA_BLOCK_LENGTH : NOXTLS_AES_BLOCK_LENGTH);
    uint8_t padding_len = (uint8_t)(block_size - ((plaintext_len + mac_len) % block_size) - 1);
    
    padded_len = plaintext_len + mac_len + padding_len + 1;
    padded_plaintext = (uint8_t*)noxtls_malloc(padded_len);
    if(padded_plaintext == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Copy plaintext */
    memcpy(padded_plaintext, plaintext, plaintext_len);
    
    /* Append MAC */
    memcpy(padded_plaintext + plaintext_len, mac, mac_len);
    
    /* Append padding (pad length byte is the padding length) */
    memset(padded_plaintext + plaintext_len + mac_len, padding_len, (uint32_t)padding_len + 1);
    if((padded_len % block_size) != 0) {
        noxtls_free(padded_plaintext);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Generate IV: TLS 1.0 = implicit (last block or write_iv); TLS 1.1 = random; TLS 1.2 = generated from write_iv + seq */
    {
        uint16_t ver = ctx->base.base.version;
        if(ver == TLS_VERSION_1_0) {
            uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_last_cipher_block : ctx->server_last_cipher_block;
            if(seq_num == 0) {
                memcpy(iv_enc, write_iv, iv_len);
            } else {
                memcpy(iv_enc, last_block, iv_len);
            }
        } else if(ver == TLS_VERSION_1_1) {
            drbg_state_t drbg;
            if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                noxtls_free(padded_plaintext);
                return NOXTLS_RETURN_FAILED;
            }
            if(drbg_generate(&drbg, iv_enc, iv_len * 8, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                noxtls_free(padded_plaintext);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            tls12_generate_iv(iv, write_iv, iv_len, seq_num);
            memcpy(iv_enc, iv, iv_len);
        }
    }
    
    /* Encrypt */
    encrypted_data = (uint8_t*)noxtls_malloc(padded_len);
    if(encrypted_data == NULL) {
        noxtls_free(padded_plaintext);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Encrypt using 3DES-CBC, AES-CBC, or ARIA-CBC */
    if(is_3des) {
        if(des3_encrypt_cbc(enc_key, 24, padded_plaintext, padded_len, iv_enc, encrypted_data) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(padded_plaintext);
            noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
    } else if(is_aria) {
        if(noxtls_aria_encrypt_cbc(enc_key, padded_plaintext, padded_len, iv_enc, encrypted_data, aria_type) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(padded_plaintext);
            noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        if(noxtls_aes_encrypt_cbc(enc_key, padded_plaintext, padded_len, iv_enc, encrypted_data, aes_type) != 0) {
            noxtls_free(padded_plaintext);
            noxtls_free(encrypted_data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    encrypted_data_len = padded_len;
    
    /* TLS 1.0: record = ciphertext only (implicit IV). TLS 1.1/1.2: record = IV || ciphertext */
    if(ctx->base.base.version == TLS_VERSION_1_0) {
        record_len = encrypted_data_len;
        if(*encrypted_record_len < record_len) {
            noxtls_free(padded_plaintext);
            noxtls_free(encrypted_data);
            *encrypted_record_len = record_len;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(encrypted_record + offset, encrypted_data, encrypted_data_len);
        /* Save last cipher block for next record */
        {
            uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->client_last_cipher_block : ctx->server_last_cipher_block;
            memcpy(last_block, encrypted_data + encrypted_data_len - iv_len, iv_len);
        }
    } else {
        record_len = iv_len + encrypted_data_len;
        if(*encrypted_record_len < record_len) {
            noxtls_free(padded_plaintext);
            noxtls_free(encrypted_data);
            *encrypted_record_len = record_len;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(encrypted_record + offset, iv_enc, iv_len);
        offset += iv_len;
        memcpy(encrypted_record + offset, encrypted_data, encrypted_data_len);
    }
    (void)offset;
    
    *encrypted_record_len = record_len;
    
    if(!tls12_is_dtls_context(ctx)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->client_seq_num++;
        } else {
            ctx->server_seq_num++;
        }
    }
    
    noxtls_free(padded_plaintext);
    noxtls_free(encrypted_data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt TLS 1.2 application data record (AES-CBC with HMAC)
 */
noxtls_return_t noxtls_tls12_decrypt_record(tls12_context_t *ctx,
                                       uint8_t type,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len)
{
    const uint8_t *mac_key;
    uint32_t mac_key_len;
    uint8_t *enc_key;
    uint32_t enc_key_len;
    const uint8_t *write_iv;
    uint32_t iv_len;
    uint64_t seq_num;
    noxtls_hash_algos_t hash_algo;
    noxtls_aes_type_t aes_type;
    uint8_t iv[16];
    uint8_t *decrypted_data = NULL;
    uint32_t decrypted_data_len;
    uint8_t mac[64];  /* Max MAC size (SHA-512) */
    uint32_t mac_len;
    uint8_t padding_len;
    uint32_t plaintext_data_len;
    uint32_t offset = 0;
    noxtls_return_t rc;
    uint32_t block_size;
    int is_gcm = 0;
    int is_3des = 0;
    
    if(ctx == NULL || encrypted_record == NULL || plaintext == NULL || plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        mac_key = ctx->server_write_mac_key;  /* Receive from server */
        enc_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 16;
        seq_num = tls12_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->server_seq_num;
    } else {
        mac_key = ctx->client_write_mac_key;  /* Receive from client */
        enc_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 16;
        seq_num = tls12_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->client_seq_num;
    }

    /* Determine hash algorithm, MAC length, and cipher type from cipher suite */
    hash_algo = NOXTLS_HASH_SHA_256;
    mac_key_len = 32;
    enc_key_len = 32;
    aes_type = NOXTLS_AES_256_BIT;
    int is_aria = 0;
    noxtls_aria_type_t aria_type = NOXTLS_ARIA_256_BIT;

    switch(ctx->cipher_suite) {
        case TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 24;
            iv_len = 8;
            is_3des = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            is_3des = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            is_aria = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 0;
            enc_key_len = 16;
            aes_type = NOXTLS_AES_128_BIT;
            iv_len = 4;
            is_aria = 0;
            is_gcm = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA:
            hash_algo = NOXTLS_HASH_SHA1;
            mac_key_len = 20;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            is_3des = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256:
            hash_algo = (ctx->cipher_suite == TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ?
                        NOXTLS_HASH_SHA_384 : NOXTLS_HASH_SHA_256;
            mac_key_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : 32;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            is_aria = 0;
            break;
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 0;
            enc_key_len = 32;
            aes_type = NOXTLS_AES_256_BIT;
            iv_len = 4;
            is_aria = 0;
            is_gcm = 1;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
            is_aria = 1;
            aria_type = NOXTLS_ARIA_128_BIT;
            hash_algo = NOXTLS_HASH_SHA_256;
            mac_key_len = 32;
            enc_key_len = 16;
            break;
        case TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
            is_aria = 1;
            aria_type = NOXTLS_ARIA_256_BIT;
            hash_algo = NOXTLS_HASH_SHA_384;
            mac_key_len = 48;
            enc_key_len = 32;
            break;
        default:
            /* Defaults already set (AES-256/SHA-256) */
            break;
    }
    
    /* Check if keys are initialized (not all zeros) */
    uint32_t key_is_zero = 1;
    uint32_t iv_is_zero = 1;
    uint32_t k;
    for(k = 0; k < enc_key_len; k++) {
        if(enc_key[k] != 0) {
            key_is_zero = 0;
            break;
        }
    }
    for(k = 0; k < iv_len; k++) {
        if(write_iv[k] != 0) {
            iv_is_zero = 0;
            break;
        }
    }
    
    if(key_is_zero || iv_is_zero) {
        return NOXTLS_RETURN_FAILED;
    }

    if(is_gcm) {
        uint8_t fixed_iv[4];
        uint8_t explicit_nonce[8];
        uint8_t nonce[12];
        uint8_t aad[13];
        uint8_t tag[16];
        uint32_t aad_len = 13;
        if(encrypted_record_len < 8 + 16) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        memcpy(explicit_nonce, encrypted_record, 8);
        memcpy(fixed_iv, write_iv, 4);
        memcpy(nonce, fixed_iv, 4);
        memcpy(nonce + 4, explicit_nonce, 8);

        uint32_t ciphertext_len = encrypted_record_len - 8 - 16;
        const uint8_t *ciphertext = encrypted_record + 8;
        const uint8_t *tag_in = encrypted_record + 8 + ciphertext_len;

        aad[0] = (uint8_t)(seq_num >> 56);
        aad[1] = (uint8_t)(seq_num >> 48);
        aad[2] = (uint8_t)(seq_num >> 40);
        aad[3] = (uint8_t)(seq_num >> 32);
        aad[4] = (uint8_t)(seq_num >> 24);
        aad[5] = (uint8_t)(seq_num >> 16);
        aad[6] = (uint8_t)(seq_num >> 8);
        aad[7] = (uint8_t)(seq_num);
        aad[8] = type;
        aad[9] = (uint8_t)(ctx->base.base.version >> 8);
        aad[10] = (uint8_t)(ctx->base.base.version);
        aad[11] = (uint8_t)(ciphertext_len >> 8);
        aad[12] = (uint8_t)(ciphertext_len);

        memcpy(tag, tag_in, 16);
        if(*plaintext_len < ciphertext_len) {
            *plaintext_len = ciphertext_len;
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_aes_gcm_decrypt(enc_key, aes_type, nonce, aad, aad_len,
                           ciphertext, ciphertext_len, tag, plaintext) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        *plaintext_len = ciphertext_len;

        if(!tls12_is_dtls_context(ctx)) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                ctx->server_seq_num++;
            } else {
                ctx->client_seq_num++;
            }
        }
        return NOXTLS_RETURN_SUCCESS;
    }

    
    block_size = is_3des ? NOXTLS_DES_BLOCK_LENGTH : (is_aria ? NOXTLS_ARIA_BLOCK_LENGTH : NOXTLS_AES_BLOCK_LENGTH);
    
    /* TLS 1.0: no leading IV (implicit); TLS 1.1/1.2: IV at start of record */
    uint32_t encrypted_data_len;
    if(ctx->base.base.version == TLS_VERSION_1_0) {
        uint64_t read_seq = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_seq_num : ctx->client_seq_num;
        const uint8_t *last_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_last_cipher_block : ctx->client_last_cipher_block;
        if(read_seq == 0) {
            memcpy(iv, write_iv, iv_len);
        } else {
            memcpy(iv, last_block, iv_len);
        }
        encrypted_data_len = encrypted_record_len;
        offset = 0;
    } else {
        if(encrypted_record_len < iv_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        memcpy(iv, encrypted_record, iv_len);
        offset += iv_len;
        encrypted_data_len = encrypted_record_len - iv_len;
    }
    
    /* Encrypted payload length check */
    if(encrypted_data_len < block_size || encrypted_data_len % block_size != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate buffer for decrypted data */
    decrypted_data = (uint8_t*)noxtls_malloc(encrypted_data_len);
    if(decrypted_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Decrypt using AES-CBC or ARIA-CBC */
    if(is_3des) {
        if(des3_decrypt_cbc(enc_key, 24, (uint8_t*)(encrypted_record + offset), encrypted_data_len, iv, decrypted_data) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
    } else if(is_aria) {
        if(noxtls_aria_decrypt_cbc(enc_key, (uint8_t*)(encrypted_record + offset), encrypted_data_len, iv, decrypted_data, aria_type) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
    } else {
        if(noxtls_aes_decrypt_cbc(enc_key, (uint8_t*)(encrypted_record + offset), encrypted_data_len, iv, decrypted_data, aes_type) != 0) {
            noxtls_free(decrypted_data);
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    
    decrypted_data_len = encrypted_data_len;
    
    /* TLS 1.0: save last cipher block for next record's IV */
    if(ctx->base.base.version == TLS_VERSION_1_0 && encrypted_data_len >= iv_len) {
        uint8_t *save_block = (ctx->base.base.role == TLS_ROLE_CLIENT) ? ctx->server_last_cipher_block : ctx->client_last_cipher_block;
        const uint8_t *ct = (offset > 0) ? (encrypted_record + offset) : encrypted_record;
        memcpy(save_block, ct + encrypted_data_len - iv_len, iv_len);
    }
    
    /* Validate and remove padding with a unified bad-record path. */
    uint32_t bad_record;
    uint32_t pad_bytes;
    uint32_t pad_scan_len;
    uint32_t body_len;
    uint32_t i;
    uint8_t computed_mac[64];
    uint32_t computed_mac_len;

    bad_record = 0u;
    pad_bytes = 1u;
    pad_scan_len = 0u;
    body_len = 0u;
    computed_mac_len = 0u;
    memset(computed_mac, 0, sizeof(computed_mac));

    if(decrypted_data_len == 0u) {
        bad_record = 1u;
        padding_len = 0u;
    } else {
        padding_len = decrypted_data[decrypted_data_len - 1u];
        pad_bytes = (uint32_t)padding_len + 1u;
    }

    if(padding_len >= block_size) {
        bad_record = 1u;
    }
    if(pad_bytes > decrypted_data_len) {
        bad_record = 1u;
        pad_bytes = 1u; /* keep bounds-safe for scan and length math */
    }

    pad_scan_len = block_size;
    if(pad_scan_len > decrypted_data_len) {
        pad_scan_len = decrypted_data_len;
    }

    /* Always scan one full block window (or all bytes when shorter). */
    for(i = 0u; i < pad_scan_len; i++) {
        uint8_t tail;
        uint8_t mask;
        uint8_t diff;

        tail = decrypted_data[decrypted_data_len - 1u - i];
        mask = (uint8_t)((i < pad_bytes) ? 0xFFu : 0x00u);
        diff = (uint8_t)((tail ^ padding_len) & mask);
        if(diff != 0u) {
            bad_record = 1u;
        }
    }

    body_len = decrypted_data_len - pad_bytes;
    
    /* Determine MAC length based on hash algorithm */
    switch(hash_algo) {
        case NOXTLS_HASH_MD4:
            mac_len = 16;
            break;
        case NOXTLS_HASH_MD5:
            mac_len = 16;
            break;
        case NOXTLS_HASH_SHA1:
            mac_len = 20;
            break;
        case NOXTLS_HASH_SHA_224:
            mac_len = 28;
            break;
        case NOXTLS_HASH_SHA_256:
            mac_len = 32;
            break;
        case NOXTLS_HASH_SHA_384:
            mac_len = 48;
            break;
        case NOXTLS_HASH_SHA_512:
            mac_len = 64;
            break;
        case NOXTLS_HASH_SHA_512_224:
            mac_len = 28;
            break;
        case NOXTLS_HASH_SHA_512_256:
            mac_len = 32;
            break;
        case NOXTLS_HASH_SHA3_224:
            mac_len = 28;
            break;
        case NOXTLS_HASH_SHA3_256:
            mac_len = 32;
            break;
        case NOXTLS_HASH_SHA3_384:
            mac_len = 48;
            break;
        case NOXTLS_HASH_SHA3_512:
            mac_len = 64;
            break;
        default:
            noxtls_free(decrypted_data);
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if(body_len < mac_len) {
        bad_record = 1u;
        plaintext_data_len = 0u;
    } else {
        plaintext_data_len = body_len - mac_len;
    }

    memset(mac, 0, sizeof(mac));
    if(body_len >= mac_len) {
        memcpy(mac, decrypted_data + plaintext_data_len, mac_len);
    }

    computed_mac_len = mac_len;
    rc = tls12_compute_mac(mac_key, mac_key_len, hash_algo, seq_num,
                          type,
                          ctx->base.base.version, (uint16_t)plaintext_data_len,
                          decrypted_data, plaintext_data_len,
                          computed_mac, &computed_mac_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        bad_record = 1u;
    }

    if(computed_mac_len != mac_len || noxtls_secret_memcmp(mac, computed_mac, mac_len) != 0) {
        bad_record = 1u;
    }
    if(bad_record != 0u) {
        noxtls_free(decrypted_data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Copy plaintext to output */
    if(*plaintext_len < plaintext_data_len) {
        noxtls_free(decrypted_data);
        *plaintext_len = plaintext_data_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    memcpy(plaintext, decrypted_data, plaintext_data_len);
    *plaintext_len = plaintext_data_len;
    
    noxtls_free(decrypted_data);
    
    /* Update sequence number */
    if(!tls12_is_dtls_context(ctx)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->server_seq_num++;
        } else {
            ctx->client_seq_num++;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate TLS 1.3 nonce from sequence number
 * nonce = client_write_iv XOR (0...0 || seq_num)
 */
static void tls13_generate_nonce(uint8_t *nonce, const uint8_t *write_iv, uint32_t iv_len, uint64_t seq_num)
{
    /* Copy write IV */
    memcpy(nonce, write_iv, iv_len);
    
    /* XOR sequence number into last 8 bytes */
    if(iv_len >= 8) {
        for(uint32_t i = 0; i < 8; i++) {
            nonce[iv_len - 8 + i] ^= (uint8_t)((seq_num >> (56 - (i << 3))) & 0xFF);
        }
    }
}

static int tls12_is_dtls_context(const tls12_context_t *ctx)
{
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_2);
}

static int tls13_is_dtls_context(const tls13_context_t *ctx)
{
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_3);
}

static noxtls_return_t tls13_get_record_cipher_params(uint16_t cipher_suite,
                                                int *use_aes_gcm,
                                                int *use_aes_ccm,
                                                int *use_chacha,
                                                noxtls_aes_type_t *aes_type,
                                                uint32_t *tag_len)
{
    if(use_aes_gcm == NULL || use_aes_ccm == NULL || use_chacha == NULL ||
       aes_type == NULL || tag_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    *use_aes_gcm = 0;
    *use_aes_ccm = 0;
    *use_chacha = 0;
    *aes_type = NOXTLS_AES_128_BIT;
    *tag_len = 16;

    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
            *use_aes_gcm = 1;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            *use_aes_gcm = 1;
            *aes_type = NOXTLS_AES_256_BIT;
            *tag_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
            *use_aes_ccm = 1;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
            *use_aes_ccm = 1;
            *aes_type = NOXTLS_AES_128_BIT;
            *tag_len = 8;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            *use_chacha = 1;
            *tag_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Encrypt TLS 1.3 application data record (AEAD)
 */
noxtls_return_t noxtls_tls13_encrypt_record(tls13_context_t *ctx,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
{
    const uint8_t *write_key;
    const uint8_t *write_iv;
    uint32_t iv_len;
    uint64_t seq_num;
    uint8_t nonce[12];
    uint8_t aad[5];  /* Additional Authenticated Data: type || version || length */
    uint8_t tag[16];
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16;
    uint32_t record_len;
    noxtls_return_t rc;
    
    if(ctx == NULL || plaintext == NULL || encrypted_record == NULL || encrypted_record_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Determine keys based on role */
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        write_key = ctx->client_write_key;
        write_iv = ctx->client_write_iv;
        iv_len = 12;
        seq_num = tls13_is_dtls_context(ctx) ? ctx->base.write_seq_num : ctx->client_seq_num;
    } else {
        write_key = ctx->server_write_key;
        write_iv = ctx->server_write_iv;
        iv_len = 12;
        seq_num = tls13_is_dtls_context(ctx) ? ctx->base.write_seq_num : ctx->server_seq_num;
    }
    
    /* Generate nonce */
    tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
    
    rc = tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Record format: encrypted_data || tag */
    record_len = plaintext_len + tag_len;  /* plaintext + tag */
    
    /* Build AAD: type || version || length */
    /* AAD length field is the encrypted_content length (ciphertext + tag) */
    aad[0] = type;
    aad[1] = (ctx->base.base.version >> 8) & 0xFF;
    aad[2] = ctx->base.base.version & 0xFF;
    aad[3] = (record_len >> 8) & 0xFF;
    aad[4] = record_len & 0xFF;
    
    if(*encrypted_record_len < record_len) {
        *encrypted_record_len = record_len;
        return NOXTLS_RETURN_FAILED;
    }
    
    if(use_aes_gcm) {
        rc = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, aad, 5,
                             plaintext, plaintext_len,
                             encrypted_record, tag);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_aes_ccm) {
        rc = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12, aad, 5,
                             plaintext, plaintext_len, encrypted_record, tag, tag_len);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_chacha) {
        rc = noxtls_chacha20_poly1305_encrypt(write_key, nonce, aad, 5,
                                       plaintext, plaintext_len,
                                       encrypted_record, tag);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    /* Append tag to ciphertext */
    memcpy(encrypted_record + plaintext_len, tag, tag_len);
    
    *encrypted_record_len = record_len;
    
    /* Update sequence number */
    if(!tls13_is_dtls_context(ctx)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            ctx->client_seq_num++;
        } else {
            ctx->server_seq_num++;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 9147: Send one DTLS 1.3 encrypted record (DTLSCiphertext with unified header + record number encryption).
 * inner_plaintext is the DTLSInnerPlaintext (content || content_type || padding).
 */
#define DTLS13_MAX_HEADER_LEN  (4 + 32)  /* 4-byte base + max CID 32 */

noxtls_return_t noxtls_tls13_send_dtls13_encrypted_record(tls13_context_t *ctx,
                                       int use_handshake_keys,
                                       uint8_t content_type,
                                       const uint8_t *inner_plaintext,
                                       uint32_t inner_len,
                                       int omit_length)
{
    (void)content_type;
    uint8_t header[DTLS13_MAX_HEADER_LEN];
    uint32_t header_len;
    uint8_t *ciphertext = NULL;
    uint32_t record_len;
    uint64_t seq_num;
    uint16_t epoch;
    const uint8_t *write_key;
    const uint8_t *write_iv;
    const uint8_t *sn_key;
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t mask[DTLS13_RECORD_NUMBER_ENC_LEN];
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16;
    int rc_aead;
    int32_t sent;
    noxtls_chacha20_context_t chacha_ctx;

    if(ctx == NULL || inner_plaintext == NULL || !tls13_is_dtls_context(ctx)) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    record_len = inner_len + tag_len;  /* ciphertext + tag */
    if(record_len < DTLS13_RECORD_NUMBER_ENC_LEN) {
        return NOXTLS_RETURN_FAILED;  /* RFC 9147: ciphertext must be at least 16 bytes for record number encryption */
    }

    epoch = ctx->base.epoch;
    seq_num = ctx->base.write_seq_num;

    if(use_handshake_keys) {
        write_key = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_write_key : ctx->server_write_key;
        write_iv  = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_write_iv  : ctx->server_write_iv;
        sn_key    = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_handshake_sn_key : ctx->server_handshake_sn_key;
    } else {
        write_key = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_write_key : ctx->server_write_key;
        write_iv  = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_write_iv  : ctx->server_write_iv;
        sn_key    = ctx->base.base.role == TLS_ROLE_CLIENT ? ctx->client_sn_key : ctx->server_sn_key;
    }

    /* Unified header: 001 [L=1] [C] EE, 8-bit seq, [16-bit length if L], [Connection ID if C set] (RFC 9147 Figure 3) */
    if(omit_length) {
        header_len = 2;
        header[0] = (uint8_t)(DTLS13_UNIFIED_FIXED_BITS | (epoch & DTLS13_UNIFIED_EPOCH_MASK));  /* L=0 */
        header[1] = (uint8_t)(seq_num & 0xFF);
        if(ctx->peer_connection_id_len > 0) {
            header[0] |= DTLS13_UNIFIED_CID_BIT;
            memcpy(header + 2, ctx->peer_connection_id, ctx->peer_connection_id_len);
            header_len += ctx->peer_connection_id_len;
        }
    } else {
        header_len = DTLS13_UNIFIED_HEADER_WITH_LEN;
        header[0] = (uint8_t)(DTLS13_UNIFIED_FIXED_BITS | DTLS13_UNIFIED_L_BIT | (epoch & DTLS13_UNIFIED_EPOCH_MASK));
        header[1] = (uint8_t)(seq_num & 0xFF);
        header[2] = (uint8_t)((record_len >> 8) & 0xFF);
        header[3] = (uint8_t)(record_len & 0xFF);
        if(ctx->peer_connection_id_len > 0) {
            header[0] |= DTLS13_UNIFIED_CID_BIT;
            memcpy(header + DTLS13_UNIFIED_HEADER_WITH_LEN, ctx->peer_connection_id, ctx->peer_connection_id_len);
            header_len += ctx->peer_connection_id_len;
        }
    }

    ciphertext = (uint8_t*)noxtls_malloc(record_len);
    if(ciphertext == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    tls13_generate_nonce(nonce, write_iv, 12, seq_num);

    if(use_aes_gcm) {
        rc_aead = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, header, header_len,
                                  inner_plaintext, inner_len, ciphertext, tag);
    } else if(use_aes_ccm) {
        rc_aead = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12, header, header_len,
                                  inner_plaintext, inner_len, ciphertext, tag, tag_len);
    } else if(use_chacha) {
        rc_aead = noxtls_chacha20_poly1305_encrypt(write_key, nonce, header, header_len,
                                            inner_plaintext, inner_len, ciphertext, tag);
    } else {
        noxtls_free(ciphertext);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rc_aead != 0) {
        noxtls_free(ciphertext);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ciphertext + inner_len, tag, tag_len);

    /* Record number encryption (RFC 9147 §4.2.3): Mask = f(ciphertext[0..15]), encrypted_seq = seq XOR mask[0] */
    if(use_aes_gcm || use_aes_ccm) {
        if(noxtls_aes_encrypt_data(sn_key, ciphertext, DTLS13_RECORD_NUMBER_ENC_LEN, NULL, mask, aes_type, NOXTLS_AES_ECB) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        static const uint8_t zeros_16[16] = { 0 };
        uint64_t counter = (uint64_t)(ciphertext[0] | (ciphertext[1] << 8) | (ciphertext[2] << 16) | (ciphertext[3] << 24));
        if(noxtls_chacha20_init(&chacha_ctx, sn_key, ciphertext + 4, counter) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_chacha20_process(&chacha_ctx, zeros_16, mask, DTLS13_RECORD_NUMBER_ENC_LEN) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(ciphertext);
            return NOXTLS_RETURN_FAILED;
        }
    }
    header[1] = (uint8_t)((seq_num & 0xFF) ^ mask[0]);

    {
        uint32_t total = header_len + record_len;
        uint8_t *out = (uint8_t*)noxtls_malloc(total);
        if(out == NULL) {
            noxtls_free(ciphertext);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memcpy(out, header, header_len);
        memcpy(out + header_len, ciphertext, record_len);
        noxtls_free(ciphertext);
        sent = ctx->base.base.send_callback(ctx->base.base.user_data, out, total);
        noxtls_free(out);
        if(sent != (int32_t)total) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    ctx->base.write_seq_num++;
    ctx->base.bytes_sent += (uint64_t)(header_len + record_len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 9147: Return byte length of the first DTLSCiphertext record in raw (for multiple records per datagram).
 * own_connection_id_len is from ctx->own_connection_id_len. Returns 0 if invalid or incomplete.
 */
uint32_t noxtls_tls13_dtls13_record_size(const uint8_t *raw, uint32_t raw_len, uint8_t own_connection_id_len)
{
    uint32_t cid_len;
    uint32_t aad_len;
    uint32_t ciphertext_len;
    if(raw == NULL || raw_len < 2) {
        return 0;
    }
    if((raw[0] & 0xE0) != DTLS13_UNIFIED_FIXED_BITS) {
        return 0;
    }
    cid_len = (raw[0] & DTLS13_UNIFIED_CID_BIT) ? (uint32_t)own_connection_id_len : 0;
    if(raw[0] & DTLS13_UNIFIED_L_BIT) {
        aad_len = 4 + cid_len;
        if(raw_len < aad_len + 16) {
            return 0;
        }
        ciphertext_len = (uint32_t)((raw[2] << 8) | raw[3]);
        if(ciphertext_len < 16) {
            return 0;
        }
        return aad_len + ciphertext_len;
    }
    aad_len = 2 + cid_len;
    if(raw_len < aad_len + 16) {
        return 0;
    }
    ciphertext_len = raw_len - aad_len;
    return aad_len + ciphertext_len;
}

/**
 * @brief RFC 9147: Decrypt one DTLS 1.3 DTLSCiphertext (unified header + record number decryption + AEAD).
 * raw = full packet (unified_hdr || encrypted_record). On success: out_content_type and out_plaintext filled; out_plaintext_len set to content length.
 */
noxtls_return_t noxtls_tls13_decrypt_dtls13_record(tls13_context_t *ctx,
                                       const uint8_t *raw, uint32_t raw_len,
                                       uint8_t *out_content_type, uint8_t *out_plaintext, uint32_t *out_plaintext_len)
{
    uint8_t epoch;
    uint32_t aad_len;
    uint32_t ciphertext_len;
    uint32_t inner_len;
    uint32_t tag_len;
    const uint8_t *ciphertext;
    uint8_t seq_enc;
    uint8_t seq;
    const uint8_t *read_key;
    const uint8_t *read_iv;
    const uint8_t *sn_key;
    uint8_t nonce[12];
    uint8_t mask[DTLS13_RECORD_NUMBER_ENC_LEN];
    uint8_t tag[16];
    int use_handshake;
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    int rc_aead;
    uint32_t i;
    noxtls_chacha20_context_t chacha_ctx;
    static const uint8_t zeros_16[16] = { 0 };

    if(ctx == NULL || raw == NULL || out_content_type == NULL || out_plaintext == NULL || out_plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!tls13_is_dtls_context(ctx) || raw_len < 4 + 8 + 1) {
        return NOXTLS_RETURN_BAD_DATA;  /* unified header + minimum AEAD tag + at least 1 byte inner */
    }
    if((raw[0] & 0xE0) != DTLS13_UNIFIED_FIXED_BITS) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    epoch = raw[0] & DTLS13_UNIFIED_EPOCH_MASK;
    use_handshake = (epoch == 1);
    {
        uint32_t cid_len = (raw[0] & DTLS13_UNIFIED_CID_BIT) ? ctx->own_connection_id_len : 0;
        if(raw[0] & DTLS13_UNIFIED_L_BIT) {
            aad_len = 4 + cid_len;
            seq_enc = raw[1];
            ciphertext_len = (uint32_t)((raw[2] << 8) | raw[3]);
            if(raw_len < aad_len + ciphertext_len || ciphertext_len < 16) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            ciphertext = raw + aad_len;
            if(cid_len > 0 && (cid_len > raw_len - 4 || memcmp(raw + 4, ctx->own_connection_id, cid_len) != 0)) {
                return NOXTLS_RETURN_BAD_DATA;  /* Connection ID mismatch */
            }
        } else {
            aad_len = 2 + cid_len;
            seq_enc = raw[1];
            ciphertext_len = raw_len - aad_len;
            if(ciphertext_len < 16) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            ciphertext = raw + aad_len;
            if(cid_len > 0 && (cid_len > raw_len - 2 || memcmp(raw + 2, ctx->own_connection_id, cid_len) != 0)) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
    }

    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        read_key = ctx->server_write_key;
        read_iv  = ctx->server_write_iv;
        sn_key   = use_handshake ? ctx->server_handshake_sn_key : ctx->server_sn_key;
    } else {
        read_key = ctx->client_write_key;
        read_iv  = ctx->client_write_iv;
        sn_key   = use_handshake ? ctx->client_handshake_sn_key : ctx->client_sn_key;
    }

    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ciphertext_len <= tag_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Record number decryption (reverse of send path) */
    if(use_aes_gcm || use_aes_ccm) {
        if(noxtls_aes_encrypt_data(sn_key, (uint8_t*)ciphertext, DTLS13_RECORD_NUMBER_ENC_LEN, NULL, mask, aes_type, NOXTLS_AES_ECB) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        uint64_t counter = (uint64_t)(ciphertext[0] | (ciphertext[1] << 8) | (ciphertext[2] << 16) | (ciphertext[3] << 24));
        if(noxtls_chacha20_init(&chacha_ctx, sn_key, (uint8_t*)(ciphertext + 4), counter) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_chacha20_process(&chacha_ctx, zeros_16, mask, DTLS13_RECORD_NUMBER_ENC_LEN) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    seq = seq_enc ^ mask[0];

    if(*out_plaintext_len < ciphertext_len - tag_len) {
        *out_plaintext_len = ciphertext_len - tag_len;
        return NOXTLS_RETURN_FAILED;
    }
    tls13_generate_nonce(nonce, read_iv, 12, (uint64_t)seq);
    memcpy(tag, ciphertext + ciphertext_len - tag_len, tag_len);
    inner_len = ciphertext_len - tag_len;

    if(use_aes_gcm) {
        rc_aead = noxtls_aes_gcm_decrypt(read_key, aes_type, nonce, raw, aad_len,
                                  ciphertext, inner_len, tag, out_plaintext);
    } else if(use_aes_ccm) {
        rc_aead = noxtls_aes_ccm_decrypt(read_key, aes_type, nonce, 12, raw, aad_len,
                                  ciphertext, inner_len, tag, tag_len, out_plaintext);
    } else {
        rc_aead = noxtls_chacha20_poly1305_decrypt(read_key, nonce, raw, aad_len,
                                            ciphertext, inner_len, tag, out_plaintext);
    }
    if(rc_aead != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Inner plaintext: content || content_type (1 byte) || padding. Last byte is content type. */
    *out_content_type = out_plaintext[inner_len - 1];
    for(i = inner_len - 2; i != (uint32_t)-1 && out_plaintext[i] == 0; i--) {
        /* skip padding */
    }
    *out_plaintext_len = i + 1;
    ctx->base.read_seq_num = (uint64_t)seq + 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt TLS 1.3 0-RTT (early data) record using early_write_key/iv/seq.
 * cipher_suite is the ticket's cipher (e.g. ctx->ticket_cipher_suite on client).
 */
noxtls_return_t noxtls_tls13_encrypt_record_early(tls13_context_t *ctx,
                                       uint16_t cipher_suite,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len)
{
    const uint8_t *write_key = ctx->early_write_key;
    const uint8_t *write_iv = ctx->early_write_iv;
    uint64_t seq_num = ctx->early_seq_num;
    uint8_t nonce[12];
    uint8_t aad[5];
    uint8_t tag[16];
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16;
    uint32_t record_len;
    noxtls_return_t rc;

    if(ctx == NULL || plaintext == NULL || encrypted_record == NULL || encrypted_record_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    tls13_generate_nonce(nonce, write_iv, 12, seq_num);

    if(tls13_get_record_cipher_params(cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    record_len = plaintext_len + tag_len;
    aad[0] = type;
    aad[1] = (ctx->base.base.version >> 8) & 0xFF;
    aad[2] = ctx->base.base.version & 0xFF;
    aad[3] = (record_len >> 8) & 0xFF;
    aad[4] = record_len & 0xFF;

    if(*encrypted_record_len < record_len) {
        *encrypted_record_len = record_len;
        return NOXTLS_RETURN_FAILED;
    }

    if(use_aes_gcm) {
        rc = noxtls_aes_gcm_encrypt(write_key, aes_type, nonce, aad, 5,
                             plaintext, plaintext_len,
                             encrypted_record, tag);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_aes_ccm) {
        rc = noxtls_aes_ccm_encrypt(write_key, aes_type, nonce, 12, aad, 5,
                             plaintext, plaintext_len, encrypted_record, tag, tag_len);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(use_chacha) {
        rc = noxtls_chacha20_poly1305_encrypt(write_key, nonce, aad, 5,
                                       plaintext, plaintext_len,
                                       encrypted_record, tag);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(encrypted_record + plaintext_len, tag, tag_len);
    *encrypted_record_len = record_len;
    ctx->early_seq_num++;
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
    const uint8_t *write_key = ctx->early_write_key;
    const uint8_t *write_iv = ctx->early_write_iv;
    uint64_t seq_num = ctx->early_seq_num;
    uint8_t nonce[12];
    uint8_t aad[5];
    uint8_t tag[16];
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16;
    uint32_t ciphertext_len;
    noxtls_return_t rc;

    if(ctx == NULL || encrypted_record == NULL || plaintext == NULL || plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(encrypted_record_len < 8) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    tls13_generate_nonce(nonce, write_iv, 12, seq_num);
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1] = (ctx->base.base.version >> 8) & 0xFF;
    aad[2] = ctx->base.base.version & 0xFF;
    aad[3] = (encrypted_record_len >> 8) & 0xFF;
    aad[4] = encrypted_record_len & 0xFF;

    if(tls13_get_record_cipher_params(cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(encrypted_record_len <= tag_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    ciphertext_len = encrypted_record_len - tag_len;
    memcpy(tag, encrypted_record + ciphertext_len, tag_len);

    if(*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return NOXTLS_RETURN_FAILED;
    }
    if(use_aes_gcm) {
        rc = noxtls_aes_gcm_decrypt(write_key, aes_type, nonce, aad, 5,
                             encrypted_record, ciphertext_len, tag, plaintext);
    } else if(use_aes_ccm) {
        rc = noxtls_aes_ccm_decrypt(write_key, aes_type, nonce, 12, aad, 5,
                             encrypted_record, ciphertext_len, tag, tag_len, plaintext);
    } else if(use_chacha) {
        rc = noxtls_chacha20_poly1305_decrypt(write_key, nonce, aad, 5,
                                       encrypted_record, ciphertext_len, tag, plaintext);
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rc != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *plaintext_len = ciphertext_len;
    ctx->early_seq_num++;
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
    uint8_t *write_key;
    uint8_t *write_iv;
    uint32_t iv_len;
    uint64_t seq_num;
    uint8_t nonce[12];
    uint8_t aad[5];  /* Additional Authenticated Data: type || version || length */
    uint8_t tag[16];
    int use_aes_gcm = 0;
    int use_aes_ccm = 0;
    int use_chacha = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint32_t tag_len = 16;
    uint32_t ciphertext_len;
    noxtls_return_t rc;
    
    if(ctx == NULL || encrypted_record == NULL || plaintext == NULL || plaintext_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(encrypted_record_len < 8) {
        return NOXTLS_RETURN_BAD_DATA;  /* Need at least tag */
    }
    
    /* Determine keys based on role */
    int used_client_keys = 0;
    if(ctx->base.base.role == TLS_ROLE_CLIENT) {
        write_key = ctx->server_write_key;  /* Receive from server */
        write_iv = ctx->server_write_iv;
        iv_len = 12;
        seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->server_seq_num;
    } else {
        write_key = ctx->client_write_key;  /* Receive from client */
        write_iv = ctx->client_write_iv;
        iv_len = 12;
        seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->client_seq_num;
        used_client_keys = 1;
    }
    
    if(tls13_get_record_cipher_params(ctx->cipher_suite, &use_aes_gcm, &use_aes_ccm, &use_chacha, &aes_type, &tag_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(encrypted_record_len <= tag_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Extract tag */
    ciphertext_len = encrypted_record_len - tag_len;
    memcpy(tag, encrypted_record + ciphertext_len, tag_len);
    if(ciphertext_len >= 4) {
        noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: tag[0..3]=%02X%02X%02X%02X ct_len=%u\n",
                              tag[0], tag[1], tag[2], tag[3], ciphertext_len);
    }
    
    /* Generate nonce */
    tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
    
    /* Build AAD: type || version || length */
    /* For TLS 1.3, AAD uses the encrypted_content length (ciphertext + tag) */
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1] = (ctx->base.base.version >> 8) & 0xFF;
    aad[2] = ctx->base.base.version & 0xFF;
    aad[3] = (encrypted_record_len >> 8) & 0xFF;
    aad[4] = encrypted_record_len & 0xFF;
    
    noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: suite=0x%04X seq=%llu len=%u\n",
                          ctx->cipher_suite, (unsigned long long)seq_num, encrypted_record_len);
    noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: key[0..3]=%02X%02X%02X%02X iv[0..3]=%02X%02X%02X%02X\n",
                          write_key[0], write_key[1], write_key[2], write_key[3],
                          write_iv[0], write_iv[1], write_iv[2], write_iv[3]);
    noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: nonce[0..3]=%02X%02X%02X%02X aad[0..4]=%02X%02X%02X%02X%02X\n",
                          nonce[0], nonce[1], nonce[2], nonce[3],
                          aad[0], aad[1], aad[2], aad[3], aad[4]);
    /* Decrypt using AEAD */
    if(*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return NOXTLS_RETURN_FAILED;
    }

    if(use_aes_gcm) {
        rc = noxtls_aes_gcm_decrypt(write_key, aes_type, nonce, aad, 5,
                             encrypted_record, ciphertext_len,
                             tag, plaintext);
        if(rc != 0) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_gcm rc=%d, trying client keys...\n", rc);
                write_key = ctx->client_write_key;
                write_iv = ctx->client_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->client_seq_num;
                used_client_keys = 1;
            } else {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_gcm rc=%d, trying server keys...\n", rc);
                write_key = ctx->server_write_key;
                write_iv = ctx->server_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->server_seq_num;
                used_client_keys = 0;
            }
            tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
            rc = noxtls_aes_gcm_decrypt(write_key, aes_type, nonce, aad, 5,
                                 encrypted_record, ciphertext_len,
                                 tag, plaintext);
        }
        if(rc != 0) {
            noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_gcm rc=%d\n", rc);
            if(ctx->base.base.role == TLS_ROLE_CLIENT && seq_num == 0) {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: ciphertext+tag (hex)\n");
                for(uint32_t i = 0; i < encrypted_record_len; i++) {
                    noxtls_debug_printf("%02X", encrypted_record[i]);
                    if(((i + 1) & 31) == 0) {
                        noxtls_debug_printf("\n");
                    }
                }
                if((encrypted_record_len & 31) != 0) {
                    noxtls_debug_printf("\n");
                }
            }
            return NOXTLS_RETURN_BAD_DATA;  /* AEAD tag verification failed */
        }
    } else if(use_aes_ccm) {
        rc = noxtls_aes_ccm_decrypt(write_key, aes_type, nonce, 12, aad, 5,
                             encrypted_record, ciphertext_len, tag, tag_len, plaintext);
        if(rc != 0) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_ccm rc=%d, trying client keys...\n", rc);
                write_key = ctx->client_write_key;
                write_iv = ctx->client_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->client_seq_num;
                used_client_keys = 1;
            } else {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_ccm rc=%d, trying server keys...\n", rc);
                write_key = ctx->server_write_key;
                write_iv = ctx->server_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->server_seq_num;
                used_client_keys = 0;
            }
            tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
            rc = noxtls_aes_ccm_decrypt(write_key, aes_type, nonce, 12, aad, 5,
                                 encrypted_record, ciphertext_len, tag, tag_len, plaintext);
        }
        if(rc != 0) {
            noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: aes_ccm rc=%d\n", rc);
            return NOXTLS_RETURN_BAD_DATA;  /* AEAD tag verification failed */
        }
    } else if(use_chacha) {
        rc = noxtls_chacha20_poly1305_decrypt(write_key, nonce, aad, 5,
                                       encrypted_record, ciphertext_len,
                                       tag, plaintext);
        if(rc != 0) {
            if(ctx->base.base.role == TLS_ROLE_CLIENT) {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: chacha rc=%d, trying client keys...\n", rc);
                write_key = ctx->client_write_key;
                write_iv = ctx->client_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->client_seq_num;
                used_client_keys = 1;
            } else {
                noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: chacha rc=%d, trying server keys...\n", rc);
                write_key = ctx->server_write_key;
                write_iv = ctx->server_write_iv;
                seq_num = tls13_is_dtls_context(ctx) ? ctx->base.read_seq_num : ctx->server_seq_num;
                used_client_keys = 0;
            }
            tls13_generate_nonce(nonce, write_iv, iv_len, seq_num);
            rc = noxtls_chacha20_poly1305_decrypt(write_key, nonce, aad, 5,
                                           encrypted_record, ciphertext_len,
                                           tag, plaintext);
        }
        if(rc != 0) {
            noxtls_debug_printf("[TLS13_DEBUG] decrypt_record: chacha rc=%d\n", rc);
            return NOXTLS_RETURN_BAD_DATA;  /* AEAD tag verification failed */
        }
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    *plaintext_len = ciphertext_len;
    
    /* Update sequence number */
    if(!tls13_is_dtls_context(ctx)) {
        if(ctx->base.base.role == TLS_ROLE_CLIENT) {
            if(used_client_keys) {
                ctx->client_seq_num++;
            } else {
                ctx->server_seq_num++;
            }
        } else {
            if(used_client_keys) {
                ctx->client_seq_num++;
            } else {
                ctx->server_seq_num++;
            }
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

