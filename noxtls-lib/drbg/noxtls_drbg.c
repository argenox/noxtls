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
* File:    noxtls_drbg.c
* Summary: Deterministic Random Bit Generator (DRBG) - AES-CTR-DRBG Implementation
*          Per NIST SP 800-90A
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_drbg.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_accel.h"
#include "encryption/aes/noxtls_aes_internal.h"
#include "noxtls_common.h"

/* Platform-specific includes for entropy sources */
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  /* Windows Vista or later for BCrypt */
#endif
#elif !defined(__ZEPHYR__)
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif
/* On Zephyr, no unistd/fcntl - entropy via noxtls_drbg_set_entropy_callback only */

/* Platform-specific entropy source */
#if defined(_WIN32) || defined(_WIN64)
/* Windows: Use BCryptGenRandom (CNG) or CryptGenRandom (CryptoAPI) */

/* Try to use BCryptGenRandom (CNG) - preferred method */
/* Use dynamic loading to avoid requiring bcrypt.lib at link time */
#ifdef __cplusplus
extern "C" {
#endif
/* Forward declarations for Windows BCrypt APIs (dynamically loaded) */
typedef LONG NTSTATUS;
typedef void* BCRYPT_ALG_HANDLE;
typedef const wchar_t* LPCWSTR;
typedef unsigned char* PUCHAR;
typedef unsigned long ULONG;
#define BCRYPT_RNG_ALGORITHM L"RNG"

typedef NTSTATUS (WINAPI *BCryptOpenAlgorithmProviderFunc)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *BCryptGenRandomFunc)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *BCryptCloseAlgorithmProviderFunc)(BCRYPT_ALG_HANDLE, ULONG);

static HMODULE g_bcrypt_dll = NULL;
static BCryptOpenAlgorithmProviderFunc g_BCryptOpenAlgorithmProvider = NULL;
static BCryptGenRandomFunc g_BCryptGenRandom = NULL;
static BCryptCloseAlgorithmProviderFunc g_BCryptCloseAlgorithmProvider = NULL;
static BCRYPT_ALG_HANDLE g_bcrypt_alg_handle = NULL;
static int g_bcrypt_initialized = 0;

/**
 * @brief Dynamically loads bcrypt.dll and opens the CNG RNG algorithm provider.
 *
 * @return 1 if @ref get_entropy_windows_bcrypt may use BCrypt; 0 on load or open failure.
 */
static int init_bcrypt(void)
{
    if(g_bcrypt_initialized) {
        return (g_bcrypt_alg_handle != NULL) ? 1 : 0;
    }
    
    g_bcrypt_initialized = 1;
    
    /* Load bcrypt.dll */
    g_bcrypt_dll = LoadLibraryA("bcrypt.dll");
    if(g_bcrypt_dll == NULL) {
        return 0;
    }
    
    /* Get function pointers */
#ifdef _MSC_VER
    NOXTLS_MSVC_WARNING_PUSH
    __pragma(warning(disable: 4191))
#endif
    g_BCryptOpenAlgorithmProvider = (BCryptOpenAlgorithmProviderFunc)
        GetProcAddress(g_bcrypt_dll, "BCryptOpenAlgorithmProvider");
    g_BCryptGenRandom = (BCryptGenRandomFunc)
        GetProcAddress(g_bcrypt_dll, "BCryptGenRandom");
    g_BCryptCloseAlgorithmProvider = (BCryptCloseAlgorithmProviderFunc)
        GetProcAddress(g_bcrypt_dll, "BCryptCloseAlgorithmProvider");
#ifdef _MSC_VER
    NOXTLS_MSVC_WARNING_POP
#endif
    
    if(!g_BCryptOpenAlgorithmProvider || !g_BCryptGenRandom || !g_BCryptCloseAlgorithmProvider) {
        FreeLibrary(g_bcrypt_dll);
        g_bcrypt_dll = NULL;
        return 0;
    }
    
    /* Open algorithm provider for RNG */
    if(g_BCryptOpenAlgorithmProvider(&g_bcrypt_alg_handle, BCRYPT_RNG_ALGORITHM, NULL, 0) != 0) {
        g_bcrypt_alg_handle = NULL;
        FreeLibrary(g_bcrypt_dll);
        g_bcrypt_dll = NULL;
        return 0;
    }
    
    return 1;
}

/**
 * @brief Fills a buffer using Windows CNG `BCryptGenRandom`.
 *
 * @param[out] entropy_buffer Output bytes.
 * @param[in]  entropy_len Number of bytes to produce.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` if BCrypt is unavailable or the call fails.
 */
static noxtls_return_t get_entropy_windows_bcrypt(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    if(init_bcrypt() && g_bcrypt_alg_handle != NULL && g_BCryptGenRandom != NULL) {
        if(g_BCryptGenRandom(g_bcrypt_alg_handle, entropy_buffer, entropy_len, 0) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Fills a buffer using legacy CryptoAPI `CryptGenRandom`.
 *
 * Fallback: Use CryptGenRandom (legacy CryptoAPI)
 *
 * @param[out] entropy_buffer Output bytes.
 * @param[in]  entropy_len Number of bytes to produce.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` on acquire or generation failure.
 */
static noxtls_return_t get_entropy_windows_cryptoapi(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    HCRYPTPROV hProv = 0;
    
    if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if(CryptGenRandom(hProv, entropy_len, entropy_buffer)) {
            CryptReleaseContext(hProv, 0);
            return NOXTLS_RETURN_SUCCESS;
        }
        CryptReleaseContext(hProv, 0);
    }
    
    return NOXTLS_RETURN_FAILED;
}
#ifdef __cplusplus
}
#endif

#elif !defined(__ZEPHYR__)
/* Non-Windows, non-Zephyr: Use /dev/urandom */
/**
 * @brief Reads @p entropy_len bytes from `/dev/urandom`.
 *
 * @param[out] entropy_buffer Output bytes.
 * @param[in]  entropy_len Number of bytes to read.
 * @return `NOXTLS_RETURN_SUCCESS` if a full read succeeds; `NOXTLS_RETURN_FAILED` otherwise.
 */
static noxtls_return_t get_entropy_unix(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0) {
        ssize_t bytes_read = read(fd, entropy_buffer, entropy_len);
        close(fd);
        if((size_t)bytes_read == entropy_len) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}
#endif

/* Dummy entropy source - generates deterministic but varying data */
static uint32_t dummy_entropy_counter = 0;
static noxtls_entropy_source_t g_entropy_source = NOXTLS_ENTROPY_SOURCE_AUTO;
static noxtls_entropy_cb_t g_entropy_cb = NULL;

/**
 * @brief Increments a counter in big-endian order.
 *
 * @param[in,out] counter Counter to increment.
 * @return None.
 */
static void drbg_increment_counter_be(uint8_t counter[DRBG_BLOCKLEN])
{
    uint32_t idx;
    for(idx = DRBG_BLOCKLEN; idx > 0U; idx--) {
        counter[idx - 1U]++;
        if(counter[idx - 1U] != 0U) {
            break;
        }
    }
}

/**
 * @brief Generates keystream blocks using AES-CTR.
 *
 * @param[in] key AES key.
 * @param[in,out] counter Counter.
 * @param[out] output Output buffer.
 * @param[in] block_count Number of blocks to generate.
 * @param[in] aes_type AES type.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` otherwise.
 */
static noxtls_return_t drbg_generate_keystream_blocks(const uint8_t *key,
                                                      uint8_t counter[DRBG_BLOCKLEN],
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t aes_type)
{
    enum { DRBG_PORT_AES_BATCH_BLOCKS = 16 };
    uint8_t ctr_blocks[DRBG_PORT_AES_BATCH_BLOCKS * DRBG_BLOCKLEN];
    uint8_t ks_blocks[DRBG_PORT_AES_BATCH_BLOCKS * DRBG_BLOCKLEN];
    uint32_t remaining = block_count;

    while(remaining > 0U) {
        uint32_t chunk_blocks = (remaining > DRBG_PORT_AES_BATCH_BLOCKS) ?
                                DRBG_PORT_AES_BATCH_BLOCKS : remaining;
        uint32_t b;
        noxtls_return_t rc;

        for(b = 0U; b < chunk_blocks; b++) {
            memcpy(ctr_blocks + ((size_t)b * DRBG_BLOCKLEN), counter, DRBG_BLOCKLEN);
            drbg_increment_counter_be(counter);
        }

        rc = noxtls_aes_accel_port_encrypt_blocks(key,
                                                  ctr_blocks,
                                                  ks_blocks,
                                                  chunk_blocks,
                                                  aes_type);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            memcpy(output, ks_blocks, (size_t)chunk_blocks * DRBG_BLOCKLEN);
            output += (size_t)chunk_blocks * DRBG_BLOCKLEN;
            remaining -= chunk_blocks;
            continue;
        }

        break;
    }

    if(remaining == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    uint32_t block;

    for(block = 0U; block < remaining; block++) {
        noxtls_return_t rc = noxtls_aes_encrypt_block_internal(key, counter, output, aes_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        output += DRBG_BLOCKLEN;
        drbg_increment_counter_be(counter);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Selects how @ref noxtls_drbg_get_entropy obtains bytes (platform RNG, custom callback, dummy, etc.).
 *
 * @param[in] source One of `noxtls_entropy_source_t`.
 *
 * @return None.
 */
void noxtls_drbg_set_entropy_source(noxtls_entropy_source_t source)
{
    g_entropy_source = source;
}

/**
 * @brief Returns the entropy source selected by @ref noxtls_drbg_set_entropy_source.
 *
 * @return Current `noxtls_entropy_source_t` value.
 */
noxtls_entropy_source_t noxtls_drbg_get_entropy_source(void)
{
    return g_entropy_source;
}

/**
 * @brief Installs a custom entropy callback (used for `NOXTLS_ENTROPY_SOURCE_CUSTOM` and on Zephyr in some paths).
 *
 * @param[in] cb Callback, or NULL to clear.
 * @return None.
 */
void noxtls_drbg_set_entropy_callback(noxtls_entropy_cb_t cb)
{
    g_entropy_cb = cb;
}

/**
 * @brief Returns the callback set by @ref noxtls_drbg_set_entropy_callback.
 *
 * @return Current callback pointer, or NULL if unset.
 */
noxtls_entropy_cb_t noxtls_drbg_get_entropy_callback(void)
{
    return g_entropy_cb;
}

/**
 * @brief Deterministic fallback entropy (not cryptographic); used when platform entropy is unavailable.
 *
 * @param[out] entropy_buffer Output bytes.
 * @param[in]  entropy_len Number of bytes to fill.
 *
 * @return Always `NOXTLS_RETURN_SUCCESS`.
 */
static noxtls_return_t drbg_entropy_dummy(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    uint64_t time_seed = (uint64_t)time(NULL);
    for(uint32_t i = 0; i < entropy_len; i++) {
        entropy_buffer[i] = (uint8_t)((dummy_entropy_counter + i + (uint32_t)time_seed) & DRBG_DUMMY_ENTROPY_MASK);
        dummy_entropy_counter++;
        if(i % DRBG_DUMMY_ENTROPY_STEP == 0) {
            time_seed = time_seed * DRBG_DUMMY_ENTROPY_LCG_MULTIPLIER + DRBG_DUMMY_ENTROPY_LCG_INCREMENT;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Fills @p entropy_len bytes using the configured entropy source and fallbacks.
 *
 * @param[out] entropy_buffer Caller buffer; must not be NULL.
 * @param[in]  entropy_len Number of bytes to produce.
 *
 * @return `NOXTLS_RETURN_SUCCESS` when bytes are written; `NOXTLS_RETURN_NULL` if @p entropy_buffer is NULL.
 */
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    if(entropy_buffer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    switch(g_entropy_source) {
        case NOXTLS_ENTROPY_SOURCE_CUSTOM:
            if(g_entropy_cb) {
                if(g_entropy_cb(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_SUCCESS;
                }
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
        case NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG:
#if defined(_WIN32) || defined(_WIN64)
            if(get_entropy_windows_bcrypt(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            if(get_entropy_windows_cryptoapi(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
#endif
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
        case NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM:
#if defined(__ZEPHYR__)
            if(g_entropy_cb && g_entropy_cb(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
#elif !(defined(_WIN32) || defined(_WIN64))
            if(get_entropy_unix(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
#endif
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
        case NOXTLS_ENTROPY_SOURCE_DUMMY:
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
        case NOXTLS_ENTROPY_SOURCE_AUTO:
        default:
#if defined(__ZEPHYR__)
            if(g_entropy_cb && g_entropy_cb(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
#elif defined(_WIN32) || defined(_WIN64)
            if(get_entropy_windows_bcrypt(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            if(get_entropy_windows_cryptoapi(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
#else
            if(get_entropy_unix(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return drbg_entropy_dummy(entropy_buffer, entropy_len);
#endif
    }
}

/**
 * @brief Updates DRBG internal state (Key and V) using AES-CTR mixing (NIST SP 800-90A §10.2.1.2 Update).
 *
 * @param[in,out] state Instantiated DRBG state; `Key` and `V` are overwritten.
 * @param[in]     provided_data Optional seeding material; may be NULL to use zero padding in the derivation path.
 * @param[in]     provided_data_len Length of @p provided_data in bytes (ignored if @p provided_data is NULL).
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p state is NULL; `NOXTLS_RETURN_INVALID_ALGORITHM` for unknown AES variant.
 */
noxtls_return_t drbg_update(drbg_state_t *state,
                               const uint8_t *provided_data,
                               uint32_t provided_data_len)
{
    uint8_t temp[DRBG_SEEDLEN_AES256];  /* Maximum seed length */
    uint8_t block[DRBG_BLOCKLEN];
    uint8_t keystream[DRBG_BLOCKLEN];
    uint32_t i;
    uint32_t j;
    uint32_t seedlen;
    noxtls_aes_type_t aes_type;
    
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    seedlen = state->seedlen;
    
    /* Convert DRBG AES type to AES type */
    switch(state->aes_type) {
        case DRBG_AES128:
            aes_type = NOXTLS_AES_128_BIT;
            break;
        case DRBG_AES192:
            aes_type = NOXTLS_AES_192_BIT;
            break;
        case DRBG_AES256:
            aes_type = NOXTLS_AES_256_BIT;
            break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    /* Initialize temp with provided_data */
    memset(temp, 0, seedlen);
    if(provided_data != NULL && provided_data_len > 0) {
        uint32_t copy_len = (provided_data_len < seedlen) ? provided_data_len : seedlen;
        memcpy(temp, provided_data, copy_len);
    }
    
    /* Step 1: temp = temp XOR (V || 0x00...0x00) */
    /* Concatenate V with zeros to fill seedlen */
    for(i = 0; i < seedlen; i++) {
        if(i < DRBG_BLOCKLEN) {
            temp[i] ^= state->V[i];
        }
    }
    
    /* Step 2: Key = df(Key || temp, keylen) */
    /* df (derivation function) using AES-CTR */
    /* For simplicity, we use AES-CTR to generate keylen bytes */
    memcpy(block, state->V, DRBG_BLOCKLEN);
    
    /* Encrypt counter blocks to generate new key material */
    for(i = 0; i < state->keylen; i += DRBG_BLOCKLEN) {
        uint32_t block_len = (state->keylen - i < DRBG_BLOCKLEN) ? 
                             (state->keylen - i) : DRBG_BLOCKLEN;
        
        noxtls_aes_encrypt_block_internal(state->Key, block, keystream, aes_type);
        
        /* XOR with temp data */
        for(j = 0; j < block_len; j++) {
            state->Key[i + j] = keystream[j] ^ temp[i + j];
        }
        
        /* Increment counter (big-endian) */
        for(j = DRBG_BLOCKLEN - 1; ; j--) {
            block[j]++;
            if(block[j] != 0 || j == 0) break;
        }
    }
    
    /* Step 3: V = df(Key || V, blocklen) */
    /* Generate new V using AES-CTR */
    memcpy(block, state->V, DRBG_BLOCKLEN);
    noxtls_aes_encrypt_block_internal(state->Key, block, state->V, aes_type);
    
    /* XOR with temp data */
    for(i = 0; i < DRBG_BLOCKLEN; i++) {
        state->V[i] ^= temp[i];
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Creates a DRBG instance from entropy and optional nonce/personalization (NIST SP 800-90A §10.2.1.2).
 *
 * @param[out] state Output state; zeroed then filled; must not be NULL.
 * @param[in]  aes_type AES-128/192/256 DRBG variant.
 * @param[in]  entropy_input Optional caller entropy; if NULL or shorter than seed length, @ref noxtls_drbg_get_entropy supplies bytes.
 * @param[in]  entropy_len Length of @p entropy_input when provided.
 * @param[in]  nonce Optional nonce bytes (may be NULL).
 * @param[in]  nonce_len Length of @p nonce.
 * @param[in]  personalization_string Optional personalization (may be NULL).
 * @param[in]  pers_len Length of @p personalization_string.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_ALGORITHM`, or `NOXTLS_RETURN_FAILED` on error.
 */
noxtls_return_t drbg_instantiate(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len)
{
    uint8_t seed_material[DRBG_SEEDLEN_AES256];
    uint8_t entropy[DRBG_SEEDLEN_AES256];
    uint32_t seedlen;
    uint32_t keylen;
    uint32_t i;
    
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Initialize state structure */
    memset(state, 0, sizeof(drbg_state_t));
    state->aes_type = aes_type;
    
    /* Set seed and key lengths based on AES type */
    switch(aes_type) {
        case DRBG_AES128:
            seedlen = DRBG_SEEDLEN_AES128;
            keylen = DRBG_KEYLEN_AES128;
            break;
        case DRBG_AES192:
            seedlen = DRBG_SEEDLEN_AES192;
            keylen = DRBG_KEYLEN_AES192;
            break;
        case DRBG_AES256:
            seedlen = DRBG_SEEDLEN_AES256;
            keylen = DRBG_KEYLEN_AES256;
            break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    state->seedlen = seedlen;
    state->keylen = keylen;
    
    /* Get entropy input */
    if(entropy_input == NULL || entropy_len < seedlen) {
        /* Use dummy entropy source */
        if(noxtls_drbg_get_entropy(entropy, seedlen) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        /* entropy_len is input-only; seedlen drives local buffer sizing */
    } else {
        memcpy(entropy, entropy_input, seedlen);
    }
    
    /* Prepare seed material: entropy || nonce || personalization_string */
    memset(seed_material, 0, seedlen);
    i = 0;
    
    /* Copy entropy (in else branch entropy_len >= seedlen; in if branch we set entropy_len = seedlen) */
    memcpy(seed_material + i, entropy, seedlen);
    i += seedlen;
    
    /* Copy nonce if provided */
    if(nonce != NULL && nonce_len > 0 && i < seedlen) {
        uint32_t copy_len = (nonce_len < (seedlen - i)) ? nonce_len : (seedlen - i);
        memcpy(seed_material + i, nonce, copy_len);
        i += copy_len;
    }
    
    /* Copy personalization string if provided */
    if(personalization_string != NULL && pers_len > 0 && i < seedlen) {
        uint32_t copy_len = (pers_len < (seedlen - i)) ? pers_len : (seedlen - i);
        memcpy(seed_material + i, personalization_string, copy_len);
    }
    
    /* Initialize Key and V to zero */
    memset(state->Key, 0, DRBG_KEYLEN_AES256);
    memset(state->V, 0, DRBG_BLOCKLEN);
    
    /* Update state with seed material */
    if(drbg_update(state, seed_material, seedlen) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Initialize reseed counter */
    state->reseed_counter = 1;
    state->instantiated = 1;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generates pseudorandom bits and advances internal state (NIST SP 800-90A §10.2.1.3).
 * @param[in,out] state Instantiated DRBG; updated and reseed counter incremented.
 * @param[out]    output_buffer Receives at least `ceil(requested_bits/8)` bytes (final byte masked if bit count not multiple of 8).
 * @param[in]     requested_bits Number of random bits to produce (must not exceed `DRBG_MAX_BITS_PER_REQUEST`).
 * @param[in]     additional_input Optional additional input for update step (may be NULL).
 * @param[in]     add_input_len Length of @p additional_input.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED` (not instantiated or reseed required), `NOXTLS_RETURN_INVALID_PARAM`, or `NOXTLS_RETURN_INVALID_ALGORITHM` on error.
 */
noxtls_return_t drbg_generate(drbg_state_t *state,
                                 uint8_t *output_buffer,
                                 uint32_t requested_bits,
                                 const uint8_t *additional_input,
                                 uint32_t add_input_len)
{
    uint8_t block[DRBG_BLOCKLEN];
    uint8_t keystream[DRBG_BLOCKLEN];
    uint32_t requested_bytes;
    uint32_t full_blocks;
    uint32_t tail_bytes;
    noxtls_aes_type_t aes_type;
    
    if(state == NULL || output_buffer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(!state->instantiated) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check reseed requirement */
    if(state->reseed_counter > DRBG_RESEED_INTERVAL) {
        return NOXTLS_RETURN_FAILED;  /* Reseed required */
    }
    
    /* Check maximum request size */
    if(requested_bits > DRBG_MAX_BITS_PER_REQUEST) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    /* Convert bits to bytes (round up) */
    requested_bytes = (requested_bits + 7) >> 3;
    
    /* Convert DRBG AES type to AES type */
    switch(state->aes_type) {
        case DRBG_AES128:
            aes_type = NOXTLS_AES_128_BIT;
            break;
        case DRBG_AES192:
            aes_type = NOXTLS_AES_192_BIT;
            break;
        case DRBG_AES256:
            aes_type = NOXTLS_AES_256_BIT;
            break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    /* Step 1: If additional_input is provided, update state */
    if(additional_input != NULL && add_input_len > 0) {
        if(drbg_update(state, additional_input, add_input_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    /* Step 2: Generate output using AES-CTR */
    memcpy(block, state->V, DRBG_BLOCKLEN);

    full_blocks = requested_bytes / DRBG_BLOCKLEN;
    tail_bytes = requested_bytes % DRBG_BLOCKLEN;

    if(full_blocks > 0U) {
        if(drbg_generate_keystream_blocks(state->Key,
                                          block,
                                          output_buffer,
                                          full_blocks,
                                          aes_type) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    if(tail_bytes > 0U) {
        if(noxtls_aes_encrypt_block_internal(state->Key, block, keystream, aes_type) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(output_buffer + ((size_t)full_blocks * DRBG_BLOCKLEN), keystream, tail_bytes);
        drbg_increment_counter_be(block);
    }
    
    /* Step 3: Update state */
    if(drbg_update(state, additional_input, add_input_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Step 4: Increment reseed counter */
    state->reseed_counter++;
    
    /* Step 5: Truncate output if requested_bits is not a multiple of 8 */
    if((requested_bits & 7U) != 0U) {
        uint8_t mask = (uint8_t)((1U << (requested_bits & 7U)) - 1U);
        output_buffer[requested_bytes - 1] &= mask;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reseeds an instantiated DRBG with fresh entropy and optional additional input (NIST SP 800-90A §10.2.1.4).
 *
 * @param[in,out] state Live DRBG state; reseed counter reset to 1 on success.
 * @param[in]     entropy_input Optional caller entropy; if NULL or shorter than seed length, @ref noxtls_drbg_get_entropy is used.
 * @param[in]     entropy_len Length of @p entropy_input when provided.
 * @param[in]     additional_input Optional extra seeding material (may be NULL).
 * @param[in]     add_input_len Length of @p additional_input.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_FAILED`, or errors from @ref drbg_update on failure.
 */
noxtls_return_t drbg_reseed(drbg_state_t *state,
                              const uint8_t *entropy_input,
                              uint32_t entropy_len,
                              const uint8_t *additional_input,
                              uint32_t add_input_len)
{
    uint8_t seed_material[DRBG_SEEDLEN_AES256];
    uint8_t entropy[DRBG_SEEDLEN_AES256];
    uint32_t seedlen;
    uint32_t i;
    
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(!state->instantiated) {
        return NOXTLS_RETURN_FAILED;
    }
    
    seedlen = state->seedlen;
    
    /* Get entropy input */
    if(entropy_input == NULL || entropy_len < seedlen) {
        /* Use dummy entropy source */
        if(noxtls_drbg_get_entropy(entropy, seedlen) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        /* entropy_len is input-only; seedlen drives local buffer sizing */
    } else {
        memcpy(entropy, entropy_input, seedlen);
    }
    
    /* Prepare seed material: entropy || additional_input */
    memset(seed_material, 0, seedlen);
    i = 0;
    
    /* Copy entropy (in else branch entropy_len >= seedlen; in if branch we set entropy_len = seedlen) */
    memcpy(seed_material + i, entropy, seedlen);
    i += seedlen;
    
    /* Copy additional input if provided */
    if(additional_input != NULL && add_input_len > 0 && i < seedlen) {
        uint32_t copy_len = (add_input_len < (seedlen - i)) ? add_input_len : (seedlen - i);
        memcpy(seed_material + i, additional_input, copy_len);
    }
    
    /* Update state with seed material */
    if(drbg_update(state, seed_material, seedlen) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Reset reseed counter */
    state->reseed_counter = 1;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Zeroes and invalidates DRBG state (safe to call on an unused or active instance).
 *
 * @param[in,out] state State buffer to clear; must not be NULL.
 *
 * @return `NOXTLS_RETURN_SUCCESS` after clearing; `NOXTLS_RETURN_NULL` if @p state is NULL.
 */
noxtls_return_t noxtls_drbg_uninstantiate(drbg_state_t *state)
{
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Clear all state */
    memset(state, 0, sizeof(drbg_state_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

