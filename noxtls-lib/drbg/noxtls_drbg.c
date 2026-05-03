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
* File:    noxtls_drbg.c
* Summary: Deterministic Random Bit Generator (DRBG) - AES-CTR-DRBG Implementation
*          Per NIST SP 800-90A
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_drbg.h"
#include "encryption/aes/noxtls_aes.h"
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
/* On Zephyr, no unistd/fcntl - entropy via drbg_set_entropy_callback only */

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

static noxtls_return_t get_entropy_windows_bcrypt(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    if(init_bcrypt() && g_bcrypt_alg_handle != NULL && g_BCryptGenRandom != NULL) {
        if(g_BCryptGenRandom(g_bcrypt_alg_handle, entropy_buffer, entropy_len, 0) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/* Fallback: Use CryptGenRandom (legacy CryptoAPI) */
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

void drbg_set_entropy_source(noxtls_entropy_source_t source)
{
    g_entropy_source = source;
}

noxtls_entropy_source_t drbg_get_entropy_source(void)
{
    return g_entropy_source;
}

void drbg_set_entropy_callback(noxtls_entropy_cb_t cb)
{
    g_entropy_cb = cb;
}

noxtls_entropy_cb_t drbg_get_entropy_callback(void)
{
    return g_entropy_cb;
}

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
 * @brief Get entropy input
 * 
 * Attempts to use platform-specific cryptographic random number generators.
 * Falls back to time-based entropy if platform APIs are unavailable.
 */
noxtls_return_t drbg_get_entropy(uint8_t *entropy_buffer, uint32_t entropy_len)
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
 * @brief Update the DRBG state using AES-CTR
 * 
 * Per NIST SP 800-90A Section 10.2.1.2 (Update function)
 * This is the core algorithm that updates V and Key using AES-CTR
 */
noxtls_return_t drbg_update(drbg_state_t *state,
                               const uint8_t *provided_data,
                               uint32_t provided_data_len)
{
    uint8_t temp[DRBG_SEEDLEN_AES256];  /* Maximum seed length */
    uint8_t block[DRBG_BLOCKLEN];
    uint32_t i, j;
    uint32_t seedlen;
    aes_type_t aes_type;
    
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    seedlen = state->seedlen;
    
    /* Convert DRBG AES type to AES type */
    switch(state->aes_type) {
        case DRBG_AES128:
            aes_type = AES_128_BIT;
            break;
        case DRBG_AES192:
            aes_type = AES_192_BIT;
            break;
        case DRBG_AES256:
            aes_type = AES_256_BIT;
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
        uint8_t keystream[DRBG_BLOCKLEN];
        
        aes_encrypt_block_internal(state->Key, block, keystream, aes_type);
        
        /* XOR with temp data */
        for(j = 0; j < block_len; j++) {
            state->Key[i + j] = keystream[j] ^ temp[(i + j) % seedlen];
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
    aes_encrypt_block_internal(state->Key, block, state->V, aes_type);
    
    /* XOR with temp data */
    for(i = 0; i < DRBG_BLOCKLEN; i++) {
        state->V[i] ^= temp[i % seedlen];
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Instantiate the DRBG
 * 
 * Per NIST SP 800-90A Section 10.2.1.2
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
        if(drbg_get_entropy(entropy, seedlen) != NOXTLS_RETURN_SUCCESS) {
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
 * @brief Generate random bits
 * 
 * Per NIST SP 800-90A Section 10.2.1.3
 */
noxtls_return_t drbg_generate(drbg_state_t *state,
                                 uint8_t *output_buffer,
                                 uint32_t requested_bits,
                                 const uint8_t *additional_input,
                                 uint32_t add_input_len)
{
    uint8_t block[DRBG_BLOCKLEN];
    uint32_t requested_bytes;
    uint32_t i, j;
    aes_type_t aes_type;
    
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
            aes_type = AES_128_BIT;
            break;
        case DRBG_AES192:
            aes_type = AES_192_BIT;
            break;
        case DRBG_AES256:
            aes_type = AES_256_BIT;
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
    
    for(i = 0; i < requested_bytes; i += DRBG_BLOCKLEN) {
        uint32_t block_len = (requested_bytes - i < DRBG_BLOCKLEN) ? 
                             (requested_bytes - i) : DRBG_BLOCKLEN;
        uint8_t keystream[DRBG_BLOCKLEN];
        
        /* Encrypt counter to produce keystream */
        aes_encrypt_block_internal(state->Key, block, keystream, aes_type);
        
        /* Copy keystream to output */
        for(j = 0; j < block_len; j++) {
            output_buffer[i + j] = keystream[j];
        }
        
        /* Increment counter (big-endian) */
        for(j = DRBG_BLOCKLEN - 1; ; j--) {
            block[j]++;
            if(block[j] != 0 || j == 0) break;
        }
    }
    
    /* Step 3: Update state */
    if(drbg_update(state, additional_input, add_input_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Step 4: Increment reseed counter */
    state->reseed_counter++;
    
    /* Step 5: Truncate output if requested_bits is not a multiple of 8 */
    if(requested_bits & 7 != 0) {
        uint8_t mask = (1 << (requested_bits & 7)) - 1;
        output_buffer[requested_bytes - 1] &= mask;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reseed the DRBG
 * 
 * Per NIST SP 800-90A Section 10.2.1.4
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
        if(drbg_get_entropy(entropy, seedlen) != NOXTLS_RETURN_SUCCESS) {
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
 * @brief Uninstantiate the DRBG (clear state)
 */
noxtls_return_t drbg_uninstantiate(drbg_state_t *state)
{
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Clear all state */
    memset(state, 0, sizeof(drbg_state_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

