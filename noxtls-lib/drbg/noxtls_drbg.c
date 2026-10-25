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
*          Per NIST SP 800-90A Rev.1 section 10.2.1 (CTR_DRBG with and without
*          Block_Cipher_df, prediction resistance), validated with the NIST
*          CAVP CTR_DRBG vectors (ut/crypto_sym/crypto_sym_drbg_sp800_90a_test.c)
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_accel_port.h"
#include "common/noxtls_time.h"
#include "common/noxtls_ct.h"
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
#elif !defined(__ZEPHYR__) && !defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "noxtls_ct.h"
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
static uint8_t g_bcrypt_initialized = 0U;

/**
 * @brief Dynamically loads bcrypt.dll and opens the CNG RNG algorithm provider.
 *
 * @return 1 if @ref get_entropy_windows_bcrypt may use BCrypt; 0 on load or open failure.
 */
static int init_bcrypt(void)
{
    if (g_bcrypt_initialized != 0U) {
        return (g_bcrypt_alg_handle != NULL) ? 1 : 0;
    }
    
    g_bcrypt_initialized = 1U;
    
    /* Load bcrypt.dll */
    g_bcrypt_dll = LoadLibraryA("bcrypt.dll");
    if (g_bcrypt_dll == NULL) {
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
    
    if ((g_BCryptOpenAlgorithmProvider == NULL) || (g_BCryptGenRandom == NULL) || (g_BCryptCloseAlgorithmProvider == NULL)) {
        FreeLibrary(g_bcrypt_dll);
        g_bcrypt_dll = NULL;
        return 0;
    }
    
    /* Open algorithm provider for RNG */
    if (g_BCryptOpenAlgorithmProvider(&g_bcrypt_alg_handle, BCRYPT_RNG_ALGORITHM, NULL, 0) != 0) {
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
 * @param[out] entropy_out Output bytes.
 * @param[in]  entropy_len Number of bytes to produce.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` if BCrypt is unavailable or the call fails.
 */
static noxtls_return_t get_entropy_windows_bcrypt(uint8_t *entropy_out, uint32_t entropy_out_len)
{
    if ((init_bcrypt()) && (g_bcrypt_alg_handle != NULL) && (g_BCryptGenRandom != NULL)) {
        if (g_BCryptGenRandom(g_bcrypt_alg_handle, entropy_out, entropy_out_len, 0) == 0) {
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
 * @param[out] entropy_out Output bytes.
 * @param[in]  entropy_len Number of bytes to produce.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` on acquire or generation failure.
 */
static noxtls_return_t get_entropy_windows_cryptoapi(uint8_t *entropy_out, uint32_t entropy_out_len)
{
    HCRYPTPROV hProv = 0;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
        if (CryptGenRandom(hProv, entropy_out_len, entropy_out) != 0) {
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

#elif !defined(__ZEPHYR__) && !defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
/* Non-Windows, non-Zephyr: Use /dev/urandom */
/**
 * @brief Reads @p entropy_len bytes from `/dev/urandom`.
 *
 * @param[out] entropy_out Output bytes.
 * @param[in]  entropy_len Number of bytes to read.
 * @return `NOXTLS_RETURN_SUCCESS` if a full read succeeds; `NOXTLS_RETURN_FAILED` otherwise.
 */
static noxtls_return_t get_entropy_unix(uint8_t *entropy_out, uint32_t entropy_out_len)
{
    size_t done = 0U;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return NOXTLS_RETURN_FAILED;
    }
    /* read() may return fewer bytes (signal, large request): loop until full. */
    while (done < (size_t)entropy_out_len) {
        ssize_t bytes_read = read(fd, &entropy_out[done], (size_t)entropy_out_len - done);
        if (bytes_read > 0) {
            done += (size_t)bytes_read;
        } else if ((bytes_read < 0) && (errno == EINTR)) {
            /* MISRA 15.7: interrupted, retry */
        } else {
            break;
        }
    }
    (void)close(fd);
    if (done == (size_t)entropy_out_len) {
        return NOXTLS_RETURN_SUCCESS;
    }
    noxtls_secure_zero(entropy_out, (size_t)entropy_out_len);
    return NOXTLS_RETURN_FAILED;
}
#endif

static noxtls_entropy_source_t g_entropy_source = NOXTLS_ENTROPY_SOURCE_AUTO;
static noxtls_entropy_cb_t g_entropy_cb = NULL;

/* Block_Cipher_df runs ceil((keylen + blocklen) / blocklen) BCC chains: 2 for
 * AES-128, 3 for AES-192 and AES-256 (SP 800-90A 10.3.2 step 9). */
#define DRBG_DF_MAX_CHAINS      3U
/* Counter blocks staged per call of the platform batch hook. */
#define DRBG_PORT_BATCH_BLOCKS  4U
/* Number of segments concatenated into a derivation-function input string. */
#define DRBG_DF_MAX_SEGMENTS    3U

/* SP 800-90A 10.3.2 step 8: K = leftmost keylen bits of 0x00010203...1D1E1F. */
static const uint8_t k_drbg_df_key[DRBG_KEYLEN_AES256] = {
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

/** Per-variant lengths (SP 800-90A Table 3). */
typedef struct
{
    uint32_t seedlen;            /* keylen + blocklen */
    uint32_t keylen;             /* = security strength in bytes */
    noxtls_aes_type_t aes_type;
} drbg_params_t;

/** Input string of the derivation function: the concatenation of up to three segments. */
typedef struct
{
    const uint8_t *data[DRBG_DF_MAX_SEGMENTS];
    uint32_t len[DRBG_DF_MAX_SEGMENTS];
} drbg_df_input_t;

/**
 * @brief Increments a counter in big-endian order (V = (V + 1) mod 2^blocklen).
 *
 * @param[in,out] counter Counter to increment.
 * @return None.
 */
static void drbg_increment_counter_be(uint8_t *counter)
{
    uint32_t idx = 0U;
    for (idx = DRBG_BLOCKLEN; idx > 0U; idx -= 1U) {
        counter[idx - 1U] = (uint8_t)(counter[idx - 1U] + 1U);
        if (counter[idx - 1U] != 0U) {
            break;
        }
    }
}

/**
 * @brief Derive seed length, key length and AES key type for a DRBG variant.
 *
 * @param[in]  drbg_type DRBG_AES128/192/256.
 * @param[out] params Lengths and AES type.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_INVALID_ALGORITHM for an unknown variant.
 */
static noxtls_return_t drbg_variant_params(uint32_t drbg_type, drbg_params_t *params)
{
    switch (drbg_type) {
        case DRBG_AES128:
            params->seedlen = (uint32_t)DRBG_SEEDLEN_AES128;
            params->keylen = (uint32_t)DRBG_KEYLEN_AES128;
            params->aes_type = NOXTLS_AES_128_BIT;
            break;
        case DRBG_AES192:
            params->seedlen = (uint32_t)DRBG_SEEDLEN_AES192;
            params->keylen = (uint32_t)DRBG_KEYLEN_AES192;
            params->aes_type = NOXTLS_AES_192_BIT;
            break;
        case DRBG_AES256:
            params->seedlen = (uint32_t)DRBG_SEEDLEN_AES256;
            params->keylen = (uint32_t)DRBG_KEYLEN_AES256;
            params->aes_type = NOXTLS_AES_256_BIT;
            break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Identifier of the calling process for fork detection (0 when disabled).
 *
 * @return getpid() on hosted POSIX builds with NOXTLS_DRBG_FORK_DETECT, else 0.
 */
static uint32_t drbg_fork_id(void)
{
#if NOXTLS_DRBG_FORK_DETECT
    return (uint32_t)getpid();
#else
    return 0U;
#endif
}

#if defined(__GNUC__) || defined(__clang__)
/* Keep the batch and software keystream frames apart (their maxima do not add up). */
#define DRBG_NOINLINE __attribute__((noinline))
#else
#define DRBG_NOINLINE
#endif

/* Keystream use: write it to the buffer, or XOR it into the buffer (Update). */
#define DRBG_CTR_WRITE  0U
#define DRBG_CTR_XOR    1U

/**
 * @brief Stores @p n keystream bytes into @p dst (copy or XOR, see DRBG_CTR_*).
 *
 * @return None.
 */
static void drbg_put_keystream(uint8_t *dst, const uint8_t *ks, uint32_t n, uint32_t mode)
{
    uint32_t i = 0U;
    if (mode == DRBG_CTR_XOR) {
        for (i = 0U; i < n; i += 1U) {
            dst[i] ^= ks[i];
        }
    } else {
        noxtls_copy_u8(dst, (size_t)n, ks, (size_t)n);
    }
}

/**
 * @brief Keystream through the platform batch hook (noxtls_aes_accel_port_encrypt_blocks).
 *
 * Counter blocks V+1 .. V+k are staged DRBG_PORT_BATCH_BLOCKS at a time; V is
 * advanced only for blocks the hook produced. Whole output blocks are written by
 * the hook in place; a trailing partial block and XOR mode go through a local block.
 *
 * @param[out] done Bytes produced.
 *
 * @return NOXTLS_RETURN_SUCCESS (all bytes produced), NOXTLS_RETURN_NOT_SUPPORTED
 *         (no batch backend: continue with drbg_ctr_soft() at @p done), or the AES error.
 */
static DRBG_NOINLINE noxtls_return_t drbg_ctr_batch(const uint8_t *key, noxtls_aes_type_t aes_type, uint8_t *v,
                                                    uint8_t *out, uint32_t out_len, uint32_t mode, uint32_t *done)
{
    uint8_t ctr_blocks[DRBG_PORT_BATCH_BLOCKS * DRBG_BLOCKLEN];
    uint8_t last[DRBG_BLOCKLEN];
    uint32_t pos = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    while ((rc == NOXTLS_RETURN_SUCCESS) && (pos < out_len)) {
        uint32_t left = out_len - pos;
        uint32_t full = left / DRBG_BLOCKLEN;
        uint32_t direct = ((mode == DRBG_CTR_WRITE) && (full > 0U)) ? 1U : 0U;
        uint32_t chunk = 1U;
        uint32_t b = 0U;

        if (direct != 0U) {
            chunk = (full > DRBG_PORT_BATCH_BLOCKS) ? DRBG_PORT_BATCH_BLOCKS : full;
        }
        noxtls_copy_u8(ctr_blocks, sizeof(ctr_blocks), v, (size_t)DRBG_BLOCKLEN);
        drbg_increment_counter_be(ctr_blocks);
        for (b = 1U; b < chunk; b += 1U) {
            uint8_t *blk = &ctr_blocks[(size_t)b * DRBG_BLOCKLEN];
            noxtls_copy_u8(blk, (size_t)DRBG_BLOCKLEN, &ctr_blocks[(size_t)(b - 1U) * DRBG_BLOCKLEN], (size_t)DRBG_BLOCKLEN);
            drbg_increment_counter_be(blk);
        }
        rc = noxtls_aes_accel_port_encrypt_blocks(key, ctr_blocks, (direct != 0U) ? &out[pos] : last, chunk, aes_type);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(v, (size_t)DRBG_BLOCKLEN, &ctr_blocks[(size_t)(chunk - 1U) * DRBG_BLOCKLEN],
                           (size_t)DRBG_BLOCKLEN);
            if (direct != 0U) {
                pos += chunk * DRBG_BLOCKLEN;
            } else {
                uint32_t n = (left < DRBG_BLOCKLEN) ? left : DRBG_BLOCKLEN;
                drbg_put_keystream(&out[pos], last, n, mode);
                pos += n;
            }
        }
    }
    noxtls_secure_zero(ctr_blocks, sizeof(ctr_blocks));
    noxtls_secure_zero(last, sizeof(last));
    *done = pos;
    return rc;
}

/**
 * @brief Keystream through one prepared AES context (software or the per-block port).
 *
 * @return NOXTLS_RETURN_SUCCESS or the AES error.
 */
static DRBG_NOINLINE noxtls_return_t drbg_ctr_soft(const uint8_t *key, noxtls_aes_type_t aes_type, uint8_t *v,
                                                   uint8_t *out, uint32_t out_len, uint32_t mode)
{
    noxtls_aes_context_t actx;
    uint8_t last[DRBG_BLOCKLEN];
    uint32_t pos = 0U;
    noxtls_return_t rc;

    rc = noxtls_aes_prepare_context(&actx, key, aes_type);
    while ((rc == NOXTLS_RETURN_SUCCESS) && (pos < out_len)) {
        uint32_t left = out_len - pos;
        drbg_increment_counter_be(v);
        if ((mode == DRBG_CTR_WRITE) && (left >= DRBG_BLOCKLEN)) {
            rc = noxtls_aes_encrypt_block_ctx_internal(&actx, v, &out[pos]);
            pos += DRBG_BLOCKLEN;
        } else {
            uint32_t n = (left < DRBG_BLOCKLEN) ? left : DRBG_BLOCKLEN;
            rc = noxtls_aes_encrypt_block_ctx_internal(&actx, v, last);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                drbg_put_keystream(&out[pos], last, n, mode);
            }
            pos += n;
        }
    }
    noxtls_secure_zero(&actx, sizeof(actx));
    noxtls_secure_zero(last, sizeof(last));
    return rc;
}

/**
 * @brief CTR keystream with pre-incremented counter: for each output block
 *        V = (V + 1) mod 2^128, block = AES(Key, V); the last block is truncated
 *        (SP 800-90A 10.2.1.2 step 2 and 10.2.1.5.1/10.2.1.5.2 step 4).
 *
 * Uses the platform batch hook until it reports NOXTLS_RETURN_NOT_SUPPORTED, then
 * one prepared AES context. Both encrypt the same counter sequence, so the output
 * is identical.
 *
 * @param[in]     key AES key (keylen bytes).
 * @param[in]     aes_type AES key type.
 * @param[in,out] v Counter V; on return the last counter value used.
 * @param[in,out] out Output buffer (written, or XORed with the keystream).
 * @param[in]     out_len Bytes.
 * @param[in]     mode DRBG_CTR_WRITE or DRBG_CTR_XOR.
 *
 * @return NOXTLS_RETURN_SUCCESS, or the AES error (buffer zeroed).
 */
static noxtls_return_t drbg_ctr_output(const uint8_t *key, noxtls_aes_type_t aes_type, uint8_t *v,
                                       uint8_t *out, uint32_t out_len, uint32_t mode)
{
    uint32_t done = 0U;
    noxtls_return_t rc = drbg_ctr_batch(key, aes_type, v, out, out_len, mode, &done);

    if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
        rc = drbg_ctr_soft(key, aes_type, v, &out[done], out_len - done, mode);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, (size_t)out_len);
    }
    return rc;
}

/**
 * @brief CTR_DRBG_Update (SP 800-90A 10.2.1.2).
 *
 * temp = leftmost seedlen bytes of AES(Key, V+1) || AES(Key, V+2) || ...;
 * temp = temp XOR provided_data; Key = leftmost keylen bytes of temp;
 * V = rightmost blocklen bytes of temp. temp is computed in place in @p data.
 *
 * @param[in,out] state DRBG state (Key, V).
 * @param[in]     params Variant lengths.
 * @param[in,out] data seedlen bytes of provided data; zeroed on return.
 *
 * @return NOXTLS_RETURN_SUCCESS, or the AES error (state zeroed).
 */
static noxtls_return_t drbg_update_core(drbg_state_t *state, const drbg_params_t *params, uint8_t *data)
{
    noxtls_return_t rc;

    rc = drbg_ctr_output(state->Key, params->aes_type, state->V, data, params->seedlen, DRBG_CTR_XOR);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(state->Key, sizeof(state->Key), data, (size_t)params->keylen);
        noxtls_copy_u8(state->V, sizeof(state->V), &data[params->keylen], (size_t)DRBG_BLOCKLEN);
    } else {
        noxtls_secure_zero(state, sizeof(*state));
    }
    noxtls_secure_zero(data, (size_t)params->seedlen);
    return rc;
}

/**
 * @brief Absorb one 16-byte block of S into every BCC chain:
 *        chain_j = AES(K, chain_j XOR block) (SP 800-90A 10.3.3 steps 4.1-4.2).
 *
 * @param[in]     ctx Prepared AES context for the df key K.
 * @param[in,out] chains Chaining values, @p chain_count x 16 bytes.
 * @param[in]     chain_count Number of BCC chains.
 * @param[in]     block Input block.
 *
 * @return NOXTLS_RETURN_SUCCESS or the AES error.
 */
static noxtls_return_t drbg_df_bcc_block(const noxtls_aes_context_t *ctx, uint8_t *chains,
                                         uint32_t chain_count, const uint8_t *block)
{
    uint8_t x[DRBG_BLOCKLEN];
    uint32_t j = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    for (j = 0U; (j < chain_count) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
        uint8_t *cv = &chains[(size_t)j * DRBG_BLOCKLEN];
        for (i = 0U; i < DRBG_BLOCKLEN; i += 1U) {
            x[i] = (uint8_t)(cv[i] ^ block[i]);
        }
        rc = noxtls_aes_encrypt_block_ctx_internal(ctx, x, cv);
    }
    noxtls_secure_zero(x, sizeof(x));
    return rc;
}

/**
 * @brief Block_Cipher_df(input_string, seedlen bits) (SP 800-90A 10.3.2).
 *
 * S = L || N || input_string || 0x80 || 0^pad is streamed once through all
 * BCC chains in parallel (chain j starts with IV_j = j || 0^96), so neither
 * the input string nor S is ever buffered.
 *
 * @param[in]  params Variant lengths.
 * @param[in]  input Input string segments (total length checked by the caller).
 * @param[out] out seedlen bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM (length overflow), or the AES error (output zeroed).
 */
static noxtls_return_t drbg_block_cipher_df(const drbg_params_t *params, const drbg_df_input_t *input,
                                            uint8_t *out)
{
    noxtls_aes_context_t actx;
    uint8_t chains[DRBG_DF_MAX_CHAINS * DRBG_BLOCKLEN];
    uint8_t block[DRBG_BLOCKLEN];
    uint32_t chain_count = (params->keylen + DRBG_BLOCKLEN + (DRBG_BLOCKLEN - 1U)) / DRBG_BLOCKLEN;
    uint32_t total = 0U;
    uint32_t fill = 0U;
    uint32_t seg = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    for (seg = 0U; seg < DRBG_DF_MAX_SEGMENTS; seg += 1U) {
        if (input->len[seg] > (0xFFFFFFFFU - total)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        total += input->len[seg];
    }

    /* Steps 7-9: BCC(K, IV_j || S); a zero chaining value XOR IV_j is IV_j. */
    rc = noxtls_aes_prepare_context(&actx, k_drbg_df_key, params->aes_type);
    noxtls_secure_zero(chains, sizeof(chains));
    for (i = 0U; (i < chain_count) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        noxtls_secure_zero(block, sizeof(block));
        block[3] = (uint8_t)i;
        rc = noxtls_aes_encrypt_block_ctx_internal(&actx, block, &chains[(size_t)i * DRBG_BLOCKLEN]);
    }

    /* Steps 1-4: S = L || N || input_string || 0x80, zero padded to a block multiple. */
    block[0] = (uint8_t)(total >> 24U);
    block[1] = (uint8_t)(total >> 16U);
    block[2] = (uint8_t)(total >> 8U);
    block[3] = (uint8_t)total;
    block[4] = (uint8_t)(params->seedlen >> 24U);
    block[5] = (uint8_t)(params->seedlen >> 16U);
    block[6] = (uint8_t)(params->seedlen >> 8U);
    block[7] = (uint8_t)params->seedlen;
    fill = 8U;
    for (seg = 0U; (seg < DRBG_DF_MAX_SEGMENTS) && (rc == NOXTLS_RETURN_SUCCESS); seg += 1U) {
        const uint8_t *data = input->data[seg];
        uint32_t len = input->len[seg];
        for (i = 0U; (i < len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
            block[fill] = data[i];
            fill += 1U;
            if (fill == DRBG_BLOCKLEN) {
                rc = drbg_df_bcc_block(&actx, chains, chain_count, block);
                fill = 0U;
            }
        }
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        block[fill] = 0x80U;
        fill += 1U;
        while (fill < DRBG_BLOCKLEN) {
            block[fill] = 0U;
            fill += 1U;
        }
        rc = drbg_df_bcc_block(&actx, chains, chain_count, block);
    }

    /* Steps 10-15: K = leftmost keylen bytes, X = next block; X = AES(K, X) repeated. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_aes_prepare_context(&actx, chains, params->aes_type);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(block, sizeof(block), &chains[params->keylen], (size_t)DRBG_BLOCKLEN);
        for (i = 0U; (i < params->seedlen) && (rc == NOXTLS_RETURN_SUCCESS); i += DRBG_BLOCKLEN) {
            uint32_t n = ((params->seedlen - i) < DRBG_BLOCKLEN) ? (params->seedlen - i) : DRBG_BLOCKLEN;
            rc = noxtls_aes_encrypt_block_ctx_internal(&actx, block, chains);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_copy_u8(block, sizeof(block), chains, (size_t)DRBG_BLOCKLEN);
                noxtls_copy_u8(&out[i], (size_t)n, block, (size_t)n);
            }
        }
    }

    noxtls_secure_zero(&actx, sizeof(actx));
    noxtls_secure_zero(chains, sizeof(chains));
    noxtls_secure_zero(block, sizeof(block));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, (size_t)params->seedlen);
    }
    return rc;
}

/**
 * @brief Builds seed_material from entropy input and one or two further strings and
 *        applies CTR_DRBG_Update (instantiate 10.2.1.3.x steps 1-6 / reseed 10.2.1.4.x).
 *
 * df variant: seed_material = Block_Cipher_df(entropy || s2 || s3, seedlen).
 * no-df variant: seed_material = entropy XOR (s2 || 0^(seedlen - len(s2))); s3 unused
 * (the caller has checked len(entropy) == seedlen and len(s2) <= seedlen).
 *
 * @param[in,out] work seedlen-byte buffer for seed_material; may be the entropy
 *                buffer itself (the df reads all of its input before writing).
 *                Zeroed on return.
 *
 * @return NOXTLS_RETURN_SUCCESS, or an error (state zeroed).
 */
static noxtls_return_t drbg_seed(drbg_state_t *state, const drbg_params_t *params,
                                 const uint8_t *entropy, uint32_t entropy_len,
                                 const uint8_t *s2, uint32_t s2_len,
                                 const uint8_t *s3, uint32_t s3_len, uint8_t *work)
{
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((state->flags & DRBG_FLAG_NO_DF) != 0U) {
        if (work != entropy) {
            noxtls_copy_u8(work, (size_t)params->seedlen, entropy, (size_t)params->seedlen);
        }
        for (i = 0U; i < s2_len; i += 1U) {
            work[i] ^= s2[i];
        }
    } else {
        drbg_df_input_t in;
        in.data[0] = entropy;
        in.len[0] = entropy_len;
        in.data[1] = s2;
        in.len[1] = s2_len;
        in.data[2] = s3;
        in.len[2] = s3_len;
        rc = drbg_block_cipher_df(params, &in, work);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_update_core(state, params, work);
    } else {
        noxtls_secure_zero(state, sizeof(*state));
        noxtls_secure_zero(work, (size_t)params->seedlen);
    }
    return rc;
}

/**
 * @brief Reads @p entropy_len bytes from the configured entropy source for the DRBG.
 *
 * Rejects a block whose bytes are all equal (stuck source); this is a last-resort
 * sanity check, not an SP 800-90B health test (see noxtls_entropy_cb_t).
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED (buffer zeroed).
 */
static noxtls_return_t drbg_fetch_entropy(uint8_t *entropy_out, uint32_t entropy_len)
{
    noxtls_return_t rc = noxtls_drbg_get_entropy(entropy_out, entropy_len);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        uint32_t i = 0U;
        uint32_t differs = 0U;
        for (i = 1U; i < entropy_len; i += 1U) {
            differs |= (uint32_t)(entropy_out[i] ^ entropy_out[0]);
        }
        if (differs == 0U) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(entropy_out, (size_t)entropy_len);
        rc = NOXTLS_RETURN_FAILED;
    }
    return rc;
}

/**
 * @brief Reseed (SP 800-90A 9.2 / 10.2.1.4) of an instantiated state.
 *
 * @param[in,out] state Instantiated state.
 * @param[in]     params Variant lengths.
 * @param[in]     entropy_input Caller entropy, or NULL to read the entropy source.
 * @param[in]     entropy_input_len Its length.
 * @param[in]     additional_input Additional input (NULL when @p add_input_len is 0).
 * @param[in]     add_input_len Its length.
 *
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_FAILED (entropy source failure) /
 *         NOXTLS_RETURN_NOT_ENOUGH_ENTROPY / NOXTLS_RETURN_INVALID_PARAM with the
 *         state unchanged; or the AES error (state zeroed).
 */
static noxtls_return_t drbg_reseed_internal(drbg_state_t *state, const drbg_params_t *params,
                                            const uint8_t *entropy_input, uint32_t entropy_input_len,
                                            const uint8_t *additional_input, uint32_t add_input_len)
{
    uint8_t entropy[DRBG_SEEDLEN_AES256];
    const uint8_t *ent = entropy_input;
    uint32_t ent_len = entropy_input_len;
    uint32_t no_df = (uint32_t)state->flags & DRBG_FLAG_NO_DF;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((no_df != 0U) && (add_input_len > params->seedlen)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if ((entropy_input == NULL) || (entropy_input_len == 0U)) {
        /* Security strength bits (df) or seedlen bytes of full entropy (no df). */
        ent_len = (no_df != 0U) ? params->seedlen : params->keylen;
        rc = drbg_fetch_entropy(entropy, ent_len);
        ent = entropy;
    } else if (no_df != 0U) {
        if (entropy_input_len < params->seedlen) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
        } else if (entropy_input_len > params->seedlen) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
        } else {
            /* MISRA 15.7: exactly seedlen */
        }
    } else if (entropy_input_len < params->keylen) {
        rc = NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
    } else if (add_input_len > (0xFFFFFFFFU - entropy_input_len)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else {
        /* MISRA 15.7: caller entropy accepted */
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_seed(state, params, ent, ent_len, additional_input, add_input_len, NULL, 0U, entropy);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            state->reseed_counter = 1U;
            state->fork_id = drbg_fork_id();
        }
    }
    noxtls_secure_zero(entropy, sizeof(entropy));
    return rc;
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
 * @param[out] entropy_out Output bytes.
 * @param[in]  entropy_len Number of bytes to fill.
 *
 * @return Always `NOXTLS_RETURN_SUCCESS`.
 */
#ifndef NOXTLS_CUSTOM_ENTROPY_ONLY
static noxtls_return_t drbg_entropy_dummy(uint8_t *entropy_out, uint32_t entropy_out_len)
{
    /* dummy entropy counter (Rule 8.9). */
    static uint32_t dummy_entropy_counter = 0U;

    uint64_t time_seed = (uint64_t)noxtls_time_unix_seconds();
    for (uint32_t i = 0U; i < entropy_out_len; i += 1U) {
        entropy_out[i] = (uint8_t)((dummy_entropy_counter + i + (uint32_t)time_seed) & DRBG_DUMMY_ENTROPY_MASK);
        dummy_entropy_counter += 1U;
        if ((i % DRBG_DUMMY_ENTROPY_STEP) == 0U) {
            time_seed = (time_seed * DRBG_DUMMY_ENTROPY_LCG_MULTIPLIER) + DRBG_DUMMY_ENTROPY_LCG_INCREMENT;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}
#endif

/**
 * @brief Fills @p entropy_len bytes using the configured entropy source and fallbacks.
 *
 * @param[out] entropy_out Caller buffer; must not be NULL.
 * @param[in]  entropy_len Number of bytes to produce.
 *
 * @return `NOXTLS_RETURN_SUCCESS` when bytes are written; `NOXTLS_RETURN_NULL` if @p entropy_out is NULL.
 */
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_out, uint32_t entropy_out_len)
{
    if (entropy_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /*
     * SECURITY (NX-01): a real entropy source failure MUST be a hard failure.
     * The predictable `drbg_entropy_dummy` source is only ever used when the
     * caller has explicitly selected NOXTLS_ENTROPY_SOURCE_DUMMY (tests). Any
     * other source that cannot produce real entropy returns failure so that key
     * and nonce generation aborts instead of silently using guessable bytes.
     */
    switch (g_entropy_source) {
        case NOXTLS_ENTROPY_SOURCE_CUSTOM:
            if (g_entropy_cb != NULL) {
                if (g_entropy_cb(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_SUCCESS;
                }
            }
            return NOXTLS_RETURN_FAILED;
        case NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG:
#if defined(_WIN32) || defined(_WIN64)
            if (get_entropy_windows_bcrypt(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            if (get_entropy_windows_cryptoapi(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
#endif
            return NOXTLS_RETURN_FAILED;
        case NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM:
#if defined(__ZEPHYR__) || defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
            if ((g_entropy_cb) && (g_entropy_cb(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS)) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
#elif !(defined(_WIN32) || defined(_WIN64))
            if (get_entropy_unix(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
#else
            return NOXTLS_RETURN_FAILED;
#endif
        case NOXTLS_ENTROPY_SOURCE_DUMMY:
#if defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
            return NOXTLS_RETURN_FAILED;
#else
            return drbg_entropy_dummy(entropy_out, entropy_out_len);
#endif
        case NOXTLS_ENTROPY_SOURCE_AUTO:
        default:
#if NOXTLS_PORT_ENTROPY_ACCEL
            /* Platform hardware entropy source first (for example a TRNG). */
            if(noxtls_drbg_entropy_accel_port(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
#endif
#if defined(__ZEPHYR__) || defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
            if ((g_entropy_cb) && (g_entropy_cb(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS)) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
#elif defined(_WIN32) || defined(_WIN64)
            if (get_entropy_windows_bcrypt(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            if (get_entropy_windows_cryptoapi(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
#else
            if (get_entropy_unix(entropy_out, entropy_out_len) == NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
#endif
    }
}

/**
 * @brief CTR_DRBG_Update on an instantiated state (NIST SP 800-90A Rev.1 §10.2.1.2).
 *
 * @param[in,out] state Instantiated DRBG state; `Key` and `V` are overwritten.
 * @param[in]     provided_data Provided data; NULL means seedlen zero bytes, shorter data is zero padded.
 * @param[in]     provided_data_len Length of @p provided_data in bytes (at most seedlen).
 *
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL`; `NOXTLS_RETURN_FAILED` (not instantiated);
 *         `NOXTLS_RETURN_INVALID_PARAM` (longer than seedlen); `NOXTLS_RETURN_INVALID_ALGORITHM`; or the AES error (state zeroed).
 */
noxtls_return_t drbg_update(drbg_state_t *state,
                               const uint8_t *provided_data,
                               uint32_t provided_data_len)
{
    uint8_t padded[DRBG_SEEDLEN_AES256];
    drbg_params_t params;
    uint32_t len = (provided_data != NULL) ? provided_data_len : 0U;
    noxtls_return_t rc;

    if (state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (state->instantiated == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (drbg_variant_params((uint32_t)state->aes_type, &params) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (len > params.seedlen) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_secure_zero(padded, sizeof(padded));
    if (len > 0U) {
        noxtls_copy_u8(padded, sizeof(padded), provided_data, (size_t)len);
    }
    rc = drbg_update_core(state, &params, padded);
    return rc;
}

/**
 * @brief Creates a DRBG instance (NIST SP 800-90A Rev.1 §9.1 / §10.2.1.3), derivation-function variant.
 *
 * @return See drbg_instantiate_ex().
 */
noxtls_return_t drbg_instantiate(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_input_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len)
{
    return drbg_instantiate_ex(state, aes_type, 0U, entropy_input, entropy_input_len,
                               nonce, nonce_len, personalization_string, pers_len);
}

/**
 * @brief Creates a DRBG instance (NIST SP 800-90A Rev.1 §9.1 / §10.2.1.3.1 no df / §10.2.1.3.2 df).
 *
 * @param[out] state Output state; zeroed then filled; must not be NULL.
 * @param[in]  aes_type AES-128/192/256 DRBG variant.
 * @param[in]  flags DRBG_FLAG_NO_DF and/or DRBG_FLAG_PREDICTION_RESISTANCE.
 * @param[in]  entropy_input Caller entropy, or NULL (length 0) to read the entropy source.
 * @param[in]  entropy_input_len Length of @p entropy_input.
 * @param[in]  nonce Optional nonce (df variant only).
 * @param[in]  nonce_len Length of @p nonce.
 * @param[in]  personalization_string Optional personalization string.
 * @param[in]  pers_len Length of @p personalization_string.
 *
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL`; `NOXTLS_RETURN_INVALID_ALGORITHM`;
 *         `NOXTLS_RETURN_INVALID_PARAM`; `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY`; `NOXTLS_RETURN_FAILED`
 *         (entropy source); or the AES error. The state is zeroed on any failure.
 */
noxtls_return_t drbg_instantiate_ex(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    uint32_t flags,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_input_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len)
{
    uint8_t entropy[DRBG_SEEDLEN_AES256];
    const uint8_t *ent = entropy_input;
    /* NULL pointer = Null string, whatever the length argument says. */
    uint32_t ent_len = (entropy_input != NULL) ? entropy_input_len : 0U;
    uint32_t n_len = (nonce != NULL) ? nonce_len : 0U;
    uint32_t p_len = (personalization_string != NULL) ? pers_len : 0U;
    drbg_params_t params;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (state == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(state, sizeof(*state));
    if (drbg_variant_params((uint32_t)aes_type, &params) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if ((flags & ~(DRBG_FLAG_NO_DF | DRBG_FLAG_PREDICTION_RESISTANCE)) != 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if ((flags & DRBG_FLAG_NO_DF) != 0U) {
        /* 10.2.1.3.1: no nonce; personalization at most seedlen; seedlen bytes of full entropy. */
        if ((n_len != 0U) || (p_len > params.seedlen) || (ent_len > params.seedlen)) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
        } else if ((ent_len != 0U) && (ent_len < params.seedlen)) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
        } else {
            /* MISRA 15.7: valid no-df inputs */
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) && (ent_len == 0U)) {
            ent_len = params.seedlen;
            rc = drbg_fetch_entropy(entropy, ent_len);
            ent = entropy;
        }
    } else {
        /* 10.2.1.3.2 / 8.6.7: entropy >= security strength, and entropy plus nonce
         * >= 3/2 security strength (a nonce of at least half the strength, or the
         * nonce obtained together with the entropy input as SP 800-90C allows). */
        if (ent_len == 0U) {
            ent_len = params.keylen + (params.keylen / 2U);
            rc = drbg_fetch_entropy(entropy, ent_len);
            ent = entropy;
        } else if ((ent_len < params.keylen) ||
                   ((n_len < (params.keylen / 2U)) && (ent_len < (params.keylen + (params.keylen / 2U))))) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
        } else {
            /* MISRA 15.7: caller entropy accepted */
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) &&
            ((n_len > (0xFFFFFFFFU - ent_len)) || (p_len > (0xFFFFFFFFU - ent_len - n_len)))) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
        }
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        state->aes_type = (uint8_t)aes_type;
        state->flags = (uint8_t)flags;
        /* Key = 0^keylen, V = 0^blocklen (state was zeroed), then Update(seed_material). */
        if ((flags & DRBG_FLAG_NO_DF) != 0U) {
            rc = drbg_seed(state, &params, ent, ent_len, personalization_string, p_len, NULL, 0U, entropy);
        } else {
            rc = drbg_seed(state, &params, ent, ent_len, nonce, n_len, personalization_string, p_len, entropy);
        }
    }
    noxtls_secure_zero(entropy, sizeof(entropy));

    if (rc == NOXTLS_RETURN_SUCCESS) {
        state->reseed_counter = 1U;
        state->fork_id = drbg_fork_id();
        state->instantiated = 1U;
    } else {
        noxtls_secure_zero(state, sizeof(*state));
    }
    return rc;
}

/**
 * @brief Generate algorithm steps 2-7 (SP 800-90A 10.2.1.5.1 / 10.2.1.5.2) after the
 *        caller has validated the request and done any required reseed.
 *
 * @return NOXTLS_RETURN_SUCCESS, or the AES error (output and state zeroed).
 */
static DRBG_NOINLINE noxtls_return_t drbg_generate_core(drbg_state_t *state, const drbg_params_t *params,
                                                        uint8_t *output_buffer, uint32_t requested_bytes,
                                                        const uint8_t *additional_input, uint32_t add_len)
{
    uint8_t add_seed[DRBG_SEEDLEN_AES256];
    uint8_t work[DRBG_SEEDLEN_AES256];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    /* Step 2: additional_input = Block_Cipher_df(additional_input, seedlen) (df) or
     * additional_input || 0^(seedlen - len) (no df); Update. Null input: 0^seedlen. */
    noxtls_secure_zero(add_seed, sizeof(add_seed));
    if (add_len > 0U) {
        if (((uint32_t)state->flags & DRBG_FLAG_NO_DF) != 0U) {
            noxtls_copy_u8(add_seed, sizeof(add_seed), additional_input, (size_t)add_len);
        } else {
            drbg_df_input_t in;
            in.data[0] = additional_input;
            in.len[0] = add_len;
            in.data[1] = NULL;
            in.len[1] = 0U;
            in.data[2] = NULL;
            in.len[2] = 0U;
            rc = drbg_block_cipher_df(params, &in, add_seed);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(state, sizeof(*state));
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(work, sizeof(work), add_seed, (size_t)params->seedlen);
            rc = drbg_update_core(state, params, work);
        }
    }

    /* Steps 3-5: V = V + 1, output AES(Key, V) blocks, leftmost requested bits. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_ctr_output(state->Key, params->aes_type, state->V, output_buffer, requested_bytes, DRBG_CTR_WRITE);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(state, sizeof(*state));
        }
    }

    /* Step 6: (Key, V) = CTR_DRBG_Update(additional_input, Key, V). */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_update_core(state, params, add_seed);
    }
    noxtls_secure_zero(add_seed, sizeof(add_seed));
    noxtls_secure_zero(work, sizeof(work));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output_buffer, (size_t)requested_bytes);
    }
    return rc;
}

/**
 * @brief Generates pseudorandom bits (NIST SP 800-90A Rev.1 §9.3.1 and §10.2.1.5.1 / §10.2.1.5.2).
 *
 * @param[in,out] state Instantiated DRBG; updated and reseed counter incremented.
 * @param[out]    output_buffer Receives `ceil(requested_bits/8)` bytes; a partial last byte keeps the leftmost (most significant) bits.
 * @param[in]     requested_bits Number of random bits to produce (at most `DRBG_MAX_BITS_PER_REQUEST`).
 * @param[in]     additional_input Optional additional input (may be NULL).
 * @param[in]     add_input_len Length of @p additional_input.
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL`; `NOXTLS_RETURN_FAILED` (not instantiated, or the required
 *         reseed could not get entropy); `NOXTLS_RETURN_INVALID_PARAM`; `NOXTLS_RETURN_INVALID_ALGORITHM`; or the AES error
 *         (output and state zeroed).
 */
noxtls_return_t drbg_generate(drbg_state_t *state,
                                 uint8_t *output_buffer,
                                 uint32_t requested_bits,
                                 const uint8_t *additional_input,
                                 uint32_t add_input_len)
{
    drbg_params_t params;
    uint32_t requested_bytes = 0U;
    uint32_t add_len = (additional_input != NULL) ? add_input_len : 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((state == NULL) || (output_buffer == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (state->instantiated == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (requested_bits > DRBG_MAX_BITS_PER_REQUEST) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if (drbg_variant_params((uint32_t)state->aes_type, &params) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if ((((uint32_t)state->flags & DRBG_FLAG_NO_DF) != 0U) && (add_len > params.seedlen)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    requested_bytes = (requested_bits + 7U) >> 3U;

    /* 9.3.1 step 7: reseed first (with the additional input) when the reseed
     * interval is exhausted (10.2.1.5 step 1), for prediction resistance, or in
     * a forked process; the additional input is then consumed. */
    if ((state->reseed_counter > DRBG_RESEED_INTERVAL) ||
        ((state->flags & DRBG_FLAG_PREDICTION_RESISTANCE) != 0U) ||
        (state->fork_id != drbg_fork_id())) {
        rc = drbg_reseed_internal(state, &params, NULL, 0U, additional_input, add_len);
        add_len = 0U;
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate_core(state, &params, output_buffer, requested_bytes, additional_input, add_len);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output_buffer, (size_t)requested_bytes);
        return rc;
    }

    /* Step 7: reseed_counter = reseed_counter + 1. */
    state->reseed_counter += 1U;

    /* Leftmost requested_bits: a partial last byte keeps its high-order bits. */
    if ((requested_bits & 7U) != 0U) {
        output_buffer[requested_bytes - 1U] &= (uint8_t)(0xFFU << (8U - (requested_bits & 7U)));
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reseeds an instantiated DRBG (NIST SP 800-90A Rev.1 §9.2 / §10.2.1.4).
 *
 * @param[in,out] state Live DRBG state; reseed counter reset to 1 on success.
 * @param[in]     entropy_input Caller entropy, or NULL (length 0) to read the entropy source.
 * @param[in]     entropy_input_len Length of @p entropy_input.
 * @param[in]     additional_input Optional additional input (may be NULL).
 * @param[in]     add_input_len Length of @p additional_input.
 *
 * @return `NOXTLS_RETURN_SUCCESS`; `NOXTLS_RETURN_NULL`; `NOXTLS_RETURN_FAILED` (not instantiated or entropy source failure);
 *         `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY` / `NOXTLS_RETURN_INVALID_PARAM`; or the AES error (state zeroed).
 */
noxtls_return_t drbg_reseed(drbg_state_t *state,
                              const uint8_t *entropy_input,
                              uint32_t entropy_input_len,
                              const uint8_t *additional_input,
                              uint32_t add_input_len)
{
    drbg_params_t params;

    if (state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (state->instantiated == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if (drbg_variant_params((uint32_t)state->aes_type, &params) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return drbg_reseed_internal(state, &params, entropy_input, entropy_input_len, additional_input,
                                (additional_input != NULL) ? add_input_len : 0U);
}

/**
 * @brief Zeroes and invalidates DRBG state (SP 800-90A §9.4; safe on an unused or active instance).
 *
 * @param[in,out] state State buffer to clear; must not be NULL.
 *
 * @return `NOXTLS_RETURN_SUCCESS` after clearing; `NOXTLS_RETURN_NULL` if @p state is NULL.
 */
noxtls_return_t noxtls_drbg_uninstantiate(drbg_state_t *state)
{
    if (state == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* SECURITY (NX-10): securely wipe DRBG secret state (Key/V) so it cannot be
     * recovered from freed/stack memory; plain memset may be optimized away. */
    (void)noxtls_secure_zero(state, sizeof(drbg_state_t));

    return NOXTLS_RETURN_SUCCESS;
}
