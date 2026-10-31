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
* File:    noxtls_drbg.h
* Summary: Deterministic Random Bit Generator (DRBG) - AES-CTR-DRBG per NIST SP 800-90A
*
*****************************************************************************/

/** @addtogroup noxtls_drbg */
/** @{ */

#ifndef NOXTLS_DRBG_H_
#define NOXTLS_DRBG_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CTR_DRBG per NIST SP 800-90A Rev.1 section 10.2.1 with AES-128/192/256
 * (security strength = key length, seedlen = keylen + blocklen, ctr_len =
 * blocklen). Two variants:
 *  - with Block_Cipher_df (default, drbg_instantiate()): for entropy sources
 *    that are not full-entropy sources; accepts nonce, personalization string
 *    and additional input of any length;
 *  - without derivation function (drbg_instantiate_ex(..., DRBG_FLAG_NO_DF, ...)):
 *    entropy input must be seedlen bytes of FULL entropy.
 * Optional prediction resistance (DRBG_FLAG_PREDICTION_RESISTANCE).
 */

/* DRBG constants per NIST SP 800-90A Rev.1 Table 3 */
#define DRBG_SEEDLEN_AES128  32  /* 256 bits */
#define DRBG_SEEDLEN_AES192  40  /* 320 bits */
#define DRBG_SEEDLEN_AES256  48  /* 384 bits */

#define DRBG_KEYLEN_AES128   16  /* 128 bits = security strength of the AES-128 DRBG */
#define DRBG_KEYLEN_AES192   24  /* 192 bits */
#define DRBG_KEYLEN_AES256   32  /* 256 bits */

#define DRBG_BLOCKLEN        16U  /* 128 bits (AES block size) */

/* Maximum number of generate requests between reseeds (SP 800-90A Table 3:
 * reseed_interval <= 2^48). When reseed_counter exceeds it, drbg_generate()
 * first reseeds from the entropy source (SP 800-90A section 9.3.1 step 7).
 * May be lowered with -D. */
#ifndef DRBG_RESEED_INTERVAL
#define DRBG_RESEED_INTERVAL 0x1000000000000ULL
#endif

/* Maximum number of bits per request (SP 800-90A Table 3: 2^19 bits = 65536 bytes) */
#define DRBG_MAX_BITS_PER_REQUEST 524288U

/* drbg_instantiate_ex() flags, fixed for the life of the instantiation. */
/* No derivation function (SP 800-90A 10.2.1.3.1 / 10.2.1.4.1 / 10.2.1.5.1). */
#define DRBG_FLAG_NO_DF                  (0x01U)
/* Prediction resistance (SP 800-90A 9.3.1): every drbg_generate() call first
 * reseeds from the entropy source with the request's additional input. */
#define DRBG_FLAG_PREDICTION_RESISTANCE  (0x02U)

/* Dummy entropy generator constants */
#define DRBG_DUMMY_ENTROPY_MASK           (0xFFu)
#define DRBG_DUMMY_ENTROPY_STEP           (8U)
#define DRBG_DUMMY_ENTROPY_LCG_MULTIPLIER (1103515245ULL)
#define DRBG_DUMMY_ENTROPY_LCG_INCREMENT  (12345ULL)

typedef uint32_t drbg_aes_type_t;
#define DRBG_AES128 ((drbg_aes_type_t)0U)  /* Security strength: 128 bits */
#define DRBG_AES192 ((drbg_aes_type_t)1U)  /* Security strength: 192 bits */
#define DRBG_AES256 ((drbg_aes_type_t)2U)  /* Security strength: 256 bits */

typedef uint32_t noxtls_entropy_source_t;
#define NOXTLS_ENTROPY_SOURCE_AUTO            ((noxtls_entropy_source_t)0U)
#define NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG  ((noxtls_entropy_source_t)1U)
#define NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM    ((noxtls_entropy_source_t)2U)
#define NOXTLS_ENTROPY_SOURCE_CUSTOM          ((noxtls_entropy_source_t)3U)
#define NOXTLS_ENTROPY_SOURCE_DUMMY           ((noxtls_entropy_source_t)4U)

/**
 * @brief Entropy source callback (NOXTLS_ENTROPY_SOURCE_CUSTOM; the AUTO source on
 *        Zephyr and NOXTLS_CUSTOM_ENTROPY_ONLY builds).
 *
 * Contract for ports (the DRBG's entropy input, SP 800-90A section 8.6.3 / SP 800-90C):
 *  - Fill exactly @p entropy_cb_out_len bytes and return NOXTLS_RETURN_SUCCESS, or
 *    return another code (the DRBG then fails closed). Never report success for
 *    fewer, stale or repeated bytes.
 *  - Every byte must carry full entropy (8 bits of min-entropy per byte): output
 *    of an OS CSPRNG, of an SP 800-90B validated conditioned source, or of a raw
 *    TRNG that the port has conditioned / oversampled. Requests are
 *    security_strength bits (keylen bytes) per reseed, 3/2 x security_strength
 *    per instantiation (entropy input and nonce obtained in one request, as
 *    SP 800-90C allows), or seedlen bytes for the no-df variant.
 *  - Noise-source health tests (SP 800-90B section 4.4 repetition count and
 *    adaptive proportion tests, start-up tests) are the port's responsibility.
 *    The library only rejects a block whose bytes are all equal (stuck source).
 *  - It may be called from every context that draws random bits (TLS handshakes,
 *    key generation, signing, reseeds) and must be thread-safe if those are.
 */
typedef noxtls_return_t (*noxtls_entropy_cb_t)(uint8_t *entropy_cb_out, uint32_t entropy_cb_out_len);

/* Fork detection (hosted POSIX): an instantiation records getpid(); a generate
 * call in another process reseeds from the entropy source first, so a forked
 * child never repeats its parent's output. */
#ifndef NOXTLS_DRBG_FORK_DETECT
#if (defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))) && \
    !defined(__ZEPHYR__) && !defined(NOXTLS_CUSTOM_ENTROPY_ONLY)
#define NOXTLS_DRBG_FORK_DETECT 1
#else
#define NOXTLS_DRBG_FORK_DETECT 0
#endif
#endif

/* Seed and key lengths are derived from aes_type, not stored (64 bytes). */
typedef struct
{
    uint8_t V[DRBG_BLOCKLEN];        /* Current value (counter) */
    uint8_t Key[DRBG_KEYLEN_AES256];  /* Current key (max size for all variants) */
    uint64_t reseed_counter;          /* Reseed counter (SP 800-90A 10.2.1.1) */
    uint8_t aes_type;                 /* drbg_aes_type_t value (DRBG_AES128/192/256) */
    uint8_t instantiated;             /* Non-zero once instantiated; 0 after uninstantiate or a fatal error */
    uint8_t flags;                    /* DRBG_FLAG_* selected at instantiation */
    uint8_t reserved;                 /* Zero */
    uint32_t fork_id;                 /* getpid() at the last (re)seed with NOXTLS_DRBG_FORK_DETECT, else 0 */
} drbg_state_t;

/**
 * @brief Get entropy input from the configured source (see noxtls_drbg_set_entropy_source()).
 *
 * @param entropy_out Output buffer for entropy
 * @param entropy_out_len Required entropy length in bytes
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or NOXTLS_RETURN_FAILED when the
 *         selected source cannot deliver (never falls back to predictable bytes)
 */
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_out, uint32_t entropy_out_len);

/**
 * @brief Optional platform hook: fill a buffer from a hardware entropy source.
 *
 * Implemented by the selected accelerator port when NOXTLS_PORT_ENTROPY_ACCEL is
 * set (common/noxtls_accel_port.h); used by NOXTLS_ENTROPY_SOURCE_AUTO before
 * the operating-system sources. Same contract as noxtls_entropy_cb_t.
 *
 * @param[out] entropy_buffer Destination.
 * @param[in]  entropy_len    Bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED when the hardware cannot serve the request.
 */
noxtls_return_t noxtls_drbg_entropy_accel_port(uint8_t *entropy_buffer, uint32_t entropy_len);

void noxtls_drbg_set_entropy_source(noxtls_entropy_source_t source);
noxtls_entropy_source_t noxtls_drbg_get_entropy_source(void);
void noxtls_drbg_set_entropy_callback(noxtls_entropy_cb_t cb);
noxtls_entropy_cb_t noxtls_drbg_get_entropy_callback(void);

/**
 * @brief Instantiate the DRBG (derivation-function variant, no prediction resistance).
 *
 * Same as drbg_instantiate_ex(state, aes_type, 0U, ...): NIST SP 800-90A Rev.1
 * section 10.2.1.3.2, seed_material = Block_Cipher_df(entropy_input || nonce ||
 * personalization_string, seedlen).
 *
 * @param state DRBG state structure
 * @param aes_type AES variant (128/192/256)
 * @param entropy_input Entropy input, or NULL (length 0) to draw 3/2 x security
 *        strength bits from noxtls_drbg_get_entropy()
 * @param entropy_input_len Length in bytes: at least the security strength (keylen
 *        bytes), and at least 3/2 x keylen bytes when no nonce of at least keylen/2
 *        bytes is given
 * @param nonce Nonce (can be NULL)
 * @param nonce_len Length of nonce
 * @param personalization_string Personalization string (can be NULL)
 * @param pers_len Length of personalization string
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL; NOXTLS_RETURN_INVALID_ALGORITHM;
 *         NOXTLS_RETURN_NOT_ENOUGH_ENTROPY (entropy input too short);
 *         NOXTLS_RETURN_INVALID_PARAM (bad flags or lengths); NOXTLS_RETURN_FAILED
 *         (entropy source failure); or the AES error. On failure the state is zeroed.
 */
noxtls_return_t drbg_instantiate(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_input_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len);

/**
 * @brief Instantiate the DRBG with options (NIST SP 800-90A Rev.1 section 10.2.1.3).
 *
 * @param flags 0, DRBG_FLAG_NO_DF and/or DRBG_FLAG_PREDICTION_RESISTANCE. With
 *        DRBG_FLAG_NO_DF the entropy input must be NULL (seedlen bytes are drawn
 *        from the entropy source, which must then be a full-entropy source) or
 *        exactly seedlen bytes of full entropy, the nonce must be NULL, and the
 *        personalization string at most seedlen bytes.
 * Other parameters and return values: see drbg_instantiate().
 */
noxtls_return_t drbg_instantiate_ex(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    uint32_t flags,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_input_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len);

/**
 * @brief Generate random bits
 *
 * NIST SP 800-90A Rev.1 section 10.2.1.5 (Generate algorithm) inside the 9.3.1
 * Generate function: reseeds from the entropy source first when the reseed
 * interval is exhausted, when the instance has prediction resistance, or (with
 * NOXTLS_DRBG_FORK_DETECT) in a forked process.
 *
 * @param state DRBG state structure
 * @param output_buffer Output buffer of (requested_bits + 7) / 8 bytes; a partial
 *        last byte holds the trailing bits in its most significant bits, the rest zero
 * @param requested_bits Number of bits to generate (at most DRBG_MAX_BITS_PER_REQUEST)
 * @param additional_input Additional input (can be NULL); processed by the
 *        derivation function or, for the no-df variant, at most seedlen bytes
 *        (zero padded)
 * @param add_input_len Length of additional input
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL; NOXTLS_RETURN_FAILED (not
 *         instantiated, or a required reseed could not obtain entropy: state
 *         unchanged); NOXTLS_RETURN_INVALID_PARAM (request or additional input too
 *         large); or the AES error, after which output and state are zeroed
 *         (the instance must be instantiated again).
 */
noxtls_return_t drbg_generate(drbg_state_t *state,
                                 uint8_t *output_buffer,
                                 uint32_t requested_bits,
                                 const uint8_t *additional_input,
                                 uint32_t add_input_len);

/**
 * @brief Reseed the DRBG
 *
 * NIST SP 800-90A Rev.1 section 10.2.1.4.
 *
 * @param state DRBG state structure
 * @param entropy_input Entropy input, or NULL (length 0) to draw security strength
 *        bits (seedlen bytes for the no-df variant) from noxtls_drbg_get_entropy()
 * @param entropy_input_len At least keylen bytes (df variant), exactly seedlen
 *        bytes (no-df variant)
 * @param additional_input Additional input (can be NULL); at most seedlen bytes for
 *        the no-df variant
 * @param add_input_len Length of additional input
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL; NOXTLS_RETURN_FAILED (not
 *         instantiated or entropy source failure: state unchanged);
 *         NOXTLS_RETURN_NOT_ENOUGH_ENTROPY / NOXTLS_RETURN_INVALID_PARAM (lengths:
 *         state unchanged); or the AES error (state zeroed).
 */
noxtls_return_t drbg_reseed(drbg_state_t *state,
                              const uint8_t *entropy_input,
                              uint32_t entropy_input_len,
                              const uint8_t *additional_input,
                              uint32_t add_input_len);

/**
 * @brief Update the DRBG state
 *
 * CTR_DRBG_Update (NIST SP 800-90A Rev.1 section 10.2.1.2) on an instantiated
 * state. Low-level primitive used by instantiate / reseed / generate.
 *
 * @param state Instantiated DRBG state structure
 * @param provided_data Provided data; NULL means seedlen zero bytes, a shorter
 *        buffer is zero padded to seedlen
 * @param provided_data_len Length of provided data (at most seedlen)
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL; NOXTLS_RETURN_FAILED (not
 *         instantiated); NOXTLS_RETURN_INVALID_PARAM (longer than seedlen); or the
 *         AES error (state zeroed)
 */
noxtls_return_t drbg_update(drbg_state_t *state,
                               const uint8_t *provided_data,
                               uint32_t provided_data_len);

/**
 * @brief Uninstantiate the DRBG (SP 800-90A section 9.4): zeroize the whole state.
 *
 * @param state DRBG state structure
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_drbg_uninstantiate(drbg_state_t *state);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_DRBG_H_ */

/** @} */
