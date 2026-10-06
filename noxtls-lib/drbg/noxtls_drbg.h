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

/* DRBG Constants per NIST SP 800-90A */
#define DRBG_SEEDLEN_AES128  32  /* 256 bits */
#define DRBG_SEEDLEN_AES192  40  /* 320 bits */
#define DRBG_SEEDLEN_AES256  48  /* 384 bits */

#define DRBG_KEYLEN_AES128   16  /* 128 bits */
#define DRBG_KEYLEN_AES192   24  /* 192 bits */
#define DRBG_KEYLEN_AES256   32  /* 256 bits */

#define DRBG_BLOCKLEN        16U  /* 128 bits (AES block size) */

/* Maximum reseed counter (2^48 for AES-256) */
#define DRBG_RESEED_INTERVAL 0xFFFFFFFFFFFFULL

/* Maximum number of bits per request (2^19 bits = 65536 bytes) */
#define DRBG_MAX_BITS_PER_REQUEST 524288U

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

typedef noxtls_return_t (*noxtls_entropy_cb_t)(uint8_t *entropy_cb_out, uint32_t entropy_cb_out_len);

typedef struct
{
    uint8_t V[DRBG_BLOCKLEN];        /* Current value (counter) */
    uint8_t Key[DRBG_KEYLEN_AES256];  /* Current key (max size for all variants) */
    uint64_t reseed_counter;          /* Reseed counter */
    drbg_aes_type_t aes_type;         /* AES variant (128/192/256) */
    uint32_t seedlen;                 /* Seed length for this variant */
    uint32_t keylen;                  /* Key length for this variant */
    int instantiated;                 /* Flag indicating if DRBG is instantiated */
} drbg_state_t;

/**
 * @brief Get entropy input (dummy implementation for now)
 * 
 * @param entropy_buffer Output buffer for entropy
 * @param entropy_len Required entropy length in bytes
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_out, uint32_t entropy_out_len);

/**
 * @brief Optional platform hook: fill a buffer from a hardware entropy source.
 *
 * Implemented by the selected accelerator port when NOXTLS_PORT_ENTROPY_ACCEL is
 * set (common/noxtls_accel_port.h); used by NOXTLS_ENTROPY_SOURCE_AUTO before
 * the operating-system sources.
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
 * @brief Instantiate the DRBG
 * 
 * Per NIST SP 800-90A Section 10.2.1.2
 * 
 * @param state DRBG state structure
 * @param aes_type AES variant (128/192/256)
 * @param entropy_input Entropy input (can be NULL, will use dummy entropy)
 * @param entropy_len Length of entropy input
 * @param nonce Nonce (can be NULL)
 * @param nonce_len Length of nonce
 * @param personalization_string Personalization string (can be NULL)
 * @param pers_len Length of personalization string
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
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
 * @brief Generate random bits
 * 
 * Per NIST SP 800-90A Section 10.2.1.3
 * 
 * @param state DRBG state structure
 * @param output_buffer Output buffer for random bits
 * @param requested_bits Number of bits to generate
 * @param additional_input Additional input (can be NULL)
 * @param add_input_len Length of additional input
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t drbg_generate(drbg_state_t *state,
                                 uint8_t *output_buffer,
                                 uint32_t requested_bits,
                                 const uint8_t *additional_input,
                                 uint32_t add_input_len);

/**
 * @brief Reseed the DRBG
 * 
 * Per NIST SP 800-90A Section 10.2.1.4
 * 
 * @param state DRBG state structure
 * @param entropy_input Entropy input (can be NULL, will use dummy entropy)
 * @param entropy_len Length of entropy input
 * @param additional_input Additional input (can be NULL)
 * @param add_input_len Length of additional input
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t drbg_reseed(drbg_state_t *state,
                              const uint8_t *entropy_input,
                              uint32_t entropy_input_len,
                              const uint8_t *additional_input,
                              uint32_t add_input_len);

/**
 * @brief Update the DRBG state
 * 
 * Per NIST SP 800-90A Section 10.2.1.2 (Update function)
 * 
 * @param state DRBG state structure
 * @param provided_data Provided data for update
 * @param provided_data_len Length of provided data
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t drbg_update(drbg_state_t *state,
                               const uint8_t *provided_data,
                               uint32_t provided_data_len);

/**
 * @brief Uninstantiate the DRBG (clear state)
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