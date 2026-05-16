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
* File:    noxtls_drbg.h
* Summary: Deterministic Random Bit Generator (DRBG) - AES-CTR-DRBG per NIST SP 800-90A
*
*/

#ifndef _NOXTLS_DRBG_H_
#define _NOXTLS_DRBG_H_

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

#define DRBG_BLOCKLEN        16  /* 128 bits (AES block size) */

/* Maximum reseed counter (2^48 for AES-256) */
#define DRBG_RESEED_INTERVAL 0xFFFFFFFFFFFFULL

/* Maximum number of bits per request (2^19 bits = 65536 bytes) */
#define DRBG_MAX_BITS_PER_REQUEST 524288

/* Dummy entropy generator constants */
#define DRBG_DUMMY_ENTROPY_MASK           (0xFFu)
#define DRBG_DUMMY_ENTROPY_STEP           (8u)
#define DRBG_DUMMY_ENTROPY_LCG_MULTIPLIER (1103515245ULL)
#define DRBG_DUMMY_ENTROPY_LCG_INCREMENT  (12345ULL)

typedef enum
{
    DRBG_AES128 = 0,  /* Security strength: 128 bits */
    DRBG_AES192 = 1,  /* Security strength: 192 bits */
    DRBG_AES256 = 2,  /* Security strength: 256 bits */
} drbg_aes_type_t;

typedef enum
{
    NOXTLS_ENTROPY_SOURCE_AUTO = 0,
    NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG = 1,
    NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM = 2,
    NOXTLS_ENTROPY_SOURCE_CUSTOM = 3,
    NOXTLS_ENTROPY_SOURCE_DUMMY = 4,
} noxtls_entropy_source_t;

typedef noxtls_return_t (*noxtls_entropy_cb_t)(uint8_t *entropy_buffer, uint32_t entropy_len);

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
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_buffer, uint32_t entropy_len);

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
                                    uint32_t entropy_len,
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
                              uint32_t entropy_len,
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

#endif /* _NOXTLS_DRBG_H_ */


