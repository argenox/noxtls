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
* File:    noxtls_aria.h
* Summary: ARIA Block Cipher Algorithm
*
* ARIA is a block cipher developed in South Korea, standardized in RFC 5794.
* It supports 128, 192, and 256-bit keys with a 128-bit block size.
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_ARIA_H_
#define _NOXTLS_ARIA_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_ARIA_DEBUG (0)

#define ARIA_128_ROUNDS 12
#define ARIA_192_ROUNDS 14
#define ARIA_256_ROUNDS 16

#define ARIA_BLOCK_LENGTH 16

typedef enum
{
	ARIA_128_BIT = 0,
	ARIA_192_BIT = 1,
	ARIA_256_BIT = 2,
} aria_type_t;

typedef enum
{
	ARIA_ECB = 0,
	ARIA_CBC = 1,
	ARIA_CTR = 2,
	ARIA_CFB = 3,
	ARIA_OFB = 4,
} aria_mode_t;

typedef enum
{
    ARIA_OP_ENCRYPT = 0,
    ARIA_OP_DECRYPT = 1,
} aria_operation_t;

/* ARIA Key Schedule Structure */
typedef struct
{
	uint8_t round_key[17][16];  /* Round keys (max 16 rounds + 1 initial key) */
	int rounds;                  /* Number of rounds */
	aria_type_t key_type;        /* Key size type */
} aria_key_t;

typedef struct
{
    uint8_t key[32];
    uint8_t feedback[ARIA_BLOCK_LENGTH];
    uint8_t partial[ARIA_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    aria_type_t type;
    aria_mode_t mode;
    aria_operation_t op;
    uint8_t initialized;
    aria_key_t enc_key;
    aria_key_t dec_key;
} aria_context_t;

/* Core ARIA Functions */
noxtls_return_t aria_set_encrypt_key(const uint8_t *user_key, aria_type_t key_type, aria_key_t *key);
noxtls_return_t aria_set_decrypt_key(const uint8_t *user_key, aria_type_t key_type, aria_key_t *key);
void aria_encrypt_block(const aria_key_t *key, const uint8_t in[16], uint8_t out[16]);
void aria_decrypt_block(const aria_key_t *key, const uint8_t in[16], uint8_t out[16]);

/* High-level ARIA Functions */
noxtls_return_t aria_encrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      aria_type_t type,
                      aria_mode_t mode);

noxtls_return_t aria_decrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      aria_type_t type,
                      aria_mode_t mode);

noxtls_return_t aria_self_test(void);

/* ARIA Mode-Specific Functions */
noxtls_return_t aria_encrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type);

noxtls_return_t aria_decrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type);

noxtls_return_t aria_init(aria_context_t *ctx,
              const uint8_t *key,
              const uint8_t *iv,
              aria_type_t type,
              aria_mode_t mode,
              aria_operation_t op);

noxtls_return_t aria_update(aria_context_t *ctx,
                const uint8_t *input,
                uint32_t input_len,
                uint8_t *output,
                uint32_t *output_len);

noxtls_return_t aria_final(aria_context_t *ctx,
               uint8_t *output,
               uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ARIA_H_ */

