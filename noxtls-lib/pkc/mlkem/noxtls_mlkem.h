/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_mlkem.h
* Summary: ML-KEM (NIST FIPS 203) API surface.
*
 * NOTE:
 * This header intentionally keeps stable API and size contracts across
 * implementation improvements.
*/

#ifndef _NOXTLS_MLKEM_H_
#define _NOXTLS_MLKEM_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    NOXTLS_MLKEM_512 = 1,
    NOXTLS_MLKEM_768 = 2,
    NOXTLS_MLKEM_1024 = 3
} noxtls_mlkem_param_t;

#define NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN 1568u
#define NOXTLS_MLKEM_MAX_SECRET_KEY_LEN 3168u
#define NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN 1568u
#define NOXTLS_MLKEM_SHARED_SECRET_LEN 32u

uint32_t noxtls_mlkem_public_key_len(noxtls_mlkem_param_t param);
uint32_t noxtls_mlkem_secret_key_len(noxtls_mlkem_param_t param);
uint32_t noxtls_mlkem_ciphertext_len(noxtls_mlkem_param_t param);

noxtls_return_t noxtls_mlkem_keygen(noxtls_mlkem_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
noxtls_return_t noxtls_mlkem_encaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);
noxtls_return_t noxtls_mlkem_decaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *secret_key,
                                    const uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);

/* Test-only deterministic hook for vector conformance harnesses. */
void noxtls_mlkem_set_test_random_sequence(const uint8_t *bytes, uint32_t byte_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_MLKEM_H_ */
