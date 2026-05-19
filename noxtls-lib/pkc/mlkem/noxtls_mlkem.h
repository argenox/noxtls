/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
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
    NOXTLS_MLKEM_NONE = 0,
    NOXTLS_MLKEM_512 = 1,
    NOXTLS_MLKEM_768 = 2,
    NOXTLS_MLKEM_1024 = 3
} noxtls_mlkem_param_t;

#define NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN 1568u
#define NOXTLS_MLKEM_MAX_SECRET_KEY_LEN 3168u
#define NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN 1568u
#define NOXTLS_MLKEM_SHARED_SECRET_LEN 32u

#define MLKEM_Q 3329
#define MLKEM_N 256
#define MLKEM_MAX_K 4
#define MLKEM_POLY12_BYTES 384u
#define MLKEM_QINV (-3327)

typedef struct
{
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
    uint8_t du;
    uint8_t dv;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t ciphertext_len;
} mlkem_params_t;

typedef struct
{
    int16_t c[MLKEM_N];
} mlkem_poly_t;

typedef struct
{
    mlkem_poly_t v[MLKEM_MAX_K];
} mlkem_polyvec_t;


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
