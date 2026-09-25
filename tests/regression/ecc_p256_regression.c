/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_ecdh.h"

static int hex_nibble(char value)
{
    if(value >= '0' && value <= '9') {
        return value - '0';
    }
    if(value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if(value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int decode_hex(uint8_t *output, uint32_t output_size, const char *hex)
{
    uint32_t i;

    if(output == NULL || hex == NULL || strlen(hex) != (size_t)output_size * 2U) {
        return 0;
    }
    for(i = 0U; i < output_size; i++) {
        int high = hex_nibble(hex[i * 2U]);
        int low = hex_nibble(hex[i * 2U + 1U]);
        if(high < 0 || low < 0) {
            return 0;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static int load_point(ecc_point_t *point, const char *x_hex, const char *y_hex)
{
    memset(point, 0, sizeof(*point));
    point->size = 32U;
    return decode_hex(point->x, 32U, x_hex) && decode_hex(point->y, 32U, y_hex);
}

static int check_multiply(const ecc_curve_params_t *curve,
                          const char *name,
                          const char *scalar_hex,
                          const char *expected_x_hex,
                          const char *expected_y_hex)
{
    uint8_t scalar[32];
    ecc_point_t actual;
    ecc_point_t expected;
    noxtls_return_t rc;

    memset(&actual, 0, sizeof(actual));
    if(!decode_hex(scalar, sizeof(scalar), scalar_hex) ||
       !load_point(&expected, expected_x_hex, expected_y_hex)) {
        printf("FAIL %s: malformed test vector\n", name);
        return 0;
    }

    rc = noxtls_ecc_point_multiply(&actual, scalar, &curve->G, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("FAIL %s: multiply returned %d\n", name, (int)rc);
        return 0;
    }
    if(actual.size != 32U || memcmp(actual.x, expected.x, 32U) != 0 ||
       memcmp(actual.y, expected.y, 32U) != 0) {
        printf("FAIL %s: unexpected public point\n", name);
        return 0;
    }
    if(noxtls_ecc_point_validate_public(&actual, curve) != NOXTLS_RETURN_SUCCESS) {
        printf("FAIL %s: known-good result was rejected\n", name);
        return 0;
    }
    printf("PASS %s\n", name);
    return 1;
}

int main(void)
{
    static const char scalar_two[] =
        "0000000000000000000000000000000000000000000000000000000000000002";
    static const char scalar_dense[] =
        "519b423d715f8b5d5495e9c3f4f0f6e8e5b26de9bc12c3594a8f866c94f96878";
    ecc_curve_params_t curve;
    ecc_point_t captured_invalid;
    ecc_key_t local_key;
    ecc_point_t local_before;
    uint8_t dense_scalar[32];
    uint8_t shared_secret[32];
    uint32_t shared_secret_len = sizeof(shared_secret);
    int passed = 1;

    memset(&curve, 0, sizeof(curve));
    if(noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
        printf("FAIL curve initialization\n");
        return 1;
    }

    passed &= check_multiply(&curve,
                             "P-256 scalar 2",
                             scalar_two,
                             "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
                             "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
    passed &= check_multiply(&curve,
                             "P-256 dense scalar",
                             scalar_dense,
                             "f38659b4201fae0cafc60429e337794c4e4e10b07cd318847cb0ffad1b00d219",
                             "63d110d1580609fa6068e3e99db0b51d1ff4a3129eb74d664a0990fe9315f349");

    memset(&local_key, 0, sizeof(local_key));
    memset(&local_before, 0, sizeof(local_before));
    memset(shared_secret, 0, sizeof(shared_secret));
    if(!decode_hex(dense_scalar, sizeof(dense_scalar), scalar_dense) ||
       !load_point(&local_key.Q,
                   "f38659b4201fae0cafc60429e337794c4e4e10b07cd318847cb0ffad1b00d219",
                   "63d110d1580609fa6068e3e99db0b51d1ff4a3129eb74d664a0990fe9315f349")) {
        printf("FAIL ECDH preserves local public key: malformed test vector\n");
        passed = 0;
    } else {
        local_key.d = dense_scalar;
        local_key.curve = &curve;
        memcpy(&local_before, &local_key.Q, sizeof(local_before));
        if(noxtls_ecdh_compute_shared_secret(&local_key, &local_key.Q,
                                             shared_secret,
                                             &shared_secret_len) !=
               NOXTLS_RETURN_SUCCESS ||
           shared_secret_len != sizeof(shared_secret) ||
           memcmp(&local_key.Q, &local_before, sizeof(local_before)) != 0 ||
           noxtls_ecc_point_validate_public(&local_key.Q, &curve) !=
               NOXTLS_RETURN_SUCCESS) {
            printf("FAIL ECDH preserves local public key\n");
            passed = 0;
        } else {
            printf("PASS ECDH preserves local public key\n");
        }
    }

    if(!load_point(&captured_invalid,
                   "116c223489a332f6cc8f5416f6ba57b092e9732803af80249b57a1345dba63e9",
                   "5cc0efc17bae7933ce8110d690d35401d11029f187322f0089ebfb99d8d9b392")) {
        printf("FAIL captured off-curve point: malformed test vector\n");
        passed = 0;
    } else if(noxtls_ecc_point_validate_public(&captured_invalid, &curve) == NOXTLS_RETURN_SUCCESS) {
        printf("FAIL captured off-curve point: validator accepted it\n");
        passed = 0;
    } else {
        printf("PASS captured off-curve point rejected\n");
    }

    (void)noxtls_ecc_curve_free(&curve);
    return passed ? 0 : 1;
}
