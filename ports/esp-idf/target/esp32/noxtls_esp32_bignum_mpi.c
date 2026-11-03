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
* File:    noxtls_esp32_bignum_mpi.c
* Summary: ESP-IDF hardware MPI for NoxTLS P-256 field arithmetic (mod, mod_exp).
*
* Uses the ESP-IDF mbedtls MPI layer (esp_bignum / PKC peripheral) for modular
* math only. NoxTLS does not use mbedtls for TLS or ECDSA logic.
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_bn_platform.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#include "noxtls_esp_hw_accel.h"

#if CONFIG_NOXTLS_ESP_HW_MPI

#include "mbedtls/bignum.h"

#if defined(CONFIG_MBEDTLS_HARDWARE_MPI) && CONFIG_MBEDTLS_HARDWARE_MPI

#define NOXTLS_ESP_MPI_P256_LEN 32U

/*
 * Operands and results live in per-call mbedtls_mpi objects that are freed
 * (mbedtls_mpi_free zeroizes the limbs) on every exit. Nothing is shared
 * between calls or tasks, so no operand, reduction result or ECDH secret is
 * retained after the hook returns. ESP-IDF serializes the MPI peripheral
 * itself inside the mbedtls hardware MPI layer.
 */

/**
 * @brief Write the fixed value to the ESP hardware MPI
 *
 * @param[in] mpi The MPI to write the fixed value to
 * @param[out] out The output to write the fixed value to
 * @param[in] out_len The length of the output to write the fixed value to
 * @return The return code
 */
static noxtls_return_t noxtls_esp_mpi_write_fixed(const mbedtls_mpi *mpi,
                                                    uint8_t *out,
                                                    uint32_t out_len)
{
    int rc;

    if(mpi == NULL || out == NULL || out_len == 0U) {
        return NOXTLS_RETURN_NULL;
    }

    if(mbedtls_mpi_size(mpi) > out_len) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(out, 0, out_len);
    rc = mbedtls_mpi_write_binary(mpi, out, out_len);
    if(rc != 0) {
        noxtls_secure_zero(out, out_len);
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Mod the P-256 value
 *
 * @param[out] result The result of the mod operation
 * @param[in] a The value to mod
 * @param[in] a_len The length of the value to mod
 * @param[in] mod The modulus to mod the value by
 * @param[in] mod_len The length of the modulus to mod the value by
 * @return The return code
 */
static noxtls_return_t noxtls_esp_mpi_mod_p256(uint8_t *result,
                                               const uint8_t *a,
                                               uint32_t a_len,
                                               const uint8_t *mod,
                                               uint32_t mod_len)
{
    mbedtls_mpi mpi_a;
    mbedtls_mpi mpi_m;
    mbedtls_mpi mpi_r;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(result == NULL || a == NULL || mod == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(mod_len != NOXTLS_ESP_MPI_P256_LEN) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    mbedtls_mpi_init(&mpi_a);
    mbedtls_mpi_init(&mpi_m);
    mbedtls_mpi_init(&mpi_r);

    if((mbedtls_mpi_read_binary(&mpi_a, a, a_len) == 0) &&
       (mbedtls_mpi_read_binary(&mpi_m, mod, mod_len) == 0) &&
       (mbedtls_mpi_mod_mpi(&mpi_r, &mpi_a, &mpi_m) == 0)) {
        rc = noxtls_esp_mpi_write_fixed(&mpi_r, result, mod_len);
    }

    mbedtls_mpi_free(&mpi_a);
    mbedtls_mpi_free(&mpi_m);
    mbedtls_mpi_free(&mpi_r);
    return rc;
}

/**
 * @brief Mod exponent the P-256 value
 *
 * @param[out] result The result of the mod exponent operation
 * @param[in] base The base to mod exponent the value by
 * @param[in] exp The exponent to mod exponent the value by
 * @param[in] exp_len The length of the exponent to mod exponent the value by
 * @param[in] mod The modulus to mod exponent the value by
 * @param[in] mod_len The length of the modulus to mod exponent the value by
 * @return The return code
 */
static noxtls_return_t noxtls_esp_mpi_mod_exp_p256(uint8_t *result,
                                                   const uint8_t *base,
                                                   const uint8_t *exp,
                                                   uint32_t exp_len,
                                                   const uint8_t *mod,
                                                   uint32_t mod_len)
{
    mbedtls_mpi mpi_b;
    mbedtls_mpi mpi_e;
    mbedtls_mpi mpi_m;
    mbedtls_mpi mpi_r;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(result == NULL || base == NULL || exp == NULL || mod == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(mod_len != NOXTLS_ESP_MPI_P256_LEN) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    mbedtls_mpi_init(&mpi_b);
    mbedtls_mpi_init(&mpi_e);
    mbedtls_mpi_init(&mpi_m);
    mbedtls_mpi_init(&mpi_r);

    if((mbedtls_mpi_read_binary(&mpi_b, base, mod_len) == 0) &&
       (mbedtls_mpi_read_binary(&mpi_e, exp, exp_len) == 0) &&
       (mbedtls_mpi_read_binary(&mpi_m, mod, mod_len) == 0) &&
       (mbedtls_mpi_exp_mod(&mpi_r, &mpi_b, &mpi_e, &mpi_m, NULL) == 0)) {
        rc = noxtls_esp_mpi_write_fixed(&mpi_r, result, mod_len);
    }

    mbedtls_mpi_free(&mpi_b);
    mbedtls_mpi_free(&mpi_e);
    mbedtls_mpi_free(&mpi_m);
    mbedtls_mpi_free(&mpi_r);
    return rc;
}

/**
 * @brief The ESP hardware MPI operations
 *
 * @return The ESP hardware MPI operations
 */
static const noxtls_bn_platform_ops_t s_esp_bn_mpi_ops = {
    .mod = noxtls_esp_mpi_mod_p256,
    .mod_exp = noxtls_esp_mpi_mod_exp_p256,
};

/**
 * @brief Check if the ESP hardware MPI is compiled in
 *
 * @return 1 if the ESP hardware MPI is compiled in, 0 otherwise
 */
int noxtls_esp_hw_mpi_compiled_in(void)
{
#if defined(CONFIG_MBEDTLS_HARDWARE_MPI) && CONFIG_MBEDTLS_HARDWARE_MPI
    return 1;
#else
    return 0;
#endif
}

/**
 * @brief Register the ESP hardware MPI hooks
 *
 * @return void
 */
void noxtls_esp_hw_mpi_register(void)
{
    noxtls_bn_platform_register(&s_esp_bn_mpi_ops);
}

#else /* !CONFIG_MBEDTLS_HARDWARE_MPI */

/**
 * @brief Check if the ESP hardware MPI is compiled in
 *
 * @return 1 if the ESP hardware MPI is compiled in, 0 otherwise
 */
int noxtls_esp_hw_mpi_compiled_in(void)
{
    return 0;
}

/**
 * @brief Register the ESP hardware MPI hooks
 *
 * @return void
 */
void noxtls_esp_hw_mpi_register(void)
{
    (void)0;
}

#endif /* CONFIG_MBEDTLS_HARDWARE_MPI */

#else /* !CONFIG_NOXTLS_ESP_HW_MPI */

/**
 * @brief Check if the ESP hardware MPI is compiled in
 *
 * @return 1 if the ESP hardware MPI is compiled in, 0 otherwise
 */
int noxtls_esp_hw_mpi_compiled_in(void)
{
    return 0;
}

/**
 * @brief Register the ESP hardware MPI hooks
 *
 * @return void
 */
void noxtls_esp_hw_mpi_register(void)
{
    (void)0;
}

#endif
