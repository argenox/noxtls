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
* File:    noxtls_esp32_ecc_accel.c
* Summary: ESP-IDF ECC acceleration hook implementation
*
* Built only when ESP_PLATFORM is set in CMake (noxtls_pkc on ESP-IDF).
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_common.h"
#include "noxtls_esp_hw_accel.h"

#include "esp_log.h"
#include "soc/soc_caps.h"

#if defined(SOC_ECC_SUPPORTED) && SOC_ECC_SUPPORTED
#define ecc_point_t esp_idf_ecc_point_t
#include "ecc_impl.h"
#undef ecc_point_t

typedef struct {
    const ecc_curve_params_t *curve;
    uint8_t x[32];
    uint8_t y[32];
    int valid;
} noxtls_esp_verified_point_cache_t;

static noxtls_esp_verified_point_cache_t s_verified_point_cache = { 0 };
#endif

/**
 * @brief Reverse the copy of the data
 *
 * @param[out] dst The destination to copy the data to
 * @param[in] src The source to copy the data from
 * @param[in] len The length of the data to copy
 */
static void noxtls_esp_reverse_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++) {
        dst[i] = src[len - 1U - i];
    }
}

/**
 * @brief Check if the curve is a supported SEC256R1 curve
 *
 * @param[in] curve The curve to check if it is a supported SEC256R1 curve
 * @return 1 if the curve is a supported SEC256R1 curve, 0 otherwise
 */
static int noxtls_esp_curve_is_secp256r1(const ecc_curve_params_t *curve)
{
    static const uint8_t p_secp256r1[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    static const uint8_t a_secp256r1[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    };
    static const uint8_t b_secp256r1[32] = {
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
        0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
        0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
    };
    if(curve == NULL || curve->size != 32U) {
        return 0;
    }
    if(memcmp(curve->p, p_secp256r1, 32U) != 0) {
        return 0;
    }
    if(memcmp(curve->a, a_secp256r1, 32U) != 0) {
        return 0;
    }
    if(memcmp(curve->b, b_secp256r1, 32U) != 0) {
        return 0;
    }
    return 1;
}

/**
 * @brief Check if the ESP hardware ECC is compiled in
 *
 * @return 1 if the ESP hardware ECC is compiled in, 0 otherwise
 */
int noxtls_esp_hw_ecc_compiled_in(void)
{
#if defined(SOC_ECC_SUPPORTED) && SOC_ECC_SUPPORTED && \
    (CONFIG_NOXTLS_ESP_HW_ECC || CONFIG_NOXTLS_ESP_HW_ECDSA)
    return 1;
#else
    return 0;
#endif
}

/**
 * @brief Get the status of the ESP hardware ECC
 *
 * @param[out] buf The buffer to store the status of the ESP hardware ECC
 * @param[in] buflen The length of the buffer to store the status of the ESP hardware ECC
 */
void noxtls_esp_hw_ecc_status_str(char *buf, unsigned int buflen)
{
    const char *msg;

    if(buf == NULL || buflen == 0U) {
        return;
    }
    if(noxtls_esp_hw_ecc_compiled_in()) {
        msg = "active";
    }
#if !defined(SOC_ECC_SUPPORTED) || !SOC_ECC_SUPPORTED
    else {
        msg = "N/A (no periph)";
    }
#else
    else {
        msg = "off (config)";
    }
#endif
    (void)snprintf(buf, (size_t)buflen, "%s", msg);
}

/**
 * @brief Multiply the point by the scalar
 *
 * @param[out] result The result of the point multiplication
 * @param[in] scalar The scalar to multiply the point by
 * @param[in] point The point to multiply
 * @param[in] curve The curve to multiply the point by
 * @return The return code of the point multiplication
 */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
#if defined(SOC_ECC_SUPPORTED) && SOC_ECC_SUPPORTED && \
    (CONFIG_NOXTLS_ESP_HW_ECC || CONFIG_NOXTLS_ESP_HW_ECDSA)
    esp_idf_ecc_point_t in_pt;
    esp_idf_ecc_point_t out_pt;
    uint8_t scalar_le[32];
    int verify_first = 1;
    int rc;

    if(result == NULL || scalar == NULL || point == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!noxtls_esp_curve_is_secp256r1(curve)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(point->size != 32U) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    noxtls_esp_reverse_copy(in_pt.x, point->x, 32U);
    noxtls_esp_reverse_copy(in_pt.y, point->y, 32U);
    noxtls_esp_reverse_copy(scalar_le, scalar, 32U);
    in_pt.len = 32U;

    if(point == &curve->G ||
       (memcmp(point->x, curve->G.x, 32U) == 0 &&
        memcmp(point->y, curve->G.y, 32U) == 0)) {
        verify_first = 0;
    } else if(s_verified_point_cache.valid &&
              s_verified_point_cache.curve == curve &&
              memcmp(s_verified_point_cache.x, point->x, 32U) == 0 &&
              memcmp(s_verified_point_cache.y, point->y, 32U) == 0) {
        verify_first = 0;
    } else {
        if(esp_ecc_point_verify(&in_pt) != 1) {
            return NOXTLS_RETURN_FAILED;
        }
        s_verified_point_cache.curve = curve;
        memcpy(s_verified_point_cache.x, point->x, 32U);
        memcpy(s_verified_point_cache.y, point->y, 32U);
        s_verified_point_cache.valid = 1;
        verify_first = 0;
    }

    rc = esp_ecc_point_multiply(&in_pt, scalar_le, &out_pt, verify_first);
    if(rc != 0 || out_pt.len != 32U) {
        static int s_logged;
        if(!s_logged) {
            ESP_LOGW("noxtls_esp", "esp_ecc_point_multiply failed rc=%d len=%u (software fallback)",
                     rc, (unsigned)out_pt.len);
            s_logged = 1;
        }
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_esp_reverse_copy(result->x, out_pt.x, 32U);
    noxtls_esp_reverse_copy(result->y, out_pt.y, 32U);
    result->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)result;
    (void)scalar;
    (void)point;
    (void)curve;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}
