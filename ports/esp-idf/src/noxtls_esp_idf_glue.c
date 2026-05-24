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
* File:    noxtls_esp_idf_glue.c
* Summary: ESP-IDF integration: entropy hooks for NoxTLS DRBG.
*
*
*****************************************************************************/

#include <stdint.h>

#include "esp_log.h"
#include "esp_random.h"
#include "sdkconfig.h"

#include "noxtls_common.h"
#include "noxtls_debug_printf.h"
#include "noxtls_drbg.h"
#include "noxtls_esp_idf.h"
#include "noxtls_esp_hw_crypto.h"

/**
 * @brief ESP hardware RNG callback for NoxTLS DRBG seeding.
 * @param entropy_buffer Output buffer.
 * @param entropy_len Number of bytes to fill.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t esp_entropy_cb(uint8_t *entropy_buffer, uint32_t entropy_len)
{
	if(entropy_buffer == NULL || entropy_len == 0U) {
		return NOXTLS_RETURN_NULL;
	}

	esp_fill_random(entropy_buffer, entropy_len);
	return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Register ESP entropy with NoxTLS DRBG.
 * @return 0 on success.
 */
int noxtls_esp_idf_init(void)
{
	/*
	 * Disable NoxTLS debug printf on embedded targets. TLS_DEBUG / KEYLOG /
	 * full-secret hex dumps and stray fflush() in crypto paths can stall the
	 * main task long enough to trip the ESP task WDT during ECDSA sign.
	 */
	noxtls_debug_set_level(0);

	noxtls_esp_hw_mpi_register();

#if defined(CONFIG_NOXTLS_ESP_HW_ECC) && CONFIG_NOXTLS_ESP_HW_ECC
	if(noxtls_esp_hw_ecc_compiled_in()) {
		ESP_LOGI("noxtls_esp", "HW ECC point multiply active (P-256)");
	} else {
		ESP_LOGW("noxtls_esp",
			 "CONFIG_NOXTLS_ESP_HW_ECC is on, but this target has no ECC peripheral "
			 "(SOC_ECC_SUPPORTED=0). Falling back to software ECC.");
	}
#endif
#if defined(CONFIG_NOXTLS_ESP_HW_MPI) && CONFIG_NOXTLS_ESP_HW_MPI
	if(noxtls_esp_hw_mpi_compiled_in()) {
		ESP_LOGI("noxtls_esp", "HW MPI active (P-256 mod/mod_exp)");
	} else {
		ESP_LOGW("noxtls_esp",
			 "CONFIG_NOXTLS_ESP_HW_MPI is on but MPI glue is a stub "
			 "(enable CONFIG_MBEDTLS_HARDWARE_MPI in sdkconfig)");
	}
#endif

#if defined(CONFIG_NOXTLS_USE_ESP_ENTROPY) && CONFIG_NOXTLS_USE_ESP_ENTROPY
	noxtls_drbg_set_entropy_callback(esp_entropy_cb);
	noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
#endif
	return 0;
}

#if defined(CONFIG_NOXTLS) && CONFIG_NOXTLS
/**
 * @brief Run NoxTLS ESP-IDF init before app_main (entropy + HW crypto hooks).
 */
static void __attribute__((constructor)) noxtls_esp_idf_init_ctor(void)
{
	(void)noxtls_esp_idf_init();
}
#endif
