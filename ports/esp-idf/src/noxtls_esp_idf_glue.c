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

#if defined(CONFIG_NOXTLS_USE_ESP_ENTROPY) && CONFIG_NOXTLS_USE_ESP_ENTROPY
/*
 * ESP-IDF documents that the hardware RNG output is only pseudo-random unless
 * the RF subsystem (Wi-Fi/Bluetooth) is running or the SAR ADC entropy source
 * is enabled with bootloader_random_enable(). The constructor runs before
 * app_main, when neither RF nor the ADC is in use, so it enables the SAR ADC
 * source once and draws a boot seed from it. Every callback output is then
 * esp_fill_random() XOR SHA-256(boot seed || counter), so DRBG seeds drawn
 * before Wi-Fi starts (or on radio-less products) still carry real entropy.
 * bootloader_random_enable() is not called later because it is unsafe while
 * RF or the ADC is active.
 */
#include "bootloader_random.h"
#include "freertos/FreeRTOS.h"
#include "noxtls_ct.h"
#include "noxtls_sha256.h"

#define NOXTLS_ESP_BOOT_SEED_LEN 32U

static uint8_t s_boot_seed[NOXTLS_ESP_BOOT_SEED_LEN];
static uint8_t s_boot_seed_ready;
static uint64_t s_boot_seed_counter;
static portMUX_TYPE s_boot_seed_lock = portMUX_INITIALIZER_UNLOCKED;

/**
 * @brief Draw the boot seed with the SAR ADC entropy source enabled.
 *
 * Call only before RF or the ADC is in use (constructor context).
 */
static void noxtls_esp_collect_boot_seed(void)
{
	bootloader_random_enable();
	esp_fill_random(s_boot_seed, NOXTLS_ESP_BOOT_SEED_LEN);
	bootloader_random_disable();
	s_boot_seed_ready = 1U;
}

/**
 * @brief XOR SHA-256(boot seed || counter) blocks into @p buf.
 * @param buf Buffer already filled from esp_fill_random().
 * @param len Number of bytes in @p buf.
 * @return NOXTLS_RETURN_SUCCESS, or the SHA-256 error.
 */
static noxtls_return_t noxtls_esp_mix_boot_seed(uint8_t *buf, uint32_t len)
{
	noxtls_sha_ctx_t ctx;
	uint8_t block[32];
	uint8_t ctr_le[8];
	uint64_t ctr;
	uint32_t nblocks = (len + 31U) / 32U;
	uint32_t off = 0U;
	uint32_t i;
	uint32_t take;
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

	taskENTER_CRITICAL(&s_boot_seed_lock);
	ctr = s_boot_seed_counter;
	s_boot_seed_counter += (uint64_t)nblocks;
	taskEXIT_CRITICAL(&s_boot_seed_lock);

	while((rc == NOXTLS_RETURN_SUCCESS) && (off < len)) {
		for(i = 0U; i < 8U; i++) {
			ctr_le[i] = (uint8_t)(ctr >> (8U * i));
		}
		rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
		if(rc == NOXTLS_RETURN_SUCCESS) {
			rc = noxtls_sha256_update(&ctx, s_boot_seed, NOXTLS_ESP_BOOT_SEED_LEN);
		}
		if(rc == NOXTLS_RETURN_SUCCESS) {
			rc = noxtls_sha256_update(&ctx, ctr_le, (uint32_t)sizeof(ctr_le));
		}
		if(rc == NOXTLS_RETURN_SUCCESS) {
			rc = noxtls_sha256_finish(&ctx, block);
		}
		if(rc == NOXTLS_RETURN_SUCCESS) {
			take = ((len - off) < 32U) ? (len - off) : 32U;
			for(i = 0U; i < take; i++) {
				buf[off + i] ^= block[i];
			}
			off += take;
			ctr++;
		}
	}
	noxtls_secure_zero(&ctx, sizeof(ctx));
	noxtls_secure_zero(block, sizeof(block));
	return rc;
}

/**
 * @brief ESP hardware RNG callback for NoxTLS DRBG seeding.
 * @param entropy_buffer Output buffer.
 * @param entropy_len Number of bytes to fill.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL on bad
 *         arguments, or a SHA-256 error (the buffer is then wiped).
 */
static noxtls_return_t esp_entropy_cb(uint8_t *entropy_buffer, uint32_t entropy_len)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

	if(entropy_buffer == NULL || entropy_len == 0U) {
		return NOXTLS_RETURN_NULL;
	}

	esp_fill_random(entropy_buffer, entropy_len);
	if(s_boot_seed_ready != 0U) {
		rc = noxtls_esp_mix_boot_seed(entropy_buffer, entropy_len);
		if(rc != NOXTLS_RETURN_SUCCESS) {
			noxtls_secure_zero(entropy_buffer, entropy_len);
		}
	}
	return rc;
}
#endif

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
#if defined(CONFIG_NOXTLS_USE_ESP_ENTROPY) && CONFIG_NOXTLS_USE_ESP_ENTROPY
	noxtls_esp_collect_boot_seed();
#endif
	(void)noxtls_esp_idf_init();
}
#endif
