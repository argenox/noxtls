/*****************************************************************************
 * Copyright (c) [2019] - [2026], Argenox Technologies LLC
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Zephyr RTOS integration: entropy and platform hooks for NoxTLS DRBG.
 *****************************************************************************/

#include <stdint.h>

#include <zephyr/init.h>
#include <zephyr/random/random.h>

#include "noxtls_common.h"
#include "noxtls_drbg.h"

/**
 * @brief Zephyr CSRNG callback for NoxTLS DRBG seeding.
 * @param entropy_buffer Output buffer.
 * @param entropy_len Number of bytes to fill.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t zephyr_entropy_cb(uint8_t *entropy_buffer, uint32_t entropy_len)
{
	int rc;

	if(entropy_buffer == NULL || entropy_len == 0U) {
		return NOXTLS_RETURN_NULL;
	}

	rc = sys_csrand_get(entropy_buffer, entropy_len);
	if(rc != 0) {
		return NOXTLS_RETURN_FAILED;
	}

	return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Register Zephyr entropy with NoxTLS during kernel init.
 * @return 0 on success.
 */
static int noxtls_zephyr_init(void)
{
#if IS_ENABLED(CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY)
	noxtls_drbg_set_entropy_callback(zephyr_entropy_cb);
	noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
#endif
	return 0;
}

SYS_INIT(noxtls_zephyr_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
