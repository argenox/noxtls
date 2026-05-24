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
* File:    main.c
* Summary: Zephyr ztest smoke test for NoxTLS crypto primitives.
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "noxtls_aes_gcm.h"
#include "noxtls_aes.h"
#include "noxtls_common.h"
#include "noxtls_drbg.h"
#include "noxtls_sha256.h"

#define NOXTLS_SMOKE_PLAINTEXT_LEN (16U)
#define NOXTLS_SMOKE_GCM_NONCE_LEN (12U)
#define NOXTLS_SMOKE_GCM_TAG_LEN   (16U)
#define NOXTLS_SMOKE_AES_KEY_LEN   (16U)
#define NOXTLS_SMOKE_DRBG_BYTES    (32U)
#define NOXTLS_SMOKE_DRBG_BITS     (NOXTLS_SMOKE_DRBG_BYTES * 8U)

static const uint8_t g_smoke_aes_key[NOXTLS_SMOKE_AES_KEY_LEN] = {
	0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
	0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
};

static const uint8_t g_smoke_gcm_nonce[NOXTLS_SMOKE_GCM_NONCE_LEN] = {
	0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
	0x18U, 0x19U, 0x1aU, 0x1bU,
};

static const uint8_t g_smoke_plaintext[NOXTLS_SMOKE_PLAINTEXT_LEN] = {
	0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U,
	0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU,
};

/* SHA-256("abc") */
static const uint8_t g_smoke_sha256_abc[HASH_SHA256_OUT_LEN] = {
	0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
	0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
	0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
	0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU,
};

ZTEST(noxtls_crypto_smoke, test_aes_gcm_roundtrip)
{
	uint8_t ciphertext[NOXTLS_SMOKE_PLAINTEXT_LEN];
	uint8_t plaintext[NOXTLS_SMOKE_PLAINTEXT_LEN];
	uint8_t tag[NOXTLS_SMOKE_GCM_TAG_LEN];
	noxtls_return_t rc;

	rc = noxtls_aes_gcm_encrypt(g_smoke_aes_key, NOXTLS_AES_128_BIT, g_smoke_gcm_nonce,
				    NULL, 0U, g_smoke_plaintext, NOXTLS_SMOKE_PLAINTEXT_LEN,
				    ciphertext, tag);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "aes gcm encrypt failed: %d", rc);

	rc = noxtls_aes_gcm_decrypt(g_smoke_aes_key, NOXTLS_AES_128_BIT, g_smoke_gcm_nonce,
				    NULL, 0U, ciphertext, NOXTLS_SMOKE_PLAINTEXT_LEN, tag,
				    plaintext);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "aes gcm decrypt failed: %d", rc);
	zassert_mem_equal(plaintext, g_smoke_plaintext, NOXTLS_SMOKE_PLAINTEXT_LEN,
			  "aes gcm plaintext mismatch");
}

ZTEST(noxtls_crypto_smoke, test_sha256_abc)
{
	noxtls_return_t rc;
	const uint8_t msg[] = "abc";

	rc = noxtls_sha256_verify(msg, 3U, g_smoke_sha256_abc);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "sha256 verify failed: %d", rc);
}

ZTEST(noxtls_crypto_smoke, test_drbg_generate)
{
	drbg_state_t state;
	uint8_t out[NOXTLS_SMOKE_DRBG_BYTES];
	uint32_t i;
	uint8_t all_zero;
	noxtls_return_t rc;

	memset(&state, 0, sizeof(state));
	all_zero = 1U;

	rc = drbg_instantiate(&state, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "drbg instantiate failed: %d", rc);

	rc = drbg_generate(&state, out, NOXTLS_SMOKE_DRBG_BITS, NULL, 0U);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "drbg generate failed: %d", rc);

	for(i = 0U; i < NOXTLS_SMOKE_DRBG_BYTES; i++) {
		if(out[i] != 0U) {
			all_zero = 0U;
			break;
		}
	}
	zassert_equal(all_zero, 0U, "drbg output was all zeros");

	rc = noxtls_drbg_uninstantiate(&state);
	zassert_equal(rc, NOXTLS_RETURN_SUCCESS, "drbg uninstantiate failed: %d", rc);
}

ZTEST_SUITE(noxtls_crypto_smoke, NULL, NULL, NULL, NULL, NULL);
