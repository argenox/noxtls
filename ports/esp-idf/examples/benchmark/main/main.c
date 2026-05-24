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
* Summary: Reports throughput (MB/s) for SHA-256 / AES-GCM / ChaCha20-Poly1305 /
 *         HMAC-SHA-256 / DRBG, and ops-per-second for ECDSA P-256 sign + verify.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "noxtls_common.h"
#include "noxtls_esp_idf.h"
#include "noxtls-lib/drbg/noxtls_drbg.h"
#include "noxtls-lib/encryption/aes/noxtls_aes_gcm.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
#if defined(NOXTLS_FEATURE_CHACHA20_POLY1305) && NOXTLS_FEATURE_CHACHA20_POLY1305
#include "noxtls-lib/encryption/chacha20/noxtls_chacha20_poly1305.h"
#endif
#include "noxtls-lib/tls/noxtls_tls_kdf.h"
#if defined(NOXTLS_FEATURE_ECDSA) && NOXTLS_FEATURE_ECDSA
#include "noxtls-lib/pkc/ecc/noxtls_ecc.h"
#include "noxtls-lib/pkc/ecdsa/noxtls_ecdsa.h"
#endif

#define NOXTLS_BENCH_TAG          "noxtls_bench"
#define NOXTLS_BENCH_AES_KEY_LEN  (16U)
#define NOXTLS_BENCH_GCM_NONCE    (12U)
#define NOXTLS_BENCH_GCM_TAG_LEN  (16U)
#define NOXTLS_BENCH_C20_KEY_LEN  (32U)
#define NOXTLS_BENCH_C20_NONCE    (12U)
#define NOXTLS_BENCH_HMAC_OUT     (HASH_SHA256_OUT_LEN)
#define NOXTLS_BENCH_DRBG_BYTES   (1024U)
#define NOXTLS_BENCH_DRBG_BITS    (NOXTLS_BENCH_DRBG_BYTES * 8U)
#define NOXTLS_BENCH_ECDSA_MSG    (32U)

static const uint8_t g_bench_aes_key[NOXTLS_BENCH_AES_KEY_LEN] = {
	0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
	0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
};

static const uint8_t g_bench_c20_key[NOXTLS_BENCH_C20_KEY_LEN] = {
	0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
	0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
	0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
	0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
};

static const uint8_t g_bench_nonce12[NOXTLS_BENCH_GCM_NONCE] = {
	0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U,
	0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU,
};

static const uint8_t g_bench_hmac_key[NOXTLS_BENCH_HMAC_OUT] = {
	0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U,
	0x38U, 0x39U, 0x3aU, 0x3bU, 0x3cU, 0x3dU, 0x3eU, 0x3fU,
	0x40U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U,
	0x48U, 0x49U, 0x4aU, 0x4bU, 0x4cU, 0x4dU, 0x4eU, 0x4fU,
};

/**
 * @brief Wall time in microseconds since boot.
 * @return Monotonic timestamp in µs.
 */
static int64_t bench_now_us(void)
{
	return esp_timer_get_time();
}

/**
 * @brief Kick the watchdog timer
 * 
 * @param[in] iter The iteration count.
 * @return void
 */
static inline void bench_wdt_kick(uint32_t iter)
{
#if CONFIG_ESP_TASK_WDT_EN
	if((iter & 0x1FU) == 0U) {
		(void)esp_task_wdt_reset();
	}
#else
	(void)iter;
#endif
}

/**
 * @brief Print MB/s throughput for a symmetric primitive.
 * @param name Display name of the algorithm.
 * @param bytes Total bytes processed across all iterations.
 * @param elapsed_us Elapsed time in microseconds.
 */
static void bench_report_throughput(const char *name, uint64_t bytes, int64_t elapsed_us)
{
	double mb;
	double seconds;
	double mbps;

	if(elapsed_us <= 0) {
		printf("  %-28s elapsed=%lld us  (skipped)\n", name, (long long)elapsed_us);
		return;
	}

	mb = (double)bytes / (1024.0 * 1024.0);
	seconds = (double)elapsed_us / 1.0e6;
	mbps = mb / seconds;
	printf("  %-28s %10.3f MB/s  (%llu B in %lld us)\n",
	       name, mbps, (unsigned long long)bytes, (long long)elapsed_us);
}

/**
 * @brief Print ops/sec for an asymmetric primitive.
 * @param name Display name of the operation.
 * @param ops Number of operations completed.
 * @param elapsed_us Elapsed time in microseconds.
 */
static void bench_report_ops(const char *name, uint32_t ops, int64_t elapsed_us)
{
	double seconds;
	double rate;

	if(elapsed_us <= 0 || ops == 0U) {
		printf("  %-28s ops=%u  elapsed=%lld us (skipped)\n", name,
		       (unsigned int)ops, (long long)elapsed_us);
		return;
	}
	seconds = (double)elapsed_us / 1.0e6;
	rate = (double)ops / seconds;
	printf("  %-28s %10.2f ops/s  (%u ops in %lld us)\n",
	       name, rate, (unsigned int)ops, (long long)elapsed_us);
}

/**
 * @brief Measure SHA-256 throughput over (buf_len * iterations) bytes.
 * @param buf Input buffer.
 * @param buf_len Per-iteration input length.
 * @param iterations Iteration count.
 */
static void bench_sha256(const uint8_t *buf, uint32_t buf_len, uint32_t iterations)
{
	noxtls_sha_ctx_t ctx;
	uint8_t out[HASH_SHA256_OUT_LEN];
	int64_t t0;
	int64_t t1;
	uint32_t i;

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		if(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) return;
		if(noxtls_sha256_update(&ctx, buf, buf_len) != NOXTLS_RETURN_SUCCESS) return;
		if(noxtls_sha256_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return;
	}
	t1 = bench_now_us();
	bench_report_throughput("SHA-256",
				(uint64_t)buf_len * iterations, t1 - t0);
}

/**
 * @brief Measure AES-128-GCM encrypt throughput.
 * @param pt Plaintext buffer.
 * @param ct Ciphertext buffer (same size).
 * @param buf_len Per-iteration size.
 * @param iterations Iteration count.
 */
static void bench_aes_gcm(const uint8_t *pt, uint8_t *ct, uint32_t buf_len, uint32_t iterations)
{
	uint8_t tag[NOXTLS_BENCH_GCM_TAG_LEN];
	int64_t t0;
	int64_t t1;
	uint32_t i;
	noxtls_return_t rc;

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		rc = noxtls_aes_gcm_encrypt(g_bench_aes_key, NOXTLS_AES_128_BIT, g_bench_nonce12,
					    NULL, 0U, pt, buf_len, ct, tag);
		if(rc != NOXTLS_RETURN_SUCCESS) return;
	}
	t1 = bench_now_us();
	bench_report_throughput("AES-128-GCM (encrypt)",
				(uint64_t)buf_len * iterations, t1 - t0);
}

#if defined(NOXTLS_FEATURE_CHACHA20_POLY1305) && NOXTLS_FEATURE_CHACHA20_POLY1305
/**
 * @brief Measure ChaCha20-Poly1305 encrypt throughput.
 * @param pt Plaintext buffer.
 * @param ct Ciphertext buffer (same size).
 * @param buf_len Per-iteration size.
 * @param iterations Iteration count.
 */
static void bench_chacha20_poly1305(const uint8_t *pt, uint8_t *ct,
				    uint32_t buf_len, uint32_t iterations)
{
	uint8_t tag[NOXTLS_BENCH_GCM_TAG_LEN];
	int64_t t0;
	int64_t t1;
	uint32_t i;
	noxtls_return_t rc;

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		rc = noxtls_chacha20_poly1305_encrypt(g_bench_c20_key, g_bench_nonce12,
						      NULL, 0U, pt, buf_len, ct, tag);
		if(rc != NOXTLS_RETURN_SUCCESS) return;
	}
	t1 = bench_now_us();
	bench_report_throughput("ChaCha20-Poly1305 (encrypt)",
				(uint64_t)buf_len * iterations, t1 - t0);
}
#endif

/**
 * @brief Measure HMAC-SHA-256 throughput.
 * @param buf Input buffer.
 * @param buf_len Per-iteration size.
 * @param iterations Iteration count.
 */
static void bench_hmac_sha256(const uint8_t *buf, uint32_t buf_len, uint32_t iterations)
{
	uint8_t mac[HASH_SHA256_OUT_LEN];
	uint32_t mac_len;
	int64_t t0;
	int64_t t1;
	uint32_t i;

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		mac_len = sizeof(mac);
		if(hmac_compute(NOXTLS_HASH_SHA_256, g_bench_hmac_key,
				NOXTLS_BENCH_HMAC_OUT, buf, buf_len, mac,
				&mac_len) != NOXTLS_RETURN_SUCCESS) return;
	}
	t1 = bench_now_us();
	bench_report_throughput("HMAC-SHA-256",
				(uint64_t)buf_len * iterations, t1 - t0);
}

/**
 * @brief Measure CTR-DRBG (AES-256) output throughput.
 * @param iterations Number of generate() calls (each NOXTLS_BENCH_DRBG_BYTES bytes).
 */
static void bench_drbg(uint32_t iterations)
{
	drbg_state_t state;
	uint8_t out[NOXTLS_BENCH_DRBG_BYTES];
	int64_t t0;
	int64_t t1;
	uint32_t i;
	noxtls_return_t rc;

	memset(&state, 0, sizeof(state));
	if(drbg_instantiate(&state, DRBG_AES256, NULL, 0U, NULL, 0U,
			    NULL, 0U) != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGW(NOXTLS_BENCH_TAG, "drbg_instantiate failed");
		return;
	}

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		rc = drbg_generate(&state, out, NOXTLS_BENCH_DRBG_BITS, NULL, 0U);
		if(rc != NOXTLS_RETURN_SUCCESS) break;
	}
	t1 = bench_now_us();
	bench_report_throughput("CTR-DRBG (AES-256)",
				(uint64_t)NOXTLS_BENCH_DRBG_BYTES * iterations, t1 - t0);
	(void)noxtls_drbg_uninstantiate(&state);
}

#if defined(NOXTLS_FEATURE_ECDSA) && NOXTLS_FEATURE_ECDSA
/**
 * @brief Measure ECDSA P-256 sign and verify ops per second.
 * @param iterations Number of sign+verify pairs to perform.
 */
static void bench_ecdsa_p256(uint32_t iterations)
{
	ecc_key_t key;
	ecdsa_signature_t sig;
	const uint8_t msg[NOXTLS_BENCH_ECDSA_MSG] = { 0 };
	int64_t t0;
	int64_t t1;
	uint32_t i;
	int key_ok;
	int sig_ok;

	memset(&key, 0, sizeof(key));
	memset(&sig, 0, sizeof(sig));
	key_ok = 0;
	sig_ok = 0;

	if(noxtls_ecc_key_generate(&key, ECC_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGW(NOXTLS_BENCH_TAG, "ecc keygen failed; skipping ECDSA bench");
		return;
	}
	key_ok = 1;

	if(noxtls_ecdsa_signature_init(&sig, 32U) != NOXTLS_RETURN_SUCCESS) {
		goto cleanup;
	}
	sig_ok = 1;

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		if(noxtls_ecdsa_sign(&key, msg, sizeof(msg), &sig,
				     NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) break;
	}
	t1 = bench_now_us();
	bench_report_ops("ECDSA P-256 sign", iterations, t1 - t0);

	t0 = bench_now_us();
	for(i = 0U; i < iterations; i++) {
		bench_wdt_kick(i);
		if(noxtls_ecdsa_verify(&key, msg, sizeof(msg), &sig,
				       NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) break;
	}
	t1 = bench_now_us();
	bench_report_ops("ECDSA P-256 verify", iterations, t1 - t0);

cleanup:
	if(sig_ok) noxtls_ecdsa_signature_free(&sig);
	if(key_ok) noxtls_ecc_key_free(&key);
}
#endif

/**
 * @brief Print one-line CPU + heap summary before running benchmarks.
 */
static void bench_print_environment(void)
{
	esp_chip_info_t info;

	esp_chip_info(&info);
	printf("Chip:      model=%d  cores=%d  rev=%d  features=0x%08x\n",
	       (int)info.model, (int)info.cores, (int)info.revision,
	       (unsigned int)info.features);
	printf("Heap free: internal=%u  largest=%u\n",
	       (unsigned int)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
	       (unsigned int)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
	printf("Buffer:    %u bytes x %u iterations  (PKC iterations=%u)\n",
	       (unsigned int)CONFIG_NOXTLS_BENCH_BUFFER_SIZE,
	       (unsigned int)CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS,
	       (unsigned int)CONFIG_NOXTLS_BENCH_PKC_ITERATIONS);
}

/**
 * @brief The main function.
 */
void app_main(void)
{
	uint8_t *buf;
	uint8_t *out;

	(void)noxtls_esp_idf_init();

	printf("\nNoxTLS ESP-IDF benchmark\n");
	printf("------------------------\n");
	bench_print_environment();

	buf = (uint8_t *)malloc(CONFIG_NOXTLS_BENCH_BUFFER_SIZE);
	out = (uint8_t *)malloc(CONFIG_NOXTLS_BENCH_BUFFER_SIZE);
	if(buf == NULL || out == NULL) {
		ESP_LOGE(NOXTLS_BENCH_TAG, "alloc failed");
		free(buf);
		free(out);
		return;
	}
	memset(buf, 0xa5, CONFIG_NOXTLS_BENCH_BUFFER_SIZE);

	printf("\nSymmetric throughput:\n");
	bench_sha256(buf, (uint32_t)CONFIG_NOXTLS_BENCH_BUFFER_SIZE,
		     (uint32_t)CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS);
	bench_aes_gcm(buf, out, (uint32_t)CONFIG_NOXTLS_BENCH_BUFFER_SIZE,
		      (uint32_t)CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS);
#if defined(NOXTLS_FEATURE_CHACHA20_POLY1305) && NOXTLS_FEATURE_CHACHA20_POLY1305
	bench_chacha20_poly1305(buf, out, (uint32_t)CONFIG_NOXTLS_BENCH_BUFFER_SIZE,
				(uint32_t)CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS);
#endif
	bench_hmac_sha256(buf, (uint32_t)CONFIG_NOXTLS_BENCH_BUFFER_SIZE,
			  (uint32_t)CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS);

	printf("\nRandom:\n");
	bench_drbg((uint32_t)CONFIG_NOXTLS_BENCH_DRBG_ITERATIONS);

#if defined(CONFIG_NOXTLS_BENCH_RUN_ECDSA) && CONFIG_NOXTLS_BENCH_RUN_ECDSA && \
    defined(NOXTLS_FEATURE_ECDSA) && NOXTLS_FEATURE_ECDSA
	printf("\nPublic-key (ECDSA P-256):\n");
	bench_ecdsa_p256((uint32_t)CONFIG_NOXTLS_BENCH_PKC_ITERATIONS);
#endif

	printf("\nDone.\n");
	free(buf);
	free(out);
}
