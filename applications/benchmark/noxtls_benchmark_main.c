/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_benchmark_main.c
* Summary: Benchmark entrypoint for crypto primitive throughput/latency runs.
*
*/

#include <stdint.h>
#include <string.h>

#include "noxtls_config.h"
#include "noxtls_bench_platform.h"

#include "mdigest/noxtls_hash.h"
#include "mdigest/noxtls_sha.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/chacha20/noxtls_chacha20.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "pkc/ecdh/noxtls_ecdh.h"

typedef noxtls_return_t (*bench_fn_t)(uint32_t iterations, uint32_t *bytes_per_iter);

typedef struct
{
    const char *name;
    bench_fn_t fn;
    uint32_t iterations;
} bench_case_t;

static const uint8_t g_data_1k[1024] = {0xA5u};
static const uint8_t g_data_64[64] = {0x5Au};

static void bench_print_result(const char *name, uint64_t ns_total, uint32_t iterations, uint32_t bytes_per_iter)
{
    uint64_t ns_per_op = (iterations == 0u) ? 0u : (ns_total / (uint64_t)iterations);
    uint64_t throughput_bps = 0u;
    if (ns_total > 0u && bytes_per_iter > 0u) {
        throughput_bps = ((uint64_t)bytes_per_iter * (uint64_t)iterations * 1000000000ull) / ns_total;
    }

    noxtls_bench_log("%-20s | ops=%8lu | ns/op=%10llu | B/s=%10llu\r\n",
                     name,
                     (unsigned long)iterations,
                     (unsigned long long)ns_per_op,
                     (unsigned long long)throughput_bps);
}

static noxtls_return_t bench_md5(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_MD5
    noxtls_sha_ctx_t ctx;
    uint8_t out[HASH_MD5_OUT_LEN];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_md5_update(&ctx, g_data_1k, sizeof(g_data_1k)) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_md5_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_sha1(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_SHA1
    noxtls_sha_ctx_t ctx;
    uint8_t out[HASH_SHA1_OUT_LEN];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha1_update(&ctx, g_data_1k, sizeof(g_data_1k)) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha1_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_sha256(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_SHA256
    noxtls_sha_ctx_t ctx;
    uint8_t out[HASH_SHA256_OUT_LEN];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha256_update(&ctx, g_data_1k, sizeof(g_data_1k)) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha256_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_sha512(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_SHA512
    noxtls_sha512_ctx_t ctx;
    uint8_t out[HASH_SHA512_OUT_LEN];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_update(&ctx, g_data_1k, sizeof(g_data_1k)) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_sha3_256(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_SHA3
    noxtls_sha3_ctx_t ctx;
    uint8_t out[HASH_SHA3_256_OUT_LEN];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_sha3_256_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha3_update(&ctx, g_data_1k, sizeof(g_data_1k)) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha3_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_aes_ecb_128(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_ECB && NOXTLS_FEATURE_AES_128
    static const uint8_t key[16] = {0};
    uint8_t out[sizeof(g_data_1k)];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_aes_encrypt_ecb(key, g_data_1k, sizeof(g_data_1k), NULL, out, NOXTLS_AES_128_BIT) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_chacha20(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    static const uint8_t key[32] = {0};
    static const uint8_t nonce[12] = {0};
    uint8_t out[sizeof(g_data_1k)];
    uint32_t i;
    *bytes_per_iter = sizeof(g_data_1k);
    for (i = 0; i < iterations; i++) {
        if (noxtls_chacha20_encrypt(key, nonce, 1u, g_data_1k, sizeof(g_data_1k), out) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_ecdsa_p256_sign(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_ECDSA && NOXTLS_FEATURE_ECC
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint32_t i;
    noxtls_return_t rc;

    *bytes_per_iter = sizeof(g_data_64);
    rc = noxtls_ecc_key_init(&key, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = noxtls_ecc_key_generate(&key, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecc_key_free(&key);
        return rc;
    }
    rc = noxtls_ecdsa_signature_init(&sig, key.curve->size);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecc_key_free(&key);
        return rc;
    }

    for (i = 0; i < iterations; i++) {
        rc = noxtls_ecdsa_sign(&key, g_data_64, sizeof(g_data_64), &sig, NOXTLS_HASH_SHA_256);
        if (rc != NOXTLS_RETURN_SUCCESS) break;
    }

    (void)noxtls_ecdsa_signature_free(&sig);
    (void)noxtls_ecc_key_free(&key);
    return rc;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t bench_ecdh_p256(uint32_t iterations, uint32_t *bytes_per_iter)
{
#if NOXTLS_FEATURE_ECC
    ecc_key_t a;
    ecc_key_t b;
    uint8_t secret[ECC_MAX_KEY_SIZE];
    uint32_t secret_len = sizeof(secret);
    uint32_t i;
    noxtls_return_t rc;

    *bytes_per_iter = sizeof(g_data_64);
    rc = noxtls_ecc_key_init(&a, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = noxtls_ecc_key_init(&b, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecc_key_free(&a);
        return rc;
    }
    rc = noxtls_ecc_key_generate(&a, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) goto out;
    rc = noxtls_ecc_key_generate(&b, ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) goto out;

    for (i = 0; i < iterations; i++) {
        secret_len = sizeof(secret);
        rc = noxtls_ecdh_compute_shared_secret(&a, &b.Q, secret, &secret_len);
        if (rc != NOXTLS_RETURN_SUCCESS) break;
    }
out:
    (void)noxtls_ecc_key_free(&a);
    (void)noxtls_ecc_key_free(&b);
    return rc;
#else
    (void)iterations; (void)bytes_per_iter;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

int main(void)
{
    uint32_t i;
    static const bench_case_t cases[] = {
        {"MD5", bench_md5, 3000u},
        {"SHA1", bench_sha1, 3000u},
        {"SHA256", bench_sha256, 3000u},
        {"SHA512", bench_sha512, 1500u},
        {"SHA3-256", bench_sha3_256, 1500u},
        {"AES-128-ECB", bench_aes_ecb_128, 2000u},
        {"ChaCha20", bench_chacha20, 2000u},
        {"ECDSA-P256-SIGN", bench_ecdsa_p256_sign, 100u},
        {"ECDH-P256", bench_ecdh_p256, 100u},
    };

    noxtls_bench_platform_init();
    noxtls_bench_log("\r\nNoxTLS benchmark demo\r\n");
    noxtls_bench_log("primitive            |      ops |      ns/op |        B/s\r\n");
    noxtls_bench_log("---------------------+----------+------------+------------\r\n");

    for (i = 0; i < (uint32_t)(sizeof(cases) / sizeof(cases[0])); i++) {
        uint32_t bytes_per_iter = 0u;
        noxtls_return_t rc;
        uint64_t start_ns;
        uint64_t stop_ns;

        rc = cases[i].fn(1u, &bytes_per_iter); /* warm-up */
        if (rc != NOXTLS_RETURN_SUCCESS && rc != NOXTLS_RETURN_NOT_SUPPORTED) {
            noxtls_bench_log("%-20s | ERROR rc=%d\r\n", cases[i].name, (int)rc);
            continue;
        }
        if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
            noxtls_bench_log("%-20s | not supported\r\n", cases[i].name);
            continue;
        }

        start_ns = noxtls_bench_time_now_ns();
        rc = cases[i].fn(cases[i].iterations, &bytes_per_iter);
        stop_ns = noxtls_bench_time_now_ns();
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_bench_log("%-20s | ERROR rc=%d\r\n", cases[i].name, (int)rc);
            continue;
        }

        bench_print_result(cases[i].name, stop_ns - start_ns, cases[i].iterations, bytes_per_iter);
    }

    noxtls_bench_log("\r\nDone.\r\n");
    return 0;
}
