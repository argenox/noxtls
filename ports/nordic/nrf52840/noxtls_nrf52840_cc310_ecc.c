/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_nrf52840_cc310_ecc.c
* Summary: NoxTLS P-256 acceleration using nRF52840 CryptoCell 310.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cc3xx_ecdh_util.h"
#include "cc3xx_psa_key_generation.h"
#include "nrf_cc3xx_platform.h"
#include "nrf_cc3xx_platform_abort.h"
#include "noxtls_common.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdh/noxtls_ecdh.h"

#define NOXTLS_CC310_P256_BYTES       32u
#define NOXTLS_CC310_PUBLIC_KEY_BYTES 65u

static volatile uint32_t s_cc310_lock;
static volatile uint32_t s_cc310_ready;
static volatile uint32_t s_cc310_aborted;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
static volatile uint32_t s_cc310_operation_count;
static volatile uint32_t s_cc310_fallback_count;
#endif


static const uint8_t s_p256_prime[NOXTLS_CC310_P256_BYTES] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x01u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
};

static uint8_t noxtls_cc310_try_lock(void)
{
#if defined(__GNUC__) || defined(__clang__)
    uint32_t expected = 0u;
    return __atomic_compare_exchange_n(
        &s_cc310_lock, &expected, 1u, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED) ? 1u : 0u;
#else
    if(s_cc310_lock != 0u)
        return 0u;
    s_cc310_lock = 1u;
    return 1u;
#endif
}

static void noxtls_cc310_unlock(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s_cc310_lock, 0u, __ATOMIC_RELEASE);
#else
    s_cc310_lock = 0u;
#endif
}

static void noxtls_cc310_abort(char const * const reason)
{
    (void)reason;
    s_cc310_aborted = 1u;
    s_cc310_ready = 0u;
}

/* CryptoCell is guarded across the complete driver call by s_cc310_lock, so
 * its internal PAL mutex callbacks are intentionally unnecessary. */
void nrf_cc3xx_platform_mutex_init(void)
{
}

void nrf_cc3xx_platform_abort_init(void)
{
    static const nrf_cc3xx_platform_abort_apis_t abort_apis = {
        NULL, noxtls_cc310_abort
    };
    nrf_cc3xx_platform_set_abort(&abort_apis);
}

/* The Nordic PSA driver uses the standard Mbed TLS allocation hooks. Keep
 * weak definitions so a full Mbed TLS integration can override them. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void * mbedtls_calloc(size_t count, size_t size)
{
    return calloc(count, size);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void mbedtls_free(void * pointer)
{
    free(pointer);
}

static uint8_t noxtls_cc310_is_p256(const ecc_curve_params_t * curve)
{
    return curve != NULL && curve->p != NULL &&
           curve->size == NOXTLS_CC310_P256_BYTES &&
           memcmp(curve->p, s_p256_prime, sizeof(s_p256_prime)) == 0 ?
           1u : 0u;
}

static psa_key_attributes_t noxtls_cc310_p256_attributes(void)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE |
                                         PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    return attributes;
}

static uint8_t noxtls_cc310_ensure_ready(void)
{
    if(s_cc310_ready != 0u && s_cc310_aborted == 0u)
        return 1u;

    nrf_cc3xx_platform_mutex_init();
    nrf_cc3xx_platform_abort_init();
    /* NoxTLS generates private scalars through its registered entropy source.
     * Public-key derivation and ECDH are deterministic, so initializing the
     * CC310 RNG/DRBG here only adds a large first-use latency. */
    if(nrf_cc3xx_platform_init_no_rng() != 0 || s_cc310_aborted != 0u)
    {
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        s_cc310_fallback_count++;
#endif
        return 0u;
    }
    s_cc310_ready = 1u;
    return 1u;
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(
    ecc_point_t * result, const uint8_t * scalar, const ecc_point_t * point,
    const ecc_curve_params_t * curve)
{
    psa_key_attributes_t attributes;
    uint8_t public_key[NOXTLS_CC310_PUBLIC_KEY_BYTES];
    size_t public_key_length = 0u;
    psa_status_t status;

    if(result == NULL || scalar == NULL || point == NULL || curve == NULL)
        return NOXTLS_RETURN_NULL;
    /* The PSA driver can export d*G, but raw key agreement only exposes the
     * x-coordinate for arbitrary points. ECDH therefore uses its dedicated
     * hook below; other arbitrary point operations retain software fallback. */
    if(noxtls_cc310_is_p256(curve) == 0u ||
       point->size != NOXTLS_CC310_P256_BYTES ||
       memcmp(point->x, curve->G.x, NOXTLS_CC310_P256_BYTES) != 0 ||
       memcmp(point->y, curve->G.y, NOXTLS_CC310_P256_BYTES) != 0)
    {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(noxtls_cc310_try_lock() == 0u)
        return NOXTLS_RETURN_NOT_SUPPORTED;
    if(noxtls_cc310_ensure_ready() == 0u)
    {
        noxtls_cc310_unlock();
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    attributes = noxtls_cc310_p256_attributes();
    status = cc3xx_internal_export_ecc_wrst_public_key(
        &attributes, scalar, NOXTLS_CC310_P256_BYTES,
        public_key, sizeof(public_key), &public_key_length);
    if(status == PSA_SUCCESS &&
       public_key_length == NOXTLS_CC310_PUBLIC_KEY_BYTES &&
       public_key[0] == 0x04u)
    {
        memcpy(result->x, &public_key[1], NOXTLS_CC310_P256_BYTES);
        memcpy(result->y, &public_key[1u + NOXTLS_CC310_P256_BYTES],
               NOXTLS_CC310_P256_BYTES);
        result->size = NOXTLS_CC310_P256_BYTES;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        s_cc310_operation_count++;
#endif
        noxtls_cc310_unlock();
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    s_cc310_fallback_count++;
#endif
    noxtls_cc310_unlock();
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ecdh_compute_shared_secret_accel_port(
    const ecc_key_t * private_key, const ecc_point_t * peer_public_key,
    uint8_t * shared_secret, uint32_t * shared_secret_len)
{
    uint8_t public_key[NOXTLS_CC310_PUBLIC_KEY_BYTES];
    size_t output_length = 0u;
    psa_status_t status;

    if(private_key == NULL || peer_public_key == NULL ||
       shared_secret == NULL || shared_secret_len == NULL)
    {
        return NOXTLS_RETURN_NULL;
    }
    if(private_key->d == NULL ||
       noxtls_cc310_is_p256(private_key->curve) == 0u ||
       peer_public_key->size != NOXTLS_CC310_P256_BYTES ||
       *shared_secret_len < NOXTLS_CC310_P256_BYTES)
    {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(noxtls_cc310_try_lock() == 0u)
        return NOXTLS_RETURN_NOT_SUPPORTED;
    if(noxtls_cc310_ensure_ready() == 0u)
    {
        noxtls_cc310_unlock();
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    public_key[0] = 0x04u;
    memcpy(&public_key[1], peer_public_key->x, NOXTLS_CC310_P256_BYTES);
    memcpy(&public_key[1u + NOXTLS_CC310_P256_BYTES], peer_public_key->y,
           NOXTLS_CC310_P256_BYTES);
    status = cc3xx_ecdh_calc_secret_wrst(
        PSA_ECC_FAMILY_SECP_R1, 256u,
        private_key->d, NOXTLS_CC310_P256_BYTES,
        public_key, sizeof(public_key), shared_secret, *shared_secret_len,
        &output_length);
    if(status == PSA_SUCCESS && output_length == NOXTLS_CC310_P256_BYTES)
    {
        *shared_secret_len = (uint32_t)output_length;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        s_cc310_operation_count++;
#endif
        noxtls_cc310_unlock();
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    s_cc310_fallback_count++;
#endif
    noxtls_cc310_unlock();
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
uint8_t noxtls_ecc_accel_is_ready(void)
{
    return s_cc310_ready != 0u && s_cc310_aborted == 0u ? 1u : 0u;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_cc310_operation_count;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_cc310_fallback_count;
}
#endif
