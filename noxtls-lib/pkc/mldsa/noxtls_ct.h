/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

﻿#ifndef NOXTLS_MLDSA_CT_H
#define NOXTLS_MLDSA_CT_H

#include <stddef.h>
#include <stdint.h>

#include "noxtls_mldsa_internal_common.h"

/* Volatile blocker used by value-barrier helpers. */
#define noxtls_mld_ct_opt_blocker_u64 MLD_NAMESPACE(ct_opt_blocker_u64)
extern volatile uint64_t noxtls_mld_ct_opt_blocker_u64;

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE int32_t noxtls_mld_cast_uint32_to_int32(uint32_t x)
{
    return (int32_t)x;
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE uint32_t noxtls_mld_cast_int64_to_uint32(int64_t x)
{
    return (uint32_t)(x & (int64_t)UINT32_MAX);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE uint32_t noxtls_mld_cast_int32_to_uint32(int32_t x)
{
    return noxtls_mld_cast_int64_to_uint32((int64_t)x);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE int64_t noxtls_mld_value_barrier_i64(int64_t value)
{
    return value ^ (int64_t)noxtls_mld_ct_opt_blocker_u64;
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE uint32_t noxtls_mld_value_barrier_u32(uint32_t value)
{
    return value ^ (uint32_t)noxtls_mld_ct_opt_blocker_u64;
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_ALWAYS_INLINE uint8_t noxtls_mld_value_barrier_u8(uint8_t value)
{
    return value ^ (uint8_t)noxtls_mld_ct_opt_blocker_u64;
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int32_t noxtls_mld_ct_sel_int32(int32_t a, int32_t b, uint32_t cond)
{
    uint32_t au = noxtls_mld_cast_int32_to_uint32(a);
    uint32_t bu = noxtls_mld_cast_int32_to_uint32(b);
    uint32_t mask = noxtls_mld_value_barrier_u32(cond);
    uint32_t out = bu ^ (mask & (au ^ bu));
    return noxtls_mld_cast_uint32_to_int32(out);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE uint32_t noxtls_mld_ct_cmask_nonzero_u32(uint32_t x)
{
    int64_t tmp = noxtls_mld_value_barrier_i64(-((int64_t)x));
    tmp >>= 32;
    return noxtls_mld_cast_int64_to_uint32(tmp);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE uint8_t noxtls_mld_ct_cmask_nonzero_u8(uint8_t x)
{
    return (uint8_t)(noxtls_mld_ct_cmask_nonzero_u32((uint32_t)x) & UINT8_MAX);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE uint32_t noxtls_mld_ct_cmask_neg_i32(int32_t x)
{
    int64_t tmp = noxtls_mld_value_barrier_i64((int64_t)x);
    tmp >>= 31;
    return noxtls_mld_cast_int64_to_uint32(tmp);
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int32_t noxtls_mld_ct_abs_i32(int32_t x)
{
    return noxtls_mld_ct_sel_int32(-x, x, noxtls_mld_ct_cmask_neg_i32(x));
}

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE uint8_t noxtls_mld_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                        size_t len)
{
    size_t i;
    uint8_t diff = 0u;
    uint8_t fold = 0u;

    for(i = 0u; i < len; ++i) {
        uint8_t delta = (uint8_t)(a[i] ^ b[i]);
        diff |= delta;
        fold ^= delta;
    }

    return noxtls_mld_value_barrier_u8((uint8_t)(noxtls_mld_ct_cmask_nonzero_u8(diff) ^ fold)) ^ fold;
}

#if !defined(MLD_CONFIG_CUSTOM_ZEROIZE)
static MLD_INLINE void noxtls_mld_zeroize(void *ptr, size_t len)
{
    size_t i;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for(i = 0u; i < len; ++i) {
        p[i] = 0u;
    }
}
#endif

#endif /* NOXTLS_MLDSA_CT_H */
