/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cc13xx_crypto_atomic.h
* Summary: Internal engine guards and saturating counters for CC13xx ports
*****************************************************************************/
/**
 * @file noxtls_cc13xx_crypto_atomic.h
 * @brief Internal lock-free engine guards and diagnostic counters.
 * @ingroup noxtls_cc13xx_crypto
 *
 * Not part of the public binding. Primitive selection, strongest first:
 * - C11 <stdatomic.h>: atomic_flag test-and-set/clear and atomic counters;
 * - MSVC Interlocked intrinsics (MSVC C provides <stdatomic.h> only with
 *   /std:c11 /experimental:c11atomics, which selects the first branch);
 * - otherwise GCC/Clang __atomic builtins, with the same semantics and code
 *   generation as C11, for the library's default C99 compilation.
 * Every supported CC13xx core (Cortex-M3, M4F, M33) implements these with
 * exclusive load/store instructions, so no call ever blocks or masks
 * interrupts.
 */
#ifndef NOXTLS_CC13XX_CRYPTO_ATOMIC_H
#define NOXTLS_CC13XX_CRYPTO_ATOMIC_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
/** @brief Selected primitive: C11 atomics. */
#define NOXTLS_CC13XX_ATOMIC_C11 1
/** @brief One engine's busy guard. */
typedef atomic_flag noxtls_cc13xx_guard_t;
/** @brief Saturating diagnostic counter. */
typedef atomic_uint_least32_t noxtls_cc13xx_counter_t;
/** @brief Idle guard initializer. */
#define NOXTLS_CC13XX_GUARD_IDLE ATOMIC_FLAG_INIT
#elif defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
/** @brief Selected primitive: MSVC Interlocked intrinsics. */
#define NOXTLS_CC13XX_ATOMIC_MSVC 1
/** @brief One engine's busy guard, accessed only through Interlocked intrinsics. */
typedef long noxtls_cc13xx_guard_t;
/** @brief Saturating diagnostic counter holding a 32-bit unsigned pattern. */
typedef long noxtls_cc13xx_counter_t;
/** @brief Idle guard initializer. */
#define NOXTLS_CC13XX_GUARD_IDLE 0L
/** @brief Busy guard value. */
#define NOXTLS_CC13XX_GUARD_BUSY 1L
#else
/* GCC, Clang (including clang-cl) and compilers that provide the same
 * builtins; a compiler without them fails to build here rather than silently
 * losing atomicity. */
/** @brief Selected primitive: GCC/Clang __atomic builtins. */
#define NOXTLS_CC13XX_ATOMIC_GNU 1
/** @brief One engine's busy guard, accessed only through __atomic builtins. */
typedef bool noxtls_cc13xx_guard_t;
/** @brief Saturating diagnostic counter, accessed only through __atomic builtins. */
typedef uint32_t noxtls_cc13xx_counter_t;
/** @brief Idle guard initializer. */
#define NOXTLS_CC13XX_GUARD_IDLE false
#endif

/** @brief Saturation value of a diagnostic counter. */
#define NOXTLS_CC13XX_COUNTER_MAX UINT32_MAX

/**
 * @brief Atomically take an idle engine guard (acquire ordering).
 * @internal
 *
 * @param[in,out] guard Engine guard.
 *
 * @return True when this caller now owns the engine; false when it was busy.
 */
static inline bool noxtls_cc13xx_guard_try_acquire(noxtls_cc13xx_guard_t *guard)
{
#if defined(NOXTLS_CC13XX_ATOMIC_C11)
    return !atomic_flag_test_and_set_explicit(guard, memory_order_acquire);
#elif defined(NOXTLS_CC13XX_ATOMIC_GNU)
    return !__atomic_test_and_set(guard, __ATOMIC_ACQUIRE);
#else
    return _InterlockedExchange(guard, NOXTLS_CC13XX_GUARD_BUSY) == NOXTLS_CC13XX_GUARD_IDLE;
#endif
}

/**
 * @brief Release an engine guard owned by this caller (release ordering).
 * @internal
 *
 * @param[in,out] guard Engine guard taken by noxtls_cc13xx_guard_try_acquire().
 */
static inline void noxtls_cc13xx_guard_release(noxtls_cc13xx_guard_t *guard)
{
#if defined(NOXTLS_CC13XX_ATOMIC_C11)
    atomic_flag_clear_explicit(guard, memory_order_release);
#elif defined(NOXTLS_CC13XX_ATOMIC_GNU)
    __atomic_clear(guard, __ATOMIC_RELEASE);
#else
    (void)_InterlockedExchange(guard, NOXTLS_CC13XX_GUARD_IDLE);
#endif
}

/**
 * @brief Read a diagnostic counter.
 * @internal
 *
 * @param[in] counter Counter storage.
 *
 * @return Current value.
 */
static inline uint32_t noxtls_cc13xx_counter_read(noxtls_cc13xx_counter_t *counter)
{
#if defined(NOXTLS_CC13XX_ATOMIC_C11)
    return (uint32_t)atomic_load_explicit(counter, memory_order_relaxed);
#elif defined(NOXTLS_CC13XX_ATOMIC_GNU)
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
#else
    return (uint32_t)_InterlockedCompareExchange(counter, 0L, 0L);
#endif
}

/**
 * @brief Set a diagnostic counter, for reset and saturation tests.
 * @internal
 *
 * @param[in,out] counter Counter storage.
 * @param[in] value New value.
 */
static inline void noxtls_cc13xx_counter_store(noxtls_cc13xx_counter_t *counter, uint32_t value)
{
#if defined(NOXTLS_CC13XX_ATOMIC_C11)
    atomic_store_explicit(counter, value, memory_order_relaxed);
#elif defined(NOXTLS_CC13XX_ATOMIC_GNU)
    __atomic_store_n(counter, value, __ATOMIC_RELAXED);
#else
    (void)_InterlockedExchange(counter, (long)value);
#endif
}

/**
 * @brief Increment a diagnostic counter without wraparound or lost updates.
 * @internal
 *
 * @param[in,out] counter Counter storage, saturating at NOXTLS_CC13XX_COUNTER_MAX.
 */
static inline void noxtls_cc13xx_counter_increment(noxtls_cc13xx_counter_t *counter)
{
#if defined(NOXTLS_CC13XX_ATOMIC_C11)
    uint_least32_t current = atomic_load_explicit(counter, memory_order_relaxed);
    while (current < NOXTLS_CC13XX_COUNTER_MAX) {
        if (atomic_compare_exchange_weak_explicit(counter, &current, current + 1U,
                memory_order_relaxed, memory_order_relaxed)) {
            break;
        }
    }
#elif defined(NOXTLS_CC13XX_ATOMIC_GNU)
    uint32_t current = __atomic_load_n(counter, __ATOMIC_RELAXED);
    while (current < NOXTLS_CC13XX_COUNTER_MAX) {
        if (__atomic_compare_exchange_n(counter, &current, current + 1U, true,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            break;
        }
    }
#else
    long current = _InterlockedCompareExchange(counter, 0L, 0L);
    while ((uint32_t)current < NOXTLS_CC13XX_COUNTER_MAX) {
        const long next = (long)((uint32_t)current + 1U);
        const long seen = _InterlockedCompareExchange(counter, next, current);
        if (seen == current) {
            break;
        }

        current = seen;
    }
#endif
}

#endif
