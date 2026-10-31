/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_test_util.h
* Summary: Minimal helpers shared by the ut/crypto_sym regression tests.
*
* Each test is a plain C99 program: checks are counted, every failing check
* prints its location and (for byte comparisons) both values, and the
* program returns non-zero when any check failed. No test framework is used.
*****************************************************************************/
#ifndef CRYPTO_SYM_TEST_UTIL_H_
#define CRYPTO_SYM_TEST_UTIL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"

/** Largest hex vector decoded by cs_hex()/cs_expect_hex(), in bytes. */
#define CS_HEX_MAX (20000U)

static uint32_t g_cs_checks;
static uint32_t g_cs_failures;
static const char *g_cs_section = "";

/** Name the group of checks that follows (printed with every failure). */
static inline void cs_section(const char *name)
{
    g_cs_section = name;
}

/** Record one check; prints the failing condition with its location. */
static inline int cs_check(int ok, const char *expr, const char *file, int line)
{
    g_cs_checks += 1U;
    if (ok == 0) {
        g_cs_failures += 1U;
        (void)fprintf(stderr, "FAIL [%s] %s:%d: %s\n", g_cs_section, file, line, expr);
    }
    return ok;
}

#define CHECK(cond) cs_check(((cond) ? 1 : 0), #cond, __FILE__, __LINE__)
#define CHECK_RC(call, expected) \
    cs_check_rc((noxtls_return_t)(call), (noxtls_return_t)(expected), #call, __FILE__, __LINE__)

/** Check a return code; on mismatch print both values. */
static inline int cs_check_rc(noxtls_return_t got, noxtls_return_t expected,
                              const char *expr, const char *file, int line)
{
    int ok = (got == expected) ? 1 : 0;
    g_cs_checks += 1U;
    if (ok == 0) {
        g_cs_failures += 1U;
        (void)fprintf(stderr, "FAIL [%s] %s:%d: %s returned %u, expected %u\n",
                      g_cs_section, file, line, expr, (unsigned)got, (unsigned)expected);
    }
    return ok;
}

static inline int cs_nibble(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a') + 10;
    }
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A') + 10;
    }
    return -1;
}

/**
 * Decode a hex string into out (capacity cap). Returns the number of bytes,
 * or aborts the program on malformed input (a broken vector is a test bug).
 */
static inline uint32_t cs_hex(const char *hex, uint8_t *out, uint32_t cap)
{
    uint32_t n = 0U;
    size_t len;
    size_t i;

    if (hex == NULL) {
        return 0U;
    }
    len = strlen(hex);
    if (((len % 2U) != 0U) || ((len / 2U) > cap)) {
        (void)fprintf(stderr, "BROKEN VECTOR (length %u, cap %u)\n", (unsigned)len, (unsigned)cap);
        exit(2);
    }
    for (i = 0U; i < len; i += 2U) {
        int hi = cs_nibble(hex[i]);
        int lo = cs_nibble(hex[i + 1U]);
        if ((hi < 0) || (lo < 0)) {
            (void)fprintf(stderr, "BROKEN VECTOR (bad hex digit)\n");
            exit(2);
        }
        out[n] = (uint8_t)((hi << 4) | lo);
        n += 1U;
    }
    return n;
}

/** Length in bytes of a hex vector (0 for NULL). */
static inline uint32_t cs_hex_len(const char *hex)
{
    return (hex == NULL) ? 0U : (uint32_t)(strlen(hex) / 2U);
}

static inline void cs_dump(const char *label, const uint8_t *p, uint32_t len)
{
    uint32_t i;
    (void)fprintf(stderr, "    %s (%u):", label, (unsigned)len);
    for (i = 0U; i < len; i += 1U) {
        if ((i % 32U) == 0U) {
            (void)fprintf(stderr, "\n      ");
        }
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

/** Compare len bytes; on mismatch print both buffers. */
static inline int cs_expect_mem_at(const char *what, const uint8_t *got, const uint8_t *exp,
                                   uint32_t len, const char *file, int line)
{
    int ok = (memcmp(got, exp, len) == 0) ? 1 : 0;
    g_cs_checks += 1U;
    if (ok == 0) {
        uint32_t first = 0U;
        while ((first < len) && (got[first] == exp[first])) {
            first += 1U;
        }
        g_cs_failures += 1U;
        (void)fprintf(stderr, "FAIL [%s] %s:%d: %s mismatch (first difference at byte %u)\n",
                      g_cs_section, file, line, what, (unsigned)first);
        cs_dump("got", got, (len > 96U) ? 96U : len);
        cs_dump("exp", exp, (len > 96U) ? 96U : len);
    }
    return ok;
}

/** Compare got (len bytes) with a hex vector that must have exactly len bytes. */
static inline int cs_expect_hex_at(const char *what, const uint8_t *got, uint32_t len,
                                   const char *hex, const char *file, int line)
{
    static uint8_t exp[CS_HEX_MAX];
    uint32_t n = cs_hex(hex, exp, (uint32_t)sizeof(exp));
    if (n != len) {
        g_cs_checks += 1U;
        g_cs_failures += 1U;
        (void)fprintf(stderr, "FAIL [%s] %s:%d: %s length %u, vector has %u\n",
                      g_cs_section, file, line, what, (unsigned)len, (unsigned)n);
        return 0;
    }
    return cs_expect_mem_at(what, got, exp, len, file, line);
}

#define EXPECT_MEM(what, got, exp, len) cs_expect_mem_at((what), (got), (exp), (uint32_t)(len), __FILE__, __LINE__)
#define EXPECT_HEX(what, got, len, hex) cs_expect_hex_at((what), (got), (uint32_t)(len), (hex), __FILE__, __LINE__)

/**
 * Deterministic test data: xorshift32, top byte of each state.
 * Mirrored by cs_fill() in gen_crypto_sym_vectors.py.
 */
static inline void cs_fill(uint8_t *buf, uint32_t len, uint32_t seed)
{
    uint32_t x = (seed == 0U) ? 0x9E3779B9U : seed;
    uint32_t i;
    for (i = 0U; i < len; i += 1U) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)(x >> 24);
    }
}

/** 1 when every byte of p is zero. */
static inline int cs_all_zero(const void *p, size_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0U; i < len; i += 1U) {
        if (b[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

/** 1 when every byte of p equals v. */
static inline int cs_all_byte(const void *p, size_t len, uint8_t v)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0U; i < len; i += 1U) {
        if (b[i] != v) {
            return 0;
        }
    }
    return 1;
}

/**
 * Irregular chunk schedule used for every streaming test: crosses the 64-,
 * 128-, 136-, 144- and 168-byte block/rate boundaries and includes zero-length
 * updates. Call with an increasing index; returns the next chunk length.
 */
static inline uint32_t cs_chunk(uint32_t index)
{
    static const uint32_t k_chunks[] = {
        1U, 3U, 7U, 13U, 0U, 63U, 64U, 65U, 127U, 128U, 129U, 135U, 136U, 137U,
        143U, 144U, 145U, 0U, 167U, 168U, 169U, 200U, 255U, 256U, 257U, 1000U, 2U, 5U
    };
    return k_chunks[index % (uint32_t)(sizeof(k_chunks) / sizeof(k_chunks[0]))];
}

/** Print the summary line and return the process exit status. */
static inline int cs_finish(const char *test_name)
{
    if (g_cs_failures == 0U) {
        (void)printf("%s: PASS (%u checks)\n", test_name, (unsigned)g_cs_checks);
        return 0;
    }
    (void)printf("%s: FAIL (%u of %u checks failed)\n", test_name,
                 (unsigned)g_cs_failures, (unsigned)g_cs_checks);
    return 1;
}

#endif /* CRYPTO_SYM_TEST_UTIL_H_ */
