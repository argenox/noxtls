/* Copyright (c) 2026 Argenox Technologies LLC. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 * File: ed25519_readonly_test_config.h
 * Summary: Bounded deterministic Ed25519 differential-test geometry.
 */
#ifndef ED25519_READONLY_TEST_CONFIG_H
#define ED25519_READONLY_TEST_CONFIG_H
#define ED_READONLY_TEST_LCG_MULTIPLIER 1664525U
#define ED_READONLY_TEST_LCG_INCREMENT 1013904223U
#define ED_READONLY_TEST_TOP_SHIFT 24U
#define ED_READONLY_TEST_CASES 64U
#define ED_READONLY_TEST_SEED 0x51c4a927U
#define ED_READONLY_TEST_SCALAR_BYTES 32U
#define ED_READONLY_TEST_BYTE_BITS 8U
#define ED_READONLY_TEST_CANONICAL_TOP_MASK 0x0fU
/** RFC 8032 base-point encoding, independent of production table storage. */
#define ED_READONLY_TEST_BASE_POINT { \
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, \
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, \
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, \
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 }
#endif
