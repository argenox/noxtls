/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    noxtls_static_profile_host_test.h
* Summary: Static memory profile of the host test configuration
*****************************************************************************/
/**
 * @file noxtls_static_profile_host_test.h
 * @brief Static memory for the second CTest configuration (ut/static_memory).
 *
 * The existing TLS 1.3 / DTLS 1.3 suites run unchanged on top of the region
 * allocator: they keep the default 16 KB records and certificate chains, use the
 * plain context init functions (two library pool blocks), and parse their test
 * PKI and keys in the global arena, which is sized generously for that.
 */
#ifndef NOXTLS_STATIC_PROFILE_HOST_TEST_H_
#define NOXTLS_STATIC_PROFILE_HOST_TEST_H_

#ifndef NOXTLS_CONFIG_STATIC_MEMORY
#define NOXTLS_CONFIG_STATIC_MEMORY 1
#endif
/* Test PKI: an RSA-2048 root and leaf, ECDSA roots and intermediates. */
#ifndef NOXTLS_STATIC_TRUST_ANCHORS_MAX
#define NOXTLS_STATIC_TRUST_ANCHORS_MAX 4U
#endif
#ifndef NOXTLS_STATIC_CERT_DER_MAX
#define NOXTLS_STATIC_CERT_DER_MAX 2048U
#endif
/* Fixture keys, DTLS 1.2 reassembly tests on raw contexts and X.509 tests run
 * outside any connection, in the global arena. */
#ifndef NOXTLS_STATIC_GLOBAL_EXTRA
#define NOXTLS_STATIC_GLOBAL_EXTRA (320U * 1024U)
#endif
#ifndef NOXTLS_STATIC_TLS_TX_QUEUE_SIZE
#define NOXTLS_STATIC_TLS_TX_QUEUE_SIZE (64U * 1024U)
#endif

#endif /* NOXTLS_STATIC_PROFILE_HOST_TEST_H_ */
