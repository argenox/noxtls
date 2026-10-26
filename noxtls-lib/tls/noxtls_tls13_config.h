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
* File:    noxtls_tls13_config.h
* Summary: Build-time TLS 1.3 and DTLS 1.3 peer authentication profile
*****************************************************************************/
/**
 * @file noxtls_tls13_config.h
 * @brief Build-time selection of certificate-based peer authentication.
 * @ingroup noxtls_tls
 */
#ifndef NOXTLS_TLS13_CONFIG_H_
#define NOXTLS_TLS13_CONFIG_H_

/**
 * @brief Accept certificate-based peer authentication in TLS 1.3 and DTLS 1.3.
 *
 * One (default) keeps the full RFC 8446 (August 2018) Section 4.4.2
 * Certificate and Section 4.4.3 CertificateVerify receive paths for clients
 * and for servers that request client authentication. Zero builds a
 * PSK-only profile: a client aborts with handshake_failure when the server
 * did not select its PSK, before any Certificate is read, a server never
 * sends CertificateRequest, and no peer certificate parser is linked. Use
 * zero only when every context authenticates with an external PSK.
 */
#ifndef NOXTLS_TLS13_PEER_CERTIFICATES
#define NOXTLS_TLS13_PEER_CERTIFICATES 1
#endif

/**
 * @brief DTLS 1.3 integrity limit for AEAD_AES_128_GCM, AEAD_AES_256_GCM and
 * AEAD_CHACHA20_POLY1305.
 *
 * RFC 9147 (DTLS 1.3, April 2022) Section 4.5.3: records that fail authentication are
 * counted per key, and the connection is closed once the count exceeds 2^36. An
 * application may lower the value; raising it above the RFC figure is not allowed.
 */
#ifndef NOXTLS_DTLS13_INTEGRITY_LIMIT_GCM_CHACHA
#define NOXTLS_DTLS13_INTEGRITY_LIMIT_GCM_CHACHA ((uint64_t)1U << 36U)
#endif

/**
 * @brief DTLS 1.3 integrity limit for AEAD_AES_128_CCM.
 *
 * RFC 9147 Section 4.5.3 and Appendix B.2: 2^23.5 records, rounded down to 11863283.
 */
#ifndef NOXTLS_DTLS13_INTEGRITY_LIMIT_CCM
#define NOXTLS_DTLS13_INTEGRITY_LIMIT_CCM ((uint64_t)11863283U)
#endif

/**
 * @brief DTLS 1.3 integrity limit for AEAD_AES_128_CCM_8.
 *
 * RFC 9147 Section 4.5.3 requires a usage limit for CCM_8; Appendix B.3 derives 2^7.
 */
#ifndef NOXTLS_DTLS13_INTEGRITY_LIMIT_CCM_8
#define NOXTLS_DTLS13_INTEGRITY_LIMIT_CCM_8 ((uint64_t)1U << 7U)
#endif

#endif /* NOXTLS_TLS13_CONFIG_H_ */
