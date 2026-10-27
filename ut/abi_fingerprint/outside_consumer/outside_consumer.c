/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    outside_consumer.c
* Summary: A NoxTLS consumer compiled with mismatched directory definitions
*****************************************************************************/

/**
 * @file outside_consumer.c
 * @brief Compiled with directory definitions that contradict the library's
 *        (CMakeLists.txt next to this file); the NoxTLS targets' build
 *        configuration (cmake/noxtls_build_config.cmake) must restore the
 *        library's values. EXPECT_* carry the library's values under names the
 *        build configuration does not touch. Linking checks the ABI fingerprint.
 */

#include <stdio.h>

#include "noxtls_tls13.h"

#if !defined(NOXTLS_BUILD_CONFIG) || (NOXTLS_BUILD_CONFIG == 0)
#error "The NoxTLS targets did not pass NOXTLS_BUILD_CONFIG to this consumer."
#endif
#if (NOXTLS_FEATURE_DH + 0) != (EXPECT_NOXTLS_FEATURE_DH + 0)
#error "NOXTLS_FEATURE_DH differs from the library's."
#endif
#if (NOXTLS_FEATURE_ML_KEM + 0) != (EXPECT_NOXTLS_FEATURE_ML_KEM + 0)
#error "NOXTLS_FEATURE_ML_KEM differs from the library's."
#endif
#if (NOXTLS_FEATURE_DTLS + 0) != (EXPECT_NOXTLS_FEATURE_DTLS + 0)
#error "NOXTLS_FEATURE_DTLS differs from the library's."
#endif
#if (NOXTLS_FEATURE_X25519 + 0) != (EXPECT_NOXTLS_FEATURE_X25519 + 0)
#error "NOXTLS_FEATURE_X25519 differs from the library's."
#endif
#if (NOXTLS_CONFIG_STATIC_MEMORY + 0) != (EXPECT_NOXTLS_CONFIG_STATIC_MEMORY + 0)
#error "NOXTLS_CONFIG_STATIC_MEMORY differs from the library's."
#endif

/** Stringify an expanded macro. */
#define OC_STR2(x) #x
#define OC_STR(x) OC_STR2(x)

/**
 * @brief Report the configuration and the fingerprint this consumer requires.
 * @return 0.
 */
int main(void)
{
    (void)printf("DH %d ML-KEM %d DTLS %d static memory %d algorithm filter %d; requires %s\n",
                 (int)NOXTLS_FEATURE_DH, (int)NOXTLS_FEATURE_ML_KEM, (int)NOXTLS_FEATURE_DTLS,
                 (int)NOXTLS_CONFIG_STATIC_MEMORY, (int)NOXTLS_TLS_ALGORITHM_FILTER,
                 OC_STR(NOXTLS_ABI_SYMBOL));
    return 0;
}
