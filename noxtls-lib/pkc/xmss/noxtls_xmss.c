/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_xmss.c
* Summary: XMSS/XMSS^MT API scaffold.
*****************************************************************************/

#include "noxtls_xmss.h"

/**
 * @brief Get the public key length
 * 
 * @param param The parameter
 * @return The public key length
 */
uint32_t noxtls_xmss_public_key_len(noxtls_xmss_param_t param)
{
    switch(param) {
        case NOXTLS_XMSS_SHA2_10_256:
        case NOXTLS_XMSS_SHA2_16_256:
        case NOXTLS_XMSSMT_SHA2_20_2_256:
        case NOXTLS_XMSSMT_SHA2_20_4_256:
            return 64U;
        default:
            return 0U;
    }
}

/**
 * @brief Get the secret key length
 * 
 * @param param The parameter
 * @return The secret key length
 */
uint32_t noxtls_xmss_secret_key_len(noxtls_xmss_param_t param)
{
    switch(param) {
        case NOXTLS_XMSS_SHA2_10_256:
        case NOXTLS_XMSS_SHA2_16_256:
        case NOXTLS_XMSSMT_SHA2_20_2_256:
        case NOXTLS_XMSSMT_SHA2_20_4_256:
            return 132u;
        default:
            return 0U;
    }
}

/**
 * @brief Get the signature length
 * 
 * @param param The parameter
 * @return The signature length
 */
uint32_t noxtls_xmss_signature_len(noxtls_xmss_param_t param)
{
    switch(param) {
        case NOXTLS_XMSS_SHA2_10_256: return 2500u;
        case NOXTLS_XMSS_SHA2_16_256: return 2692u;
        case NOXTLS_XMSSMT_SHA2_20_2_256: return 4968u;
        case NOXTLS_XMSSMT_SHA2_20_4_256: return 5608u;
        default: return 0U;
    }
}

/**
 * @brief Generate a XMSS key pair
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param public_key_len The length of the public key
 * @param secret_key The secret key
 * @param secret_key_len The length of the secret key
 * @return The return value
 */
noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param,
                                   uint8_t *public_key,
                                   uint32_t public_key_len,
                                   uint8_t *secret_key,
                                   uint32_t secret_key_len)
{
    (void)param;
    (void)public_key;
    (void)public_key_len;
    (void)secret_key;
    (void)secret_key_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Sign a message with XMSS
 * 
 * @param param The parameter
 * @param secret_key The secret key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature 
 * @return NOXTLS_RETURN_NOT_SUPPORTED
 */
noxtls_return_t noxtls_xmss_sign(noxtls_xmss_param_t param,
                                 const uint8_t *secret_key,
                                 const uint8_t *message,
                                 uint32_t message_len,
                                 uint8_t *signature,
                                 uint32_t *signature_len)
{
    (void)param;
    (void)secret_key;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}


/**
 * @brief Verify a message with XMSS
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature 
 * @return The return value
 */
noxtls_return_t noxtls_xmss_verify(noxtls_xmss_param_t param,
                                   const uint8_t *public_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t *signature,
                                   uint32_t signature_len)
{
    (void)param;
    (void)public_key;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

