/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_lms.c
* Summary: LMS/HSS API scaffold.
*
*****************************************************************************/

#include "noxtls_lms.h"

/**
 * @brief Get the public key length
 * 
 * @param param The parameter
 * @return The public key length
 */
uint32_t noxtls_lms_public_key_len(noxtls_lms_param_t param)
{
    switch(param) {
        case NOXTLS_LMS_SHA256_M32_H5:
        case NOXTLS_LMS_SHA256_M32_H10:
        case NOXTLS_LMS_SHA256_M32_H15:
        case NOXTLS_HSS_SHA256_M32_H10_D2:
        case NOXTLS_HSS_SHA256_M32_H15_D2:
            return 56u;
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
uint32_t noxtls_lms_secret_key_len(noxtls_lms_param_t param)
{
    switch(param) {
        case NOXTLS_LMS_SHA256_M32_H5:
        case NOXTLS_LMS_SHA256_M32_H10:
        case NOXTLS_LMS_SHA256_M32_H15:
        case NOXTLS_HSS_SHA256_M32_H10_D2:
        case NOXTLS_HSS_SHA256_M32_H15_D2:
            return 128U;
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
uint32_t noxtls_lms_signature_len(noxtls_lms_param_t param)
{
    switch(param) {
        case NOXTLS_LMS_SHA256_M32_H5: return 1452u;
        case NOXTLS_LMS_SHA256_M32_H10: return 1708u;
        case NOXTLS_LMS_SHA256_M32_H15: return 1964u;
        case NOXTLS_HSS_SHA256_M32_H10_D2: return 3480u;
        case NOXTLS_HSS_SHA256_M32_H15_D2: return 3992u;
        default: return 0U;
    }
}

/**
 * @brief Generate a LMS key pair
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param public_key_len The length of the public key
 * @param secret_key The secret key
 * @param secret_key_len The length of the secret key
 * @return The return value
 */
noxtls_return_t noxtls_lms_keygen(noxtls_lms_param_t param,
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
 * @brief Sign a message with LMS
 * 
 * @param param The parameter
 * @param secret_key The secret key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature 
 * @return The return value
 */
noxtls_return_t noxtls_lms_sign(noxtls_lms_param_t param,
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
 * @brief Verify a message with LMS
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, 
           NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_lms_verify(noxtls_lms_param_t param,
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

