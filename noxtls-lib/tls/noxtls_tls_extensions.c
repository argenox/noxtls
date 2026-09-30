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
* File:    noxtls_tls_extensions.c
* Summary: TLS Extension Parsing Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "noxtls_tls_common.h"
#include "noxtls_ct.h"

/**
 * @brief Parse TLS extensions from extension list
 *
 * @param[in] data The data to parse the extensions from
 * @param[in] data_len The length of the data to parse the extensions from
 * @param[out] extensions The extensions to parse the extensions into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or extensions is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a TLS extension, NOXTLS_RETURN_BAD_DATA if the extensions is not a valid length for a TLS extension, NOXTLS_RETURN_FAILED if the extensions is not a valid extension for a TLS extension
 * @return NOXTLS_RETURN_FAILED if the extensions is not a valid extension for a TLS extension
 * @return NOXTLS_RETURN_RECORD_OVERFLOW if the extensions is not a valid extension for a TLS extension
 */
noxtls_return_t noxtls_tls_parse_extensions(const uint8_t *data, uint32_t data_len, tls_extensions_t *extensions)
{
    uint32_t offset = 0U;
    uint32_t extensions_len = 0U;
    uint32_t max_extensions = 64U;  /* Initial capacity; grow as needed. */
    
    if ((data == NULL) || (extensions == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((extensions), sizeof(tls_extensions_t));
    
    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Extensions length (2 bytes) */
    extensions_len = (((uint32_t)data[offset]) << 8U) | ((uint32_t)data[offset + 1U]);
    offset += 2U;

    if (extensions_len == 0U) {
        if (data_len != 2U) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        return NOXTLS_RETURN_SUCCESS;  /* No extensions */
    }
    
    if (extensions_len > (data_len - 2U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate extension array */
    extensions->extensions = (tls_extension_t*)NOXTLS_CALLOC(max_extensions, sizeof(tls_extension_t));
    if (extensions->extensions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse extensions */
    while ((offset < (extensions_len + 2U)) && ((offset + (uint32_t)sizeof(tls_extension_header_t)) <= data_len)) {
        if (extensions->count >= max_extensions) {
            uint32_t new_max = (uint32_t)(max_extensions * 2U);
            tls_extension_t *new_exts;
            if (new_max > 65536U) {
                (void)noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_RECORD_OVERFLOW;
            }
            new_exts = (tls_extension_t*)NOXTLS_REALLOC(extensions->extensions,
                                                 new_max * (sizeof(tls_extension_t)));
            if (new_exts == NULL) {
                (void)noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_secure_zero((&new_exts[max_extensions]),
                   (size_t)((new_max - max_extensions) * (sizeof(tls_extension_t))));
            extensions->extensions = new_exts;
            max_extensions = new_max;
        }
        
        tls_extension_t *ext = &extensions->extensions[extensions->count];
        
        /* Extension header (4 bytes) */
        ext->type = (uint16_t)((((uint16_t)data[offset]) << 8U) | ((uint16_t)data[offset + 1U]));
        ext->length = (uint16_t)((((uint16_t)data[offset + 2U]) << 8U) | ((uint16_t)data[offset + 3U]));
        offset += 4U;
        
        if ((ext->length > 0U) && ((offset + (uint32_t)ext->length) <= data_len)) {
            /* Allocate and copy extension data */
            ext->data = (uint8_t*)NOXTLS_MALLOC(ext->length);
            if (ext->data == NULL) {
                (void)noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_copy_u8(ext->data, (size_t)ext->length, &data[offset], (size_t)ext->length);
            offset += ext->length;
        } else if (ext->length > 0U) {
            /* Malformed extension length that overruns the extension block. */
            (void)noxtls_tls_extensions_free(extensions);
            return NOXTLS_RETURN_BAD_DATA;
        } else {
            ext->length = 0U;
            ext->data = NULL;
        }
        
        extensions->count += 1U;
        
        /* Parse known extensions */
        if (ext->type == TLS_EXTENSION_SERVER_NAME) {
                if (ext->length == 0U) {
                    (void)noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if (ext->data != NULL) {
                    if (extensions->sni != NULL) {
                        if (extensions->sni->hostname != NULL) {
                            (void)noxtls_free(extensions->sni->hostname);
                        }
                        (void)noxtls_free(extensions->sni);
                        extensions->sni = NULL;
                    }
                    extensions->sni = (tls_sni_extension_t*)NOXTLS_MALLOC(sizeof(tls_sni_extension_t));
                    if (extensions->sni == NULL) {
                        (void)noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                    {
                        noxtls_return_t sni_rc = noxtls_tls_parse_extension_sni(ext->data, ext->length, extensions->sni);
                        if (sni_rc != NOXTLS_RETURN_SUCCESS) {
                            (void)noxtls_free(extensions->sni);
                            extensions->sni = NULL;
                            (void)noxtls_tls_extensions_free(extensions);
                            return sni_rc;
                        }
                    }
                }
        } else if (ext->type == TLS_EXTENSION_SUPPORTED_GROUPS) {
                if ((ext->data != NULL) && (ext->length > 0U)) {
                    if (extensions->supported_groups != NULL) {
                        if (extensions->supported_groups->groups != NULL) {
                            (void)noxtls_free(extensions->supported_groups->groups);
                        }
                        (void)noxtls_free(extensions->supported_groups);
                        extensions->supported_groups = NULL;
                    }
                    extensions->supported_groups = (tls_supported_groups_extension_t*)NOXTLS_MALLOC(sizeof(tls_supported_groups_extension_t));
                    if (extensions->supported_groups != NULL) {
                        if (noxtls_tls_parse_extension_supported_groups(ext->data, ext->length, extensions->supported_groups) != NOXTLS_RETURN_SUCCESS) {
                            (void)noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        /* MISRA 15.7: final else path */
                        (void)noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
        } else if (ext->type == TLS_EXTENSION_KEY_SHARE) {
                if ((ext->data != NULL) && (ext->length > 0U)) {
                    if (extensions->key_share != NULL) {
                        if (extensions->key_share->entries != NULL) {
                            for (uint32_t k = 0U; k < extensions->key_share->count; k += 1U) {
                                if (extensions->key_share->entries[k].key_exchange != NULL) {
                                    (void)noxtls_free(extensions->key_share->entries[k].key_exchange);
                                }
                            }
                            (void)noxtls_free(extensions->key_share->entries);
                        }
                        (void)noxtls_free(extensions->key_share);
                        extensions->key_share = NULL;
                    }
                    extensions->key_share = (tls_key_share_list_extension_t*)NOXTLS_MALLOC(sizeof(tls_key_share_list_extension_t));
                    if (extensions->key_share != NULL) {
                        if (noxtls_tls_parse_extension_key_share(ext->data, ext->length, extensions->key_share) != NOXTLS_RETURN_SUCCESS) {
                            (void)noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        /* MISRA 15.7: final else path */
                        (void)noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
        } else if (ext->type == TLS_EXTENSION_SIGNATURE_ALGORITHMS) {
                if ((ext->data != NULL) && (ext->length > 0U)) {
                    if (extensions->signature_algorithms != NULL) {
                        if (extensions->signature_algorithms->algorithms != NULL) {
                            (void)noxtls_free(extensions->signature_algorithms->algorithms);
                        }
                        (void)noxtls_free(extensions->signature_algorithms);
                        extensions->signature_algorithms = NULL;
                    }
                    extensions->signature_algorithms = (tls_signature_algorithms_extension_t*)NOXTLS_MALLOC(sizeof(tls_signature_algorithms_extension_t));
                    if (extensions->signature_algorithms != NULL) {
                        if (noxtls_tls_parse_extension_signature_algorithms(ext->data, ext->length, extensions->signature_algorithms) != NOXTLS_RETURN_SUCCESS) {
                            (void)noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        /* MISRA 15.7: final else path */
                        (void)noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
        } else if (ext->type == TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                if (ext->length == 0U) {
                    (void)noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if (ext->data == NULL) {
                    (void)noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if (extensions->alpn != NULL) {
                    if (extensions->alpn->protocols != NULL) {
                        for (uint32_t k = 0U; k < extensions->alpn->count; k += 1U) {
                            if (extensions->alpn->protocols[k] != NULL) {
                                (void)noxtls_free(extensions->alpn->protocols[k]);
                            }
                        }
                        (void)noxtls_free((void *)extensions->alpn->protocols);
                    }
                    (void)noxtls_free(extensions->alpn);
                    extensions->alpn = NULL;
                }
                extensions->alpn = (tls_alpn_extension_t*)NOXTLS_MALLOC(sizeof(tls_alpn_extension_t));
                if (extensions->alpn == NULL) {
                    (void)noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_FAILED;
                }
                if (noxtls_tls_parse_extension_alpn(ext->data, ext->length, extensions->alpn) != NOXTLS_RETURN_SUCCESS) {
                    (void)noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
        } else if (ext->type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                if ((ext->data != NULL) && (ext->length > 0U)) {
                    if (extensions->supported_versions != NULL) {
                        if (extensions->supported_versions->versions != NULL) {
                            (void)noxtls_free(extensions->supported_versions->versions);
                        }
                        (void)noxtls_free(extensions->supported_versions);
                        extensions->supported_versions = NULL;
                    }
                    extensions->supported_versions = (tls_supported_versions_extension_t*)NOXTLS_MALLOC(sizeof(tls_supported_versions_extension_t));
                    if (extensions->supported_versions != NULL) {
                        if (noxtls_tls_parse_extension_supported_versions(ext->data, ext->length, extensions->supported_versions) != NOXTLS_RETURN_SUCCESS) {
                            (void)noxtls_free(extensions->supported_versions);
                            extensions->supported_versions = NULL;
                        }
                    }
                }
        } else {
                /* Unknown extension types are ignored (stored in the generic list above). */
        }
    }

    if((offset != (extensions_len + 2U)) ){
        (void)noxtls_tls_extensions_free(extensions);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if (offset != data_len) {
        (void)noxtls_tls_extensions_free(extensions);
        return NOXTLS_RETURN_BAD_DATA;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free parsed extensions
 *
 * @param[in] extensions The extensions to free
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the extensions is NULL
 */
static void tls_extensions_free_raw(tls_extensions_t *extensions)
{
    uint32_t i = 0U;
    if (extensions->extensions == NULL) {
        return;
    }
    for (i = 0U; i < extensions->count; i += 1U) {
        if (extensions->extensions[i].data != NULL) {
            (void)noxtls_free(extensions->extensions[i].data);
        }
    }
    (void)noxtls_free(extensions->extensions);
    extensions->extensions = NULL;
}

static void tls_extensions_free_sni(tls_extensions_t *extensions)
{
    if (extensions->sni == NULL) {
        return;
    }
    if (extensions->sni->hostname != NULL) {
        (void)noxtls_free(extensions->sni->hostname);
    }
    (void)noxtls_free(extensions->sni);
    extensions->sni = NULL;
}

static void tls_extensions_free_supported_groups(tls_extensions_t *extensions)
{
    if (extensions->supported_groups == NULL) {
        return;
    }
    if (extensions->supported_groups->groups != NULL) {
        (void)noxtls_free(extensions->supported_groups->groups);
    }
    (void)noxtls_free(extensions->supported_groups);
    extensions->supported_groups = NULL;
}

static void tls_extensions_free_key_share(tls_extensions_t *extensions)
{
    uint32_t i = 0U;
    if (extensions->key_share == NULL) {
        return;
    }
    if (extensions->key_share->entries != NULL) {
        for (i = 0U; i < extensions->key_share->count; i += 1U) {
            if (extensions->key_share->entries[i].key_exchange != NULL) {
                (void)noxtls_free(extensions->key_share->entries[i].key_exchange);
            }
        }
        (void)noxtls_free(extensions->key_share->entries);
    }
    (void)noxtls_free(extensions->key_share);
    extensions->key_share = NULL;
}

static void tls_extensions_free_signature_algorithms(tls_extensions_t *extensions)
{
    if (extensions->signature_algorithms == NULL) {
        return;
    }
    if (extensions->signature_algorithms->algorithms != NULL) {
        (void)noxtls_free(extensions->signature_algorithms->algorithms);
    }
    (void)noxtls_free(extensions->signature_algorithms);
    extensions->signature_algorithms = NULL;
}

static void tls_extensions_free_alpn(tls_extensions_t *extensions)
{
    uint32_t i = 0U;
    if (extensions->alpn == NULL) {
        return;
    }
    if (extensions->alpn->protocols != NULL) {
        for (i = 0U; i < extensions->alpn->count; i += 1U) {
            if (extensions->alpn->protocols[i] != NULL) {
                (void)noxtls_free(extensions->alpn->protocols[i]);
            }
        }
        (void)noxtls_free((void *)extensions->alpn->protocols);
    }
    (void)noxtls_free(extensions->alpn);
    extensions->alpn = NULL;
}

static void tls_extensions_free_supported_versions(tls_extensions_t *extensions)
{
    if (extensions->supported_versions == NULL) {
        return;
    }
    if (extensions->supported_versions->versions != NULL) {
        (void)noxtls_free(extensions->supported_versions->versions);
    }
    (void)noxtls_free(extensions->supported_versions);
    extensions->supported_versions = NULL;
}

noxtls_return_t noxtls_tls_extensions_free(tls_extensions_t *extensions)
{
    if (extensions == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    tls_extensions_free_raw(extensions);
    tls_extensions_free_sni(extensions);
    tls_extensions_free_supported_groups(extensions);
    tls_extensions_free_key_share(extensions);
    tls_extensions_free_signature_algorithms(extensions);
    tls_extensions_free_alpn(extensions);
    tls_extensions_free_supported_versions(extensions);

    noxtls_secure_zero((extensions), sizeof(tls_extensions_t));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Server Name Indication (SNI) extension
 *
 * @param[in] nm The name to validate
 * @param[in] name_len The length of the name to validate
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER if the name is not a valid name
 */
static noxtls_return_t tls_sni_validate_host_name_octets(const uint8_t *nm, uint16_t name_len)
{
    uint32_t j = 0U;
    for (j = 0U; j < (uint32_t)name_len; j += 1U) {
        uint8_t c = (uint8_t)(nm[j]);
        if (c == 0U) {
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
        /* Reject controls, DEL, and non-ASCII (tlsfuzzer invalid SNI / UTF-8 probes). */
        if ((c < 0x20U) || (c > 0x7eU)) {
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Server Name Indication (SNI) extension
 *
 * @param[in] data The data to parse the SNI extension from
 * @param[in] data_len The length of the data to parse the SNI extension from
 * @param[out] sni The SNI extension to parse the SNI extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or sni is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a SNI extension, NOXTLS_RETURN_BAD_DATA if the sni is not a valid SNI extension
 */
noxtls_return_t noxtls_tls_parse_extension_sni(const uint8_t *data, uint32_t data_len, tls_sni_extension_t *sni)
{
    uint16_t server_name_list_len = 0U;
    uint32_t list_end = 0U;
    uint32_t pos = 0U;
    int found_host = 0;
    const uint8_t *host_ptr = NULL;
    uint16_t host_len = 0U;

    if ((data == NULL) || (sni == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((sni), sizeof(tls_sni_extension_t));

    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    server_name_list_len = (uint16_t)(((uint16_t)data[0] <<8U) | (uint16_t)data[1]);
    if ((server_name_list_len == 0U) ||
       (((uint32_t)2U + (uint32_t)server_name_list_len) != data_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    list_end = 2U + (uint32_t)server_name_list_len;
    pos = 2U;

    while (pos < list_end) {
        uint8_t name_type = 0U;
        uint16_t name_len = 0U;

        if ((pos + 3U) > list_end) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        name_type = data[pos];
        pos += 1U;
        name_len = (uint16_t)(((uint16_t)data[pos] <<8U) | (uint16_t)data[pos + 1U]);
        pos += 2U;
        if ((pos + (uint32_t)name_len) > list_end) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        if (name_type == 0U) {
            noxtls_return_t vrc = NOXTLS_RETURN_FAILED;
            if (found_host != 0) {
                /* RFC 6066: client MUST NOT send multiple host_name entries. */
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
            if (name_len == 0U) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            vrc = tls_sni_validate_host_name_octets(&data[pos], name_len);
            if (vrc != NOXTLS_RETURN_SUCCESS) {
                return vrc;
            }
            found_host = 1;
            sni->name_type = 0U;
            sni->name_len = name_len;
            host_ptr = &data[pos];
            host_len = name_len;
            pos += (uint32_t)name_len;
        } else {
            /* Unknown name_type: ignore (RFC 6066; tlsfuzzer multiple-type probes). */
            pos += (uint32_t)name_len;
        }
    }

    if ((found_host == 0) || (host_ptr == NULL) || (host_len == 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    sni->hostname = (uint8_t *)NOXTLS_MALLOC((size_t)host_len + 1U);
    if (sni->hostname == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    {
        const uint8_t *src = host_ptr;
        uint8_t *dst = sni->hostname;
        uint32_t hi = 0U;
        for(hi = 0U; hi < host_len; hi += 1U) {
            dst[hi] = (uint8_t)src[hi];
        }
    }
    sni->hostname[host_len] = 0U;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Supported Groups extension
 *
 * @param[in] data The data to parse the Supported Groups extension from
 * @param[in] data_len The length of the data to parse the Supported Groups extension from
 * @param[out] groups The Supported Groups extension to parse the Supported Groups extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or groups is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a Supported Groups extension, NOXTLS_RETURN_BAD_DATA if the groups is not a valid Supported Groups extension
 */
noxtls_return_t noxtls_tls_parse_extension_supported_groups(const uint8_t *data, uint32_t data_len, tls_supported_groups_extension_t *groups)
{
    uint32_t offset = 0U;
    uint16_t groups_list_len = 0U;
    uint32_t i = 0U;
    
    if ((data == NULL) || (groups == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((groups), sizeof(tls_supported_groups_extension_t));
    
    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Groups List length (2 bytes) */
    groups_list_len = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
    offset += 2U;
    
    if ((groups_list_len == 0U) || ((offset + groups_list_len) > data_len) || (((uint32_t)groups_list_len & 1U) != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    groups->count = (uint32_t)groups_list_len / 2U;
    
    /* Allocate groups array */
    groups->groups = (uint16_t*)NOXTLS_MALLOC(groups->count * (sizeof(uint16_t)));
    if (groups->groups == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse groups */
    for (i = 0U; (i < groups->count) && ((offset + 2U) <= data_len); i += 1U) {
        groups->groups[i] = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
        offset += 2U;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Key Share extension (TLS 1.3)
 *
 * @param[in] data The data to parse the Key Share extension from
 * @param[in] data_len The length of the data to parse the Key Share extension from
 * @param[out] key_share The Key Share extension to parse the Key Share extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or key_share is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a Key Share extension, NOXTLS_RETURN_BAD_DATA if the key_share is not a valid Key Share extension
 */
noxtls_return_t noxtls_tls_parse_extension_key_share(const uint8_t *data, uint32_t data_len, tls_key_share_list_extension_t *key_share)
{
    uint32_t offset = 0U;
    uint16_t key_share_list_len = 0U;
    uint32_t max_entries = 512U;
    
    if ((data == NULL) || (key_share == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((key_share), sizeof(tls_key_share_list_extension_t));
    
    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Key Share List length (2 bytes) */
    key_share_list_len = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
    offset += 2U;

    if(((offset + key_share_list_len) > data_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* RFC 8446: empty list is valid in ClientHello to elicit HelloRetryRequest. */
    if (key_share_list_len == 0U) {
        key_share->entries = NULL;
        key_share->count = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Allocate entries array */
    key_share->entries = (tls_key_share_extension_t*)NOXTLS_CALLOC(max_entries, sizeof(tls_key_share_extension_t));
    if (key_share->entries == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse key share entries */
    {
        uint32_t key_share_list_end = (uint32_t)key_share_list_len + 2U;
        while ((offset < key_share_list_end) && ((offset + 4U) <= data_len) && (key_share->count < max_entries)) {
            tls_key_share_extension_t *entry = &key_share->entries[key_share->count];
            
            /* Group (2 bytes) */
            entry->group = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
            offset += 2U;
            
            /* Key Exchange length (2 bytes) */
            entry->key_exchange_len = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
            offset += 2U;
            
            if ((entry->key_exchange_len > 0U) && ((offset + entry->key_exchange_len) <= data_len) &&
               ((offset + entry->key_exchange_len) <= key_share_list_end)) {
                /* Allocate and copy key exchange data */
                entry->key_exchange = (uint8_t*)NOXTLS_MALLOC(entry->key_exchange_len);
                if (entry->key_exchange == NULL) {
                    /* Cleanup partial entries */
                    for (uint32_t i = 0U; i < key_share->count; i += 1U) {
                        if (key_share->entries[i].key_exchange != NULL) {
                            (void)noxtls_free(key_share->entries[i].key_exchange);
                        }
                    }
                    (void)noxtls_free(key_share->entries);
                    key_share->entries = NULL;
                    return NOXTLS_RETURN_FAILED;
                }
                noxtls_copy_u8(entry->key_exchange, (size_t)entry->key_exchange_len, &data[offset], (size_t)entry->key_exchange_len);
                offset += entry->key_exchange_len;
            } else {
                if (entry->key_exchange_len > 0U) {
                    for (uint32_t i = 0U; i < key_share->count; i += 1U) {
                        if (key_share->entries[i].key_exchange != NULL) {
                            (void)noxtls_free(key_share->entries[i].key_exchange);
                        }
                    }
                    (void)noxtls_free(key_share->entries);
                    key_share->entries = NULL;
                    return NOXTLS_RETURN_BAD_DATA;
                }
                entry->key_exchange_len = 0U;
                entry->key_exchange = NULL;
            }

            key_share->count += 1U;
        }

        if (offset != key_share_list_end) {
            for (uint32_t i = 0U; i < key_share->count; i += 1U) {
                if (key_share->entries[i].key_exchange != NULL) {
                    (void)noxtls_free(key_share->entries[i].key_exchange);
                }
            }
            (void)noxtls_free(key_share->entries);
            key_share->entries = NULL;
            key_share->count = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Signature Algorithms extension
 *
 * @param[in] data The data to parse the Signature Algorithms extension from
 * @param[in] data_len The length of the data to parse the Signature Algorithms extension from
 * @param[out] algorithms The Signature Algorithms extension to parse the Signature Algorithms extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or algorithms is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a Signature Algorithms extension, NOXTLS_RETURN_BAD_DATA if the algorithms is not a valid Signature Algorithms extension
 */
noxtls_return_t noxtls_tls_parse_extension_signature_algorithms(const uint8_t *data, uint32_t data_len, tls_signature_algorithms_extension_t *algorithms)
{
    uint32_t offset = 0U;
    uint16_t algorithms_list_len = 0U;
    uint32_t i = 0U;
    
    if ((data == NULL) || (algorithms == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((algorithms), sizeof(tls_signature_algorithms_extension_t));
    
    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Signature Hash Algorithms List length (2 bytes) */
    algorithms_list_len = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
    offset += 2U;
    
    if ((algorithms_list_len == 0U) || (((uint32_t)algorithms_list_len & 1U) != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(((offset + algorithms_list_len) != data_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    algorithms->count = (uint32_t)algorithms_list_len / 2U;
    
    /* Allocate algorithms array */
    algorithms->algorithms = (uint16_t*)NOXTLS_MALLOC(algorithms->count * (sizeof(uint16_t)));
    if (algorithms->algorithms == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse algorithms */
    for (i = 0U; (i < algorithms->count) && ((offset + 2U) <= data_len); i += 1U) {
        algorithms->algorithms[i] = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
        offset += 2U;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Application Layer Protocol Negotiation (ALPN) extension
 *
 * @param[in] data The data to parse the ALPN extension from
 * @param[in] data_len The length of the data to parse the ALPN extension from
 * @param[out] alpn The ALPN extension to parse the ALPN extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or alpn is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a ALPN extension, NOXTLS_RETURN_BAD_DATA if the alpn is not a valid ALPN extension
 * @return NOXTLS_RETURN_FAILED if the alpn is not a valid ALPN extension
 */
noxtls_return_t noxtls_tls_parse_extension_alpn(const uint8_t *data, uint32_t data_len, tls_alpn_extension_t *alpn)
{
    uint32_t offset = 0U;
    uint16_t protocol_name_list_len = 0U;
    uint32_t list_end = 0U;
    uint32_t alloc_count = 8U;
    
    if ((data == NULL) || (alpn == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((alpn), sizeof(tls_alpn_extension_t));
    
    if (data_len < 2U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    protocol_name_list_len = (uint16_t)(((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U]);
    offset += 2U;
    
    if (protocol_name_list_len == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if ((2U + (uint32_t)protocol_name_list_len) != data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    list_end = 2U + (uint32_t)protocol_name_list_len;
    
    alpn->protocols = (uint8_t **)NOXTLS_CALLOC(alloc_count, sizeof(uint8_t *));
    if (alpn->protocols == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    while (offset < list_end) {
        uint8_t name_len = 0U;
        uint8_t **new_protocols = NULL;
        
        if (alpn->count >= alloc_count) {
            uint32_t new_count = (uint32_t)(alloc_count * 2U);
            new_protocols = (uint8_t **)NOXTLS_REALLOC((void *)alpn->protocols, new_count * (sizeof(uint8_t *)));
            if (new_protocols == NULL) {
                if (alpn->protocols != NULL) {
                    uint32_t i = 0U;
                    for (i = 0U; i < alpn->count; i += 1U) {
                        if (alpn->protocols[i] != NULL) {
                            (void)noxtls_free(alpn->protocols[i]);
                        }
                    }
                    (void)noxtls_free((void *)alpn->protocols);
                    alpn->protocols = NULL;
                }
                alpn->count = 0U;
                return NOXTLS_RETURN_BAD_DATA;
            }
            noxtls_secure_zero(((void *)&new_protocols[alloc_count]), ((size_t)(alloc_count * (sizeof(uint8_t *)))));
            alpn->protocols = new_protocols;
            alloc_count = new_count;
        }
        
        name_len = data[offset];
        
        offset += 1U;
        if (name_len == 0U) {
            if (alpn->protocols != NULL) {
                uint32_t i = 0U;
                for (i = 0U; i < alpn->count; i += 1U) {
                    if (alpn->protocols[i] != NULL) {
                        (void)noxtls_free(alpn->protocols[i]);
                    }
                }
                (void)noxtls_free((void *)alpn->protocols);
                alpn->protocols = NULL;
            }
            alpn->count = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        if ((offset + (uint32_t)name_len) > list_end) {
            if (alpn->protocols != NULL) {
                uint32_t i = 0U;
                for (i = 0U; i < alpn->count; i += 1U) {
                    if (alpn->protocols[i] != NULL) {
                        (void)noxtls_free(alpn->protocols[i]);
                    }
                }
                (void)noxtls_free((void *)alpn->protocols);
                alpn->protocols = NULL;
            }
            alpn->count = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        
        alpn->protocols[alpn->count] = (uint8_t *)NOXTLS_MALLOC((size_t)name_len + 1U);
        if (alpn->protocols[alpn->count] == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        {
            uint8_t *dst = alpn->protocols[alpn->count];
            uint32_t pi = 0U;
            for(pi = 0U; pi < (uint32_t)name_len; pi += 1U) {
                dst[pi] = (uint8_t)data[offset + pi];
            }
        }
        alpn->protocols[alpn->count][name_len] = 0U;
        offset += (uint32_t)name_len;
        alpn->count += 1U;
    }
    
    if ((offset != list_end) || (alpn->count == 0U)) {
        if (alpn->protocols != NULL) {
            uint32_t i = 0U;
            for (i = 0U; i < alpn->count; i += 1U) {
                if (alpn->protocols[i] != NULL) {
                    (void)noxtls_free(alpn->protocols[i]);
                }
            }
            (void)noxtls_free((void *)alpn->protocols);
            alpn->protocols = NULL;
        }
        alpn->count = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    return NOXTLS_RETURN_SUCCESS;

}

/**
 * @brief Check if the ALPN protocols are equal
 *
 * @param[in] a The first ALPN protocol
 * @param[in] a_len The length of the first ALPN protocol
 * @param[in] b The second ALPN protocol
 * @return 1 if the ALPN protocols are equal, 0 otherwise
*/
static int noxtls_tls_alpn_protocols_equal(const uint8_t *a, uint16_t a_len, const uint8_t *b)
{
    size_t b_len = 0U;
    
    if ((a == NULL) || (b == NULL)) {
        return 0;
    }
    b_len = (uint32_t)noxtls_u8_strlen(b);
    if ((uint16_t)b_len != a_len) {
        return 0;
    }
    {
        const uint8_t *ua = (const uint8_t *)(const void *)a;
        const uint8_t *ub = (const uint8_t *)(const void *)b;
        return (noxtls_ct_equal(ua, ub, (size_t)a_len) != 0) ? 1 : 0;
    }
}

/**
 * @brief Process the ALPN negotiation
 *
 * @param[in] extensions The extensions to process the ALPN negotiation from
 * @param[in] server_protocols The server protocols to process the ALPN negotiation from
 * @param[in] server_count The number of server protocols to process the ALPN negotiation from
 * @param[out] selected The selected protocol to process the ALPN negotiation into
 * @param[in] selected_cap The capacity of the selected protocol
 * @param[out] selected_len The length of the selected protocol
 * @return NOXTLS_TLS_ALPN_STATUS_NONE if the ALPN negotiation is not successful, 
 * @return NOXTLS_TLS_ALPN_STATUS_NEGOTIATED if the ALPN negotiation is successful, 
 * @return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR if the ALPN negotiation is not successful, 
 * @return NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP if the ALPN negotiation is not successful
 * @return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR if the ALPN negotiation is not successful
 * @return NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP if the ALPN negotiation is not successful
 */
noxtls_tls_alpn_status_t noxtls_tls_alpn_server_process(tls_extensions_t *extensions,
                                                        const uint8_t * const *server_protocols,
                                                        uint32_t server_count,
                                                        uint8_t *selected,
                                                        uint32_t selected_cap,
                                                        uint16_t *selected_len)
{
    tls_extension_t *ext_raw = NULL;
    uint32_t si = 0U;
    uint32_t ci = 0U;
    
    if (selected_len != NULL) {
        *selected_len = 0U;
    }
    if (extensions == NULL) {
        return NOXTLS_TLS_ALPN_STATUS_NONE;
    }
    
    if ((noxtls_tls_find_extension(extensions,
                                 TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                 &ext_raw) != NOXTLS_RETURN_SUCCESS) || (ext_raw == NULL)) {
        return NOXTLS_TLS_ALPN_STATUS_NONE;
    }
    
    if ((ext_raw->length == 0U) || (ext_raw->data == NULL)) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    if ((extensions->alpn == NULL) || (extensions->alpn->count == 0U)) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    /* RFC 7301: servers that do not configure ALPN may ignore the client extension. */
    if ((server_protocols == NULL) || (server_count == 0U)) {
        return NOXTLS_TLS_ALPN_STATUS_NONE;
    }
    if ((selected == NULL) || (selected_cap == 0U)) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    
    for (si = 0U; si < server_count; si += 1U) {
        const uint8_t *srv_proto = server_protocols[si];
        size_t srv_len = 0U;
        
        if (srv_proto == NULL) {
            continue;
        }
        srv_len = (uint32_t)noxtls_u8_strlen(srv_proto);
        if ((srv_len == 0U) || (srv_len > NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN)) {
            continue;
        }
        for (ci = 0U; ci < extensions->alpn->count; ci += 1U) {
            const uint8_t *cli_proto = extensions->alpn->protocols[ci];
            uint16_t cli_len = 0U;
            
            if (cli_proto == NULL) {
                continue;
            }
            cli_len = (uint16_t)noxtls_u8_strlen(cli_proto);
            if (noxtls_tls_alpn_protocols_equal(cli_proto, cli_len, srv_proto) != 0) {
                if ((uint32_t)srv_len > selected_cap) {
                    return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
                }
                {
                    uint32_t pi = 0U;
                    for (pi = 0U; pi < (uint32_t)srv_len; pi += 1U) {
                        selected[pi] = srv_proto[pi];
                    }
                }
                if (selected_len != NULL) {
                    *selected_len = (uint16_t)srv_len;
                }
                return NOXTLS_TLS_ALPN_STATUS_NEGOTIATED;
            }
        }
    }
    
    return NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP;
}

/**
 * @brief Write the selected ALPN extension
 *
 * @param[in] protocol The protocol to write the selected ALPN extension from
 * @param[in] protocol_len The length of the protocol to write the selected ALPN extension from
 * @param[out] buf The buffer to write the selected ALPN extension into
 * @param[in] buf_cap The capacity of the buffer to write the selected ALPN extension into
 * @return The number of bytes written to the buffer
 * @return 0 if the protocol is NULL, the protocol length is 0, the protocol length is greater than the maximum protocol length, the buffer is NULL, the buffer capacity is less than the body length
 */     
uint32_t noxtls_tls_alpn_write_selected_extension(const uint8_t *protocol,
                                                  uint16_t protocol_len,
                                                  uint8_t *buf,
                                                  uint32_t buf_cap)
{
    uint16_t body_len = 0U;
    uint16_t list_len = 0U;
    uint32_t offset = 0U;
    
    if ((protocol == NULL) || (protocol_len == 0U) || (protocol_len > NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN) ||
       (buf == NULL)) {
        return 0U;
    }
    body_len = (uint16_t)(2U + 1U + (uint32_t)protocol_len);
    list_len = (uint16_t)(1U + (uint32_t)protocol_len);
    if (buf_cap < (4U + (uint32_t)body_len)) {
        return 0U;
    }
    
    buf[offset] = (uint8_t)(((uint16_t)TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) >> 8U);
    
    offset += 1U;
    buf[offset] = (uint8_t)(((uint16_t)TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) & 0xFFU);
    offset += 1U;
    buf[offset] = (uint8_t)((uint32_t)(uint32_t)body_len >> 8U);
    offset += 1U;
    buf[offset] = (uint8_t)(body_len & 0xFFU);
    offset += 1U;
    buf[offset] = (uint8_t)((uint32_t)(uint32_t)list_len >> 8U);
    offset += 1U;
    buf[offset] = (uint8_t)(list_len & 0xFFU);
    offset += 1U;
    buf[offset] = (uint8_t)protocol_len;
    offset += 1U;
    {
        uint32_t pi = 0U;
        for(pi = 0U; pi < (uint32_t)protocol_len; pi += 1U) {
            buf[offset + pi] = (uint8_t)protocol[pi];
        }
    }
    offset += (uint32_t)protocol_len;
    return offset;
}

/**
 * @brief Parse Supported Versions extension (TLS 1.3)
 *
 * @param[in] data The data to parse the Supported Versions extension from
 * @param[in] data_len The length of the data to parse the Supported Versions extension from
 * @param[out] versions The Supported Versions extension to parse the Supported Versions extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the data or versions is NULL, NOXTLS_RETURN_BAD_DATA if the data is not a valid length for a Supported Versions extension, NOXTLS_RETURN_BAD_DATA if the versions is not a valid Supported Versions extension
 */
noxtls_return_t noxtls_tls_parse_extension_supported_versions(const uint8_t *data, uint32_t data_len, tls_supported_versions_extension_t *versions)
{
    uint32_t offset = 0U;
    uint8_t versions_list_len = 0U;
    uint32_t i = 0U;
    uint32_t max_versions = 16U;
    
    if ((data == NULL) || (versions == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((versions), sizeof(tls_supported_versions_extension_t));
    
    if (data_len < 1U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Versions List length (1 byte) */
    versions_list_len = data[offset];
    offset += 1U;
    
    if ((versions_list_len == 0U) || ((offset + versions_list_len) > data_len) || (((uint32_t)versions_list_len & 1U) != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    versions->count = (uint32_t)versions_list_len / 2U;
    if (versions->count > max_versions) {
        versions->count = max_versions;
    }
    
    /* Allocate versions array */
    versions->versions = (uint16_t*)NOXTLS_MALLOC(versions->count * (sizeof(uint16_t)));
    if (versions->versions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse versions */
    for (i = 0U; (i < versions->count) && ((offset + 2U) <= data_len); i += 1U) {
        versions->versions[i] = ((uint16_t)data[offset] << 8U) | (uint16_t)data[offset + 1U];
        offset += 2U;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Find extension by type
 *
 * @param[in] extensions The extensions to find the extension from
 * @param[in] type The type of the extension to find
 * @param[out] extension The extension to find the extension into
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the extensions or extension is NULL, 
 *         NOXTLS_RETURN_FAILED if the extensions is not a valid extension for a TLS extension,
 *         NOXTLS_RETURN_NULL if the extension is not found
 */
noxtls_return_t noxtls_tls_find_extension(tls_extensions_t *extensions, uint16_t type, tls_extension_t **extension)
{
    uint32_t i = 0U;
    
    if ((extensions == NULL) || (extension == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    *extension = NULL;
    
    if (extensions->extensions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    for (i = 0U; i < extensions->count; i += 1U) {
        if (extensions->extensions[i].type == type) {
            *extension = &extensions->extensions[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    
    return NOXTLS_RETURN_FAILED;
}
