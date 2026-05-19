/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_tls_extensions.c
* Summary: TLS Extension Parsing Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_tls_common.h"

/**
 * @brief Parse TLS extensions from extension list
 */
noxtls_return_t noxtls_tls_parse_extensions(const uint8_t *data, uint32_t data_len, tls_extensions_t *extensions)
{
    uint32_t offset = 0;
    uint32_t extensions_len = 0;
    uint32_t max_extensions = 64;  /* Initial capacity; grow as needed. */
    
    if(data == NULL || extensions == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(extensions, 0, sizeof(tls_extensions_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Extensions length (2 bytes) */
    extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(extensions_len == 0) {
        if(data_len != 2u) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        return NOXTLS_RETURN_SUCCESS;  /* No extensions */
    }
    
    if(extensions_len > data_len - 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate extension array */
    extensions->extensions = (tls_extension_t*)calloc(max_extensions, sizeof(tls_extension_t));
    if(extensions->extensions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse extensions */
    while(offset < extensions_len + 2 && offset + sizeof(tls_extension_header_t) <= data_len) {
        if(extensions->count >= max_extensions) {
            uint32_t new_max = max_extensions * 2u;
            tls_extension_t *new_exts;
            if(new_max > 65536u) {
                noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_RECORD_OVERFLOW;
            }
            new_exts = (tls_extension_t*)realloc(extensions->extensions,
                                                 new_max * sizeof(tls_extension_t));
            if(new_exts == NULL) {
                noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            memset(new_exts + max_extensions, 0,
                   (new_max - max_extensions) * sizeof(tls_extension_t));
            extensions->extensions = new_exts;
            max_extensions = new_max;
        }
        
        tls_extension_t *ext = &extensions->extensions[extensions->count];
        
        /* Extension header (4 bytes) */
        tls_extension_header_t header;
        memcpy(&header, data + offset, sizeof(header));
        ext->type = (uint16_t)((header.type[0] << 8) | header.type[1]);
        ext->length = (uint16_t)((header.length[0] << 8) | header.length[1]);
        offset += sizeof(header);
        
        if(ext->length > 0 && offset + ext->length <= data_len) {
            /* Allocate and copy extension data */
            ext->data = (uint8_t*)malloc(ext->length);
            if(ext->data == NULL) {
                noxtls_tls_extensions_free(extensions);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(ext->data, data + offset, ext->length);
            offset += ext->length;
        } else if(ext->length > 0) {
            /* Malformed extension length that overruns the extension block. */
            noxtls_tls_extensions_free(extensions);
            return NOXTLS_RETURN_BAD_DATA;
        } else {
            ext->length = 0;
            ext->data = NULL;
        }
        
        extensions->count++;
        
        /* Parse known extensions */
        switch(ext->type) {
            case TLS_EXTENSION_SERVER_NAME:
                if(ext->length == 0u) {
                    noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(ext->data != NULL) {
                    if(extensions->sni != NULL) {
                        if(extensions->sni->hostname != NULL) {
                            free(extensions->sni->hostname);
                        }
                        free(extensions->sni);
                        extensions->sni = NULL;
                    }
                    extensions->sni = (tls_sni_extension_t*)malloc(sizeof(tls_sni_extension_t));
                    if(extensions->sni == NULL) {
                        noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                    {
                        noxtls_return_t sni_rc = noxtls_tls_parse_extension_sni(ext->data, ext->length, extensions->sni);
                        if(sni_rc != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->sni);
                            extensions->sni = NULL;
                            noxtls_tls_extensions_free(extensions);
                            return sni_rc;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_SUPPORTED_GROUPS:
                if(ext->data != NULL && ext->length > 0) {
                    if(extensions->supported_groups != NULL) {
                        if(extensions->supported_groups->groups != NULL) {
                            free(extensions->supported_groups->groups);
                        }
                        free(extensions->supported_groups);
                        extensions->supported_groups = NULL;
                    }
                    extensions->supported_groups = (tls_supported_groups_extension_t*)malloc(sizeof(tls_supported_groups_extension_t));
                    if(extensions->supported_groups != NULL) {
                        if(noxtls_tls_parse_extension_supported_groups(ext->data, ext->length, extensions->supported_groups) != NOXTLS_RETURN_SUCCESS) {
                            noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
                break;
                
            case TLS_EXTENSION_KEY_SHARE:
                if(ext->data != NULL && ext->length > 0) {
                    if(extensions->key_share != NULL) {
                        if(extensions->key_share->entries != NULL) {
                            for(uint32_t k = 0; k < extensions->key_share->count; k++) {
                                if(extensions->key_share->entries[k].key_exchange != NULL) {
                                    free(extensions->key_share->entries[k].key_exchange);
                                }
                            }
                            free(extensions->key_share->entries);
                        }
                        free(extensions->key_share);
                        extensions->key_share = NULL;
                    }
                    extensions->key_share = (tls_key_share_list_extension_t*)malloc(sizeof(tls_key_share_list_extension_t));
                    if(extensions->key_share != NULL) {
                        if(noxtls_tls_parse_extension_key_share(ext->data, ext->length, extensions->key_share) != NOXTLS_RETURN_SUCCESS) {
                            noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
                break;
                
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                if(ext->data != NULL && ext->length > 0) {
                    if(extensions->signature_algorithms != NULL) {
                        if(extensions->signature_algorithms->algorithms != NULL) {
                            free(extensions->signature_algorithms->algorithms);
                        }
                        free(extensions->signature_algorithms);
                        extensions->signature_algorithms = NULL;
                    }
                    extensions->signature_algorithms = (tls_signature_algorithms_extension_t*)malloc(sizeof(tls_signature_algorithms_extension_t));
                    if(extensions->signature_algorithms != NULL) {
                        if(noxtls_tls_parse_extension_signature_algorithms(ext->data, ext->length, extensions->signature_algorithms) != NOXTLS_RETURN_SUCCESS) {
                            noxtls_tls_extensions_free(extensions);
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        noxtls_tls_extensions_free(extensions);
                        return NOXTLS_RETURN_FAILED;
                    }
                }
                break;
                
            case TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                if(ext->length == 0) {
                    noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(ext->data == NULL) {
                    noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                if(extensions->alpn != NULL) {
                    if(extensions->alpn->protocols != NULL) {
                        for(uint32_t k = 0; k < extensions->alpn->count; k++) {
                            if(extensions->alpn->protocols[k] != NULL) {
                                free(extensions->alpn->protocols[k]);
                            }
                        }
                        free(extensions->alpn->protocols);
                    }
                    free(extensions->alpn);
                    extensions->alpn = NULL;
                }
                extensions->alpn = (tls_alpn_extension_t*)malloc(sizeof(tls_alpn_extension_t));
                if(extensions->alpn == NULL) {
                    noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_FAILED;
                }
                if(noxtls_tls_parse_extension_alpn(ext->data, ext->length, extensions->alpn) != NOXTLS_RETURN_SUCCESS) {
                    noxtls_tls_extensions_free(extensions);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                break;
                
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                if(ext->data != NULL && ext->length > 0) {
                    if(extensions->supported_versions != NULL) {
                        if(extensions->supported_versions->versions != NULL) {
                            free(extensions->supported_versions->versions);
                        }
                        free(extensions->supported_versions);
                        extensions->supported_versions = NULL;
                    }
                    extensions->supported_versions = (tls_supported_versions_extension_t*)malloc(sizeof(tls_supported_versions_extension_t));
                    if(extensions->supported_versions != NULL) {
                        if(noxtls_tls_parse_extension_supported_versions(ext->data, ext->length, extensions->supported_versions) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->supported_versions);
                            extensions->supported_versions = NULL;
                        }
                    }
                }
                break;
        }
    }

    if(offset != extensions_len + 2) {
        noxtls_tls_extensions_free(extensions);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(offset != data_len) {
        noxtls_tls_extensions_free(extensions);
        return NOXTLS_RETURN_BAD_DATA;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free parsed extensions
 */
noxtls_return_t noxtls_tls_extensions_free(tls_extensions_t *extensions)
{
    uint32_t i;
    
    if(extensions == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Free extension data */
    if(extensions->extensions != NULL) {
        for(i = 0; i < extensions->count; i++) {
            if(extensions->extensions[i].data != NULL) {
                free(extensions->extensions[i].data);
            }
        }
        free(extensions->extensions);
        extensions->extensions = NULL;
    }
    
    /* Free SNI */
    if(extensions->sni != NULL) {
        if(extensions->sni->hostname != NULL) {
            free(extensions->sni->hostname);
        }
        free(extensions->sni);
        extensions->sni = NULL;
    }
    
    /* Free Supported Groups */
    if(extensions->supported_groups != NULL) {
        if(extensions->supported_groups->groups != NULL) {
            free(extensions->supported_groups->groups);
        }
        free(extensions->supported_groups);
        extensions->supported_groups = NULL;
    }
    
    /* Free Key Share */
    if(extensions->key_share != NULL) {
        if(extensions->key_share->entries != NULL) {
            for(i = 0; i < extensions->key_share->count; i++) {
                if(extensions->key_share->entries[i].key_exchange != NULL) {
                    free(extensions->key_share->entries[i].key_exchange);
                }
            }
            free(extensions->key_share->entries);
        }
        free(extensions->key_share);
        extensions->key_share = NULL;
    }
    
    /* Free Signature Algorithms */
    if(extensions->signature_algorithms != NULL) {
        if(extensions->signature_algorithms->algorithms != NULL) {
            free(extensions->signature_algorithms->algorithms);
        }
        free(extensions->signature_algorithms);
        extensions->signature_algorithms = NULL;
    }
    
    /* Free ALPN */
    if(extensions->alpn != NULL) {
        if(extensions->alpn->protocols != NULL) {
            for(i = 0; i < extensions->alpn->count; i++) {
                if(extensions->alpn->protocols[i] != NULL) {
                    free(extensions->alpn->protocols[i]);
                }
            }
            free(extensions->alpn->protocols);
        }
        free(extensions->alpn);
        extensions->alpn = NULL;
    }
    
    /* Free Supported Versions */
    if(extensions->supported_versions != NULL) {
        if(extensions->supported_versions->versions != NULL) {
            free(extensions->supported_versions->versions);
        }
        free(extensions->supported_versions);
        extensions->supported_versions = NULL;
    }
    
    memset(extensions, 0, sizeof(tls_extensions_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Server Name Indication (SNI) extension
 */
static noxtls_return_t tls_sni_validate_host_name_octets(const uint8_t *nm, uint16_t name_len)
{
    uint32_t j;
    for(j = 0; j < (uint32_t)name_len; j++) {
        uint8_t c = nm[j];
        if(c == 0u) {
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
        /* Reject controls, DEL, and non-ASCII (tlsfuzzer invalid SNI / UTF-8 probes). */
        if(c < 0x20u || c > 0x7eu) {
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_parse_extension_sni(const uint8_t *data, uint32_t data_len, tls_sni_extension_t *sni)
{
    uint16_t server_name_list_len = 0;
    uint32_t list_end;
    uint32_t pos;
    int found_host = 0;
    const uint8_t *host_ptr = NULL;
    uint16_t host_len = 0;

    if(data == NULL || sni == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(sni, 0, sizeof(tls_sni_extension_t));

    if(data_len < 2u) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    server_name_list_len = (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
    if(server_name_list_len == 0u ||
       (uint32_t)2u + (uint32_t)server_name_list_len != data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    list_end = 2u + (uint32_t)server_name_list_len;
    pos = 2u;

    while(pos < list_end) {
        uint8_t name_type;
        uint16_t name_len;

        if(pos + 3u > list_end) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        name_type = data[pos++];
        name_len = (uint16_t)(((uint16_t)data[pos] << 8) | data[pos + 1]);
        pos += 2u;
        if((uint32_t)pos + (uint32_t)name_len > list_end) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        if(name_type == 0u) {
            noxtls_return_t vrc;
            if(found_host) {
                /* RFC 6066: client MUST NOT send multiple host_name entries. */
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
            if(name_len == 0u) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            vrc = tls_sni_validate_host_name_octets(data + pos, name_len);
            if(vrc != NOXTLS_RETURN_SUCCESS) {
                return vrc;
            }
            found_host = 1;
            sni->name_type = 0;
            sni->name_len = name_len;
            host_ptr = data + pos;
            host_len = name_len;
            pos += (uint32_t)name_len;
        } else {
            /* Unknown name_type: ignore (RFC 6066; tlsfuzzer multiple-type probes). */
            pos += (uint32_t)name_len;
        }
    }

    if(!found_host || host_ptr == NULL || host_len == 0u) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    sni->hostname = (char*)malloc((size_t)host_len + 1u);
    if(sni->hostname == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(sni->hostname, host_ptr, host_len);
    sni->hostname[host_len] = '\0';

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Supported Groups extension
 */
noxtls_return_t noxtls_tls_parse_extension_supported_groups(const uint8_t *data, uint32_t data_len, tls_supported_groups_extension_t *groups)
{
    uint32_t offset = 0;
    uint16_t groups_list_len = 0;
    uint32_t i;
    
    if(data == NULL || groups == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(groups, 0, sizeof(tls_supported_groups_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Groups List length (2 bytes) */
    groups_list_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(groups_list_len == 0 || offset + groups_list_len > data_len || (groups_list_len & 1) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    groups->count = groups_list_len >> 1;
    
    /* Allocate groups array */
    groups->groups = (uint16_t*)malloc(groups->count * sizeof(uint16_t));
    if(groups->groups == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse groups */
    for(i = 0; i < groups->count && offset + 2 <= data_len; i++) {
        groups->groups[i] = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Key Share extension (TLS 1.3)
 */
noxtls_return_t noxtls_tls_parse_extension_key_share(const uint8_t *data, uint32_t data_len, tls_key_share_list_extension_t *key_share)
{
    uint32_t offset = 0;
    uint16_t key_share_list_len = 0;
    uint32_t max_entries = 512;
    
    if(data == NULL || key_share == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(key_share, 0, sizeof(tls_key_share_list_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Key Share List length (2 bytes) */
    key_share_list_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if(offset + key_share_list_len > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* RFC 8446: empty list is valid in ClientHello to elicit HelloRetryRequest. */
    if(key_share_list_len == 0) {
        key_share->entries = NULL;
        key_share->count = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Allocate entries array */
    key_share->entries = (tls_key_share_extension_t*)calloc(max_entries, sizeof(tls_key_share_extension_t));
    if(key_share->entries == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse key share entries */
    {
        uint32_t key_share_list_end = (uint32_t)key_share_list_len + 2u;
        while(offset < key_share_list_end && offset + 4 <= data_len && key_share->count < max_entries) {
            tls_key_share_extension_t *entry = &key_share->entries[key_share->count];
            
            /* Group (2 bytes) */
            entry->group = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            
            /* Key Exchange length (2 bytes) */
            entry->key_exchange_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            
            if(entry->key_exchange_len > 0 && offset + entry->key_exchange_len <= data_len &&
               offset + entry->key_exchange_len <= key_share_list_end) {
                /* Allocate and copy key exchange data */
                entry->key_exchange = (uint8_t*)malloc(entry->key_exchange_len);
                if(entry->key_exchange == NULL) {
                    /* Cleanup partial entries */
                    for(uint32_t i = 0; i < key_share->count; i++) {
                        if(key_share->entries[i].key_exchange != NULL) {
                            free(key_share->entries[i].key_exchange);
                        }
                    }
                    free(key_share->entries);
                    key_share->entries = NULL;
                    return NOXTLS_RETURN_FAILED;
                }
                memcpy(entry->key_exchange, data + offset, entry->key_exchange_len);
                offset += entry->key_exchange_len;
            } else {
                if(entry->key_exchange_len > 0) {
                    for(uint32_t i = 0; i < key_share->count; i++) {
                        if(key_share->entries[i].key_exchange != NULL) {
                            free(key_share->entries[i].key_exchange);
                        }
                    }
                    free(key_share->entries);
                    key_share->entries = NULL;
                    return NOXTLS_RETURN_BAD_DATA;
                }
                entry->key_exchange_len = 0;
                entry->key_exchange = NULL;
            }

            key_share->count++;
        }

        if(offset != key_share_list_end) {
            for(uint32_t i = 0; i < key_share->count; i++) {
                if(key_share->entries[i].key_exchange != NULL) {
                    free(key_share->entries[i].key_exchange);
                }
            }
            free(key_share->entries);
            key_share->entries = NULL;
            key_share->count = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Signature Algorithms extension
 */
noxtls_return_t noxtls_tls_parse_extension_signature_algorithms(const uint8_t *data, uint32_t data_len, tls_signature_algorithms_extension_t *algorithms)
{
    uint32_t offset = 0;
    uint16_t algorithms_list_len = 0;
    uint32_t i;
    
    if(data == NULL || algorithms == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(algorithms, 0, sizeof(tls_signature_algorithms_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Signature Hash Algorithms List length (2 bytes) */
    algorithms_list_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(algorithms_list_len == 0 || (algorithms_list_len & 1) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(offset + algorithms_list_len != data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    algorithms->count = algorithms_list_len / 2;
    
    /* Allocate algorithms array */
    algorithms->algorithms = (uint16_t*)malloc(algorithms->count * sizeof(uint16_t));
    if(algorithms->algorithms == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse algorithms */
    for(i = 0; i < algorithms->count && offset + 2 <= data_len; i++) {
        algorithms->algorithms[i] = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse Application Layer Protocol Negotiation (ALPN) extension
 */
noxtls_return_t noxtls_tls_parse_extension_alpn(const uint8_t *data, uint32_t data_len, tls_alpn_extension_t *alpn)
{
    uint32_t offset = 0;
    uint16_t protocol_name_list_len = 0;
    uint32_t list_end;
    uint32_t alloc_count = 8;
    
    if(data == NULL || alpn == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(alpn, 0, sizeof(tls_alpn_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    protocol_name_list_len = (uint16_t)((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    
    if(protocol_name_list_len == 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(2u + (uint32_t)protocol_name_list_len != data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    list_end = 2u + (uint32_t)protocol_name_list_len;
    
    alpn->protocols = (char**)calloc(alloc_count, sizeof(char*));
    if(alpn->protocols == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    while(offset < list_end) {
        uint8_t name_len;
        char **new_protocols;
        
        if(alpn->count >= alloc_count) {
            uint32_t new_count = alloc_count * 2u;
            new_protocols = (char**)realloc(alpn->protocols, new_count * sizeof(char*));
            if(new_protocols == NULL) {
                goto alpn_parse_fail;
            }
            memset(new_protocols + alloc_count, 0, alloc_count * sizeof(char*));
            alpn->protocols = new_protocols;
            alloc_count = new_count;
        }
        
        name_len = data[offset++];
        if(name_len == 0) {
            goto alpn_parse_fail;
        }
        if(offset + (uint32_t)name_len > list_end) {
            goto alpn_parse_fail;
        }
        
        alpn->protocols[alpn->count] = (char*)malloc((size_t)name_len + 1u);
        if(alpn->protocols[alpn->count] == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(alpn->protocols[alpn->count], data + offset, name_len);
        alpn->protocols[alpn->count][name_len] = '\0';
        offset += (uint32_t)name_len;
        alpn->count++;
    }
    
    if(offset != list_end || alpn->count == 0) {
        goto alpn_parse_fail;
    }
    
    return NOXTLS_RETURN_SUCCESS;

alpn_parse_fail:
    if(alpn->protocols != NULL) {
        uint32_t i;
        for(i = 0; i < alpn->count; i++) {
            if(alpn->protocols[i] != NULL) {
                free(alpn->protocols[i]);
            }
        }
        free(alpn->protocols);
        alpn->protocols = NULL;
    }
    alpn->count = 0;
    return NOXTLS_RETURN_BAD_DATA;
}

static int noxtls_tls_alpn_protocols_equal(const char *a, uint16_t a_len, const char *b)
{
    size_t b_len;
    
    if(a == NULL || b == NULL) {
        return 0;
    }
    b_len = strlen(b);
    if((uint16_t)b_len != a_len) {
        return 0;
    }
    return (memcmp(a, b, a_len) == 0);
}

noxtls_tls_alpn_status_t noxtls_tls_alpn_server_process(const tls_extensions_t *extensions,
                                                        const char * const *server_protocols,
                                                        uint32_t server_count,
                                                        char *selected,
                                                        uint32_t selected_cap,
                                                        uint16_t *selected_len)
{
    tls_extension_t *ext_raw = NULL;
    uint32_t si;
    uint32_t ci;
    
    if(selected_len != NULL) {
        *selected_len = 0;
    }
    if(extensions == NULL) {
        return NOXTLS_TLS_ALPN_STATUS_NONE;
    }
    
    if(noxtls_tls_find_extension((tls_extensions_t *)extensions,
                                 TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                 &ext_raw) != NOXTLS_RETURN_SUCCESS || ext_raw == NULL) {
        return NOXTLS_TLS_ALPN_STATUS_NONE;
    }
    
    if(ext_raw->length == 0 || ext_raw->data == NULL) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    if(extensions->alpn == NULL || extensions->alpn->count == 0) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    if(server_protocols == NULL || server_count == 0) {
        return NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP;
    }
    if(selected == NULL || selected_cap == 0) {
        return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
    }
    
    for(si = 0; si < server_count; si++) {
        const char *srv_proto = server_protocols[si];
        size_t srv_len;
        
        if(srv_proto == NULL) {
            continue;
        }
        srv_len = strlen(srv_proto);
        if(srv_len == 0 || srv_len > NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN) {
            continue;
        }
        for(ci = 0; ci < extensions->alpn->count; ci++) {
            const char *cli_proto = extensions->alpn->protocols[ci];
            uint16_t cli_len;
            
            if(cli_proto == NULL) {
                continue;
            }
            cli_len = (uint16_t)strlen(cli_proto);
            if(noxtls_tls_alpn_protocols_equal(cli_proto, cli_len, srv_proto)) {
                if((uint32_t)srv_len > selected_cap) {
                    return NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR;
                }
                memcpy(selected, srv_proto, srv_len);
                if(selected_len != NULL) {
                    *selected_len = (uint16_t)srv_len;
                }
                return NOXTLS_TLS_ALPN_STATUS_NEGOTIATED;
            }
        }
    }
    
    return NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP;
}

uint32_t noxtls_tls_alpn_write_selected_extension(const char *protocol,
                                                  uint16_t protocol_len,
                                                  uint8_t *buf,
                                                  uint32_t buf_cap)
{
    uint16_t body_len;
    uint16_t list_len;
    uint32_t offset = 0;
    
    if(protocol == NULL || protocol_len == 0 || protocol_len > NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN ||
       buf == NULL) {
        return 0;
    }
    body_len = (uint16_t)(2u + 1u + (uint32_t)protocol_len);
    list_len = (uint16_t)(1u + (uint32_t)protocol_len);
    if(buf_cap < 4u + (uint32_t)body_len) {
        return 0;
    }
    
    buf[offset++] = (uint8_t)(TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION >> 8);
    buf[offset++] = (uint8_t)(TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION & 0xFF);
    buf[offset++] = (uint8_t)(body_len >> 8);
    buf[offset++] = (uint8_t)(body_len & 0xFF);
    buf[offset++] = (uint8_t)(list_len >> 8);
    buf[offset++] = (uint8_t)(list_len & 0xFF);
    buf[offset++] = (uint8_t)protocol_len;
    memcpy(buf + offset, protocol, protocol_len);
    offset += (uint32_t)protocol_len;
    return offset;
}

/**
 * @brief Parse Supported Versions extension (TLS 1.3)
 */
noxtls_return_t noxtls_tls_parse_extension_supported_versions(const uint8_t *data, uint32_t data_len, tls_supported_versions_extension_t *versions)
{
    uint32_t offset = 0;
    uint8_t versions_list_len = 0;
    uint32_t i;
    uint32_t max_versions = 16;
    
    if(data == NULL || versions == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(versions, 0, sizeof(tls_supported_versions_extension_t));
    
    if(data_len < 1) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Versions List length (1 byte) */
    versions_list_len = data[offset++];
    
    if(versions_list_len == 0 || offset + versions_list_len > data_len || (versions_list_len & 1) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    versions->count = versions_list_len >> 1;
    if(versions->count > max_versions) {
        versions->count = max_versions;
    }
    
    /* Allocate versions array */
    versions->versions = (uint16_t*)malloc(versions->count * sizeof(uint16_t));
    if(versions->versions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse versions */
    for(i = 0; i < versions->count && offset + 2 <= data_len; i++) {
        versions->versions[i] = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Find extension by type
 */
noxtls_return_t noxtls_tls_find_extension(tls_extensions_t *extensions, uint16_t type, tls_extension_t **extension)
{
    uint32_t i;
    
    if(extensions == NULL || extension == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    *extension = NULL;
    
    if(extensions->extensions == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    for(i = 0; i < extensions->count; i++) {
        if(extensions->extensions[i].type == type) {
            *extension = &extensions->extensions[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    
    return NOXTLS_RETURN_FAILED;
}
