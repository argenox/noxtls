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
    uint32_t max_extensions = 64;  /* Reasonable limit */
    
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
            break;  /* Too many extensions */
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
        } else {
            ext->length = 0;
            ext->data = NULL;
        }
        
        extensions->count++;
        
        /* Parse known extensions */
        switch(ext->type) {
            case TLS_EXTENSION_SERVER_NAME:
                if(ext->data != NULL && ext->length > 0) {
                    extensions->sni = (tls_sni_extension_t*)malloc(sizeof(tls_sni_extension_t));
                    if(extensions->sni != NULL) {
                        if(noxtls_tls_parse_extension_sni(ext->data, ext->length, extensions->sni) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->sni);
                            extensions->sni = NULL;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_SUPPORTED_GROUPS:
                if(ext->data != NULL && ext->length > 0) {
                    extensions->supported_groups = (tls_supported_groups_extension_t*)malloc(sizeof(tls_supported_groups_extension_t));
                    if(extensions->supported_groups != NULL) {
                        if(noxtls_tls_parse_extension_supported_groups(ext->data, ext->length, extensions->supported_groups) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->supported_groups);
                            extensions->supported_groups = NULL;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_KEY_SHARE:
                if(ext->data != NULL && ext->length > 0) {
                    extensions->key_share = (tls_key_share_list_extension_t*)malloc(sizeof(tls_key_share_list_extension_t));
                    if(extensions->key_share != NULL) {
                        if(noxtls_tls_parse_extension_key_share(ext->data, ext->length, extensions->key_share) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->key_share);
                            extensions->key_share = NULL;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_SIGNATURE_ALGORITHMS:
                if(ext->data != NULL && ext->length > 0) {
                    extensions->signature_algorithms = (tls_signature_algorithms_extension_t*)malloc(sizeof(tls_signature_algorithms_extension_t));
                    if(extensions->signature_algorithms != NULL) {
                        if(noxtls_tls_parse_extension_signature_algorithms(ext->data, ext->length, extensions->signature_algorithms) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->signature_algorithms);
                            extensions->signature_algorithms = NULL;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                if(ext->data != NULL && ext->length > 0) {
                    extensions->alpn = (tls_alpn_extension_t*)malloc(sizeof(tls_alpn_extension_t));
                    if(extensions->alpn != NULL) {
                        if(noxtls_tls_parse_extension_alpn(ext->data, ext->length, extensions->alpn) != NOXTLS_RETURN_SUCCESS) {
                            free(extensions->alpn);
                            extensions->alpn = NULL;
                        }
                    }
                }
                break;
                
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                if(ext->data != NULL && ext->length > 0) {
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
noxtls_return_t noxtls_tls_parse_extension_sni(const uint8_t *data, uint32_t data_len, tls_sni_extension_t *sni)
{
    uint32_t offset = 0;
    uint16_t server_name_list_len = 0;
    
    if(data == NULL || sni == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(sni, 0, sizeof(tls_sni_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Server Name List length (2 bytes) */
    server_name_list_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(server_name_list_len == 0 || offset + server_name_list_len > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Parse first Server Name entry */
    if(offset + 3 > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Name type (1 byte) */
    sni->name_type = data[offset++];
    
    /* Name length (2 bytes) */
    sni->name_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(sni->name_len == 0 || offset + sni->name_len > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate and copy hostname */
    sni->hostname = (char*)malloc(sni->name_len + 1);
    if(sni->hostname == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(sni->hostname, data + offset, sni->name_len);
    sni->hostname[sni->name_len] = '\0';
    
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
    uint32_t max_groups = 32;
    
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
    if(groups->count > max_groups) {
        groups->count = max_groups;
    }
    
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
    uint32_t max_entries = 16;
    
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
    
    if(key_share_list_len == 0 || offset + key_share_list_len > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
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
            
            if(entry->key_exchange_len > 0 && offset + entry->key_exchange_len <= data_len) {
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
                entry->key_exchange_len = 0;
                entry->key_exchange = NULL;
            }
            
            key_share->count++;
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
    uint32_t max_algorithms = 64;
    
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
    
    if(algorithms_list_len == 0 || offset + algorithms_list_len > data_len || (algorithms_list_len & 1) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    algorithms->count = algorithms_list_len / 2;
    if(algorithms->count > max_algorithms) {
        algorithms->count = max_algorithms;
    }
    
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
    uint32_t max_protocols = 16;
    
    if(data == NULL || alpn == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(alpn, 0, sizeof(tls_alpn_extension_t));
    
    if(data_len < 2) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Protocol Name List length (2 bytes) */
    protocol_name_list_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    if(protocol_name_list_len == 0 || offset + protocol_name_list_len > data_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Allocate protocols array */
    alpn->protocols = (char**)calloc(max_protocols, sizeof(char*));
    if(alpn->protocols == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse protocol names */
    {
        uint32_t protocol_list_end = (uint32_t)protocol_name_list_len + 2u;
        while(offset < protocol_list_end && offset + 1 <= data_len && alpn->count < max_protocols) {
            uint8_t name_len = data[offset++];
            
            if(name_len == 0 || offset + name_len > data_len) {
                break;
            }
            
            /* Allocate and copy protocol name */
            alpn->protocols[alpn->count] = (char*)malloc(name_len + 1);
            if(alpn->protocols[alpn->count] == NULL) {
                break;
            }
            memcpy(alpn->protocols[alpn->count], data + offset, name_len);
            alpn->protocols[alpn->count][name_len] = '\0';
            offset += name_len;
            
            alpn->count++;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
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

