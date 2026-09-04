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
* File:    asn1.c
* Summary: ASN1 DER parser and encoder
*
*****************************************************************************/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <string.h>
#include "noxtls_common.h"
#include "asn1.h"
#include "oids.h"
#include "noxtls_ct.h"

/* Debug pretty-printer is opt-in; default builds omit stdio (MISRA 21.6). */
#ifndef NOXTLS_ASN1_DEBUG
#define NOXTLS_ASN1_DEBUG 0
#endif
#if NOXTLS_ASN1_DEBUG
#include <stdio.h>
#define NOXTLS_ASN1_PRINTF(...) (printf(__VA_ARGS__))
#else
#define NOXTLS_ASN1_PRINTF(...) ((void)0)
#endif

/**
 * @brief Bytes remaining between cursor and one-past-end (same object).
 */
static size_t asn1_bytes_remaining(const uint8_t *ptr, const uint8_t *end)
{
    uintptr_t start_addr;
    uintptr_t end_addr;
    if((ptr == NULL) || (end == NULL)) {
        return 0U;
    }
    start_addr = (uintptr_t)ptr;
    end_addr = (uintptr_t)end;
    if(start_addr > end_addr) {
        return 0U;
    }
    return (size_t)(end_addr - start_addr);
}

/**
 * @brief Parse one ASN.1 TLV at @p data and advance the cursor (debug helper).
 * @param[in,out] data  Current parse position; updated to end of this TLV on success.
 * @param[in] end       One past the last valid byte of the DER buffer.
 * @return 0 on success; 1 on parse error or truncated input.
 */
static uint32_t noxtls_parse_tag(const uint8_t ** data, const uint8_t * end);

/**
 * @brief Print a human-readable universal tag name (debug helper).
 * @param[in] type Universal tag number (`ASN1_TAG_*`).
 */
static void print_tag_type(uint8_t type);

/**
 * @brief Dispatch TLV value decoding by universal tag (debug helper).
 * @param[in] type      Universal tag number.
 * @param[in,out] data  Value bytes; advanced by @p len on exit for primitive types.
 * @param[in] len       Length of the TLV value field.
 */
static void parse_tag(uint8_t type, const uint8_t ** data, uint32_t len);

/**
 * @brief Walk the OID name table and print labels for a dotted OID string (debug helper).
 * @param[in,out] oid  Dotted decimal OID (modified in place by `strtok`).
 */
#if NOXTLS_ASN1_DEBUG
static void noxtls_asn1_find_oid(uint8_t * oid);
#endif

/**
 * @brief Parse and pretty-print ASN.1 DER from a buffer (debug helper).
 * @param[in] data  Start of DER-encoded data.
 * @param[in] len   Number of bytes in @p data.
 * @return 0 if the buffer parsed without error; 1 on failure or invalid input.
 */
/* Public API (asn1.h); also referenced from certificates.c (Rule 8.7). */
uint32_t noxtls_parse_der(const uint8_t * data, uint32_t len)
{
    if((data == NULL) || (len == 0U)) {
        return 1U;
    }
#if !NOXTLS_ASN1_DEBUG
    (void)data;
    (void)len;
    return 0U;
#else
    const uint8_t * ptr = data;
    const uint8_t * end = &data[len];

    uint32_t result = 0U;

    while((ptr != end) && (result == 0U))
    {
        result = noxtls_parse_tag(&ptr, end);
    }

    return result;
#endif
}

/**
 * @brief Parse one ASN.1 TLV at @p data and advance the cursor (debug helper).
 *
 * @param[in,out] data  Current parse position; updated to end of this TLV on success.
 * @param[in] end       One past the last valid byte of the DER buffer.
 *
 * @return 0 on success; 1 on parse error or truncated input.
 */
/* Iterative TLV walk (siblings and constructed contents); avoids Rule 17.2 recursion. */
static uint32_t noxtls_parse_tag(const uint8_t ** data, const uint8_t * end)
{
    if((data == NULL) || (*data == NULL) || (end == NULL)) {
        return 1U;
    }
    /* data/end are the same DER buffer origin (cursor vs one-past-end). */
    const uint8_t * ptr = *data;

    while((uintptr_t)ptr < (uintptr_t)end)
    {
        uint8_t tag_num = (uint8_t)GET_TAG_NUM(*ptr);

        print_tag_type(tag_num);

        ptr = &ptr[1];
        if((uintptr_t)ptr >= (uintptr_t)end) {
            return 1U;
        }

        uint32_t data_length = 0U;
        if((*ptr & 0x80U) != 0U)
        {
            /* Definite long form */
            uint8_t length = (uint8_t)GET_LENGTH(*ptr);
            ptr = &ptr[1];
            int32_t i = 0;
            if((length == 0U) || (length > 4U) || (asn1_bytes_remaining(ptr, end) < (size_t)length)) {
                return 1U;
            }
            for(i = (int32_t)length - 1; i >= 0; i -= 1)
            {
                uint8_t val = (uint8_t)(*ptr);
                ptr = &ptr[1];
                NOXTLS_ASN1_PRINTF("\tval[%d]: %x\n", (int)i, val);
                switch(i) {
                case 0:
                    data_length |= (uint32_t)val;
                    break;
                case 1:
                    data_length |= (uint32_t)((uint32_t)val << 8U);
                    break;
                case 2:
                    data_length |= (uint32_t)((uint32_t)val << 16U);
                    break;
                case 3:
                    data_length |= (uint32_t)((uint32_t)val << 24U);
                    break;
                default:
                    /* Intentionally empty: length already range-checked. */
                    (void)0;
                    break;
                }
            }

        }
        else
        {
            /* Short form */
            {
                uint8_t short_len = (uint8_t)GET_LENGTH(*ptr);
                data_length = (uint32_t)short_len;
            }
            ptr = &ptr[1];
        }

        if(asn1_bytes_remaining(ptr, end) < (size_t)data_length) {
            /* Length error */
            return 1U;
        }

        parse_tag(tag_num, &ptr, data_length);
    }
    *data = ptr;
    return 0U;
}

/**
 * @brief Print an INTEGER value when it fits in 32 bits (debug helper).
 * @param[in] data  Pointer to big-endian integer bytes (not advanced).
 * @param[in] len   Length of the integer value in bytes (must be <= 4 to print).
 */
/* File-local debug helper; stdio via NOXTLS_ASN1_PRINTF is intentional. */
static void noxtls_asn1_decode_integer(const uint8_t * const * data, uint32_t len)
{
    if(len <= 4U)
    {
        const uint8_t * ptr = *data;
        uint32_t val = 0U;
        uint32_t i = 0U;
        for(i = 0U; i < len; i += 1U) {
            const uint32_t byte_pos = (uint32_t)((len - 1U) - i);
            if(byte_pos == 0U) {
                val |= (uint32_t)ptr[i];
            } else if(byte_pos == 1U) {
                val |= (uint32_t)((uint32_t)ptr[i] << 8U);
            } else if(byte_pos == 2U) {
                val |= (uint32_t)((uint32_t)ptr[i] << 16U);
            } else {
                val |= (uint32_t)((uint32_t)ptr[i] << 24U);
            }
        }

        NOXTLS_ASN1_PRINTF("\tInteger: 0x%lx (%lu)\n", (unsigned long)val, (unsigned long)val);
    }
}

/**
 * @brief Print BIT STRING length (debug helper; does not dump bits).
 * @param[in] data  BIT STRING contents (unused).
 * @param[in] len   Length of the BIT STRING value in bytes.
 */
static void noxtls_asn1_decode_bitstring(const uint8_t * const * data, uint32_t len)
{
    (void)data;
    NOXTLS_ASN1_PRINTF("bit len: %u\n", (uint32_t)len);
}

/**
 * @brief Decode OBJECT IDENTIFIER contents to dotted decimal and print (debug helper).
 *
 * @param[in] data  Pointer to DER OID body bytes (first/subsequent arc encoding).
 * @param[in] len   Length of the OID value field in bytes.
 */
static void noxtls_asn1_decode_obj_ident(const uint8_t * const * data, uint32_t len)
{
#if !NOXTLS_ASN1_DEBUG
    (void)data;
    (void)len;
#else
    uint8_t oid_str[64] = {0};

    int32_t j = 0;
    uint32_t i = 0U;

    uint32_t obj_ident_vals[8] = {0};
    uint8_t obj_ident_cnt = 0U;

    const uint8_t * ptr = *data;
    for(i = 0U; i < len; i += 1U)
    {
        if(i != 0U) {
            if((ptr[i] & 0x80U) != 0U) {
                /* Multiple byte OIDs numbers */
                uint32_t val = 0U;
                val |= (uint32_t)(ptr[i] & 0x7FU);

                for(j = 1; j < 4; j += 1)
                {
                    if((i + (uint32_t)j) >= len) {
                        return;
                    }
                    val *= 128U;
                    val |= (uint32_t)(ptr[i + (uint32_t)j] & 0x7FU);

                    if((ptr[i + (uint32_t)j] & 0x80U) == 0U) {
                        /* Last one */
                        break;
                    }
                }

                if((obj_ident_cnt + 1U) > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                    return;
                }
                obj_ident_vals[obj_ident_cnt] = val;
                obj_ident_cnt += 1U;
                i += (uint32_t)j;
            } else {
                /* MISRA 15.7: final else path */
                if((obj_ident_cnt + 1U) > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                    return;
                }
                obj_ident_vals[obj_ident_cnt] = (uint32_t)ptr[i];
                obj_ident_cnt += 1U;
            }
            continue;
        }

        /* First byte is always 40 * val1 + val2 */
        for(j = 2; j >= 0; j -= 1) {
            if(((int32_t)ptr[i] - (40 * j)) > 0) {
                if((obj_ident_cnt + 2U) > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                    return;
                }
                obj_ident_vals[obj_ident_cnt] = (uint32_t)j;
                obj_ident_cnt += 1U;
                obj_ident_vals[obj_ident_cnt] = (uint32_t)((int32_t)ptr[i] - (40U * j));
                obj_ident_cnt += 1U;
                break;
            }
        }
    }

    i = 0U;

    {
        size_t off = (size_t)noxtls_u8_strlen(oid_str);
        /* Mandatory 21.17: prove remaining capacity before snprintf. */
        if(off < (size_t)sizeof(oid_str)) {
            (void)snprintf(&oid_str[off], (sizeof(oid_str) - off), "%lu",
                           (unsigned long)obj_ident_vals[i]);
        }
    }
    for(i = 1U; i < obj_ident_cnt; i += 1U)
    {
        size_t off = (size_t)noxtls_u8_strlen(oid_str);
        if(off < (size_t)sizeof(oid_str)) {
            (void)snprintf(&oid_str[off], (sizeof(oid_str) - off), ".%lu",
                           (unsigned long)obj_ident_vals[i]);
        }
    }

    NOXTLS_ASN1_PRINTF("OID_STR: %s\n", oid_str);
    (void)noxtls_asn1_find_oid(oid_str);

    NOXTLS_ASN1_PRINTF("\n");
#endif /* NOXTLS_ASN1_DEBUG */
}

/**
 * @brief Find an OID in the OID table and print the name.
 *
 * @param[in] oid  OID string to search for.
 *
 * @return void
 */
#if NOXTLS_ASN1_DEBUG
/* strtok requires mutable uint8_t *; signedness of plain char is not relied upon. */
static void noxtls_asn1_find_oid(uint8_t * oid)
{
    const oid_item_t * oid_ptr = &base_oids[0];
    const uint8_t *pch = NULL;
    uint32_t id = 0U;

#ifdef _MSC_VER
    uint8_t * context = NULL;
    pch = strtok_s(oid, ".", &context);
#else
    pch = strtok(oid, ".");
#endif

    while(pch != NULL)
    {
        id = (uint32_t) strtoul(pch, NULL, 10);

        while(oid_ptr != NULL)
        {
            if((oid_ptr->id == 0U) &&
                    (oid_ptr->name == NULL) &&
                    (oid_ptr->items == NULL))
            {
                break;
            }
            if(oid_ptr->id == id)
            {
                if(oid_ptr->name != NULL) {
                    NOXTLS_ASN1_PRINTF("%s ", oid_ptr->name);
                }

                if(oid_ptr->items != NULL) {
                    oid_ptr = oid_ptr->items;
                }
                break;
            }
            oid_ptr = &oid_ptr[1U];
        }

        if(oid_ptr != NULL) {
            /* Move to next digit (pch is non-NULL at loop entry) */
#ifdef _MSC_VER
            pch = strtok_s(NULL, ".", &context);
#else
            pch = strtok(NULL, ".");
#endif
        }
        else
        {
            break;
        }
    }
}
#endif /* NOXTLS_ASN1_DEBUG */

/**
 * @brief Print PrintableString or IA5String contents (debug helper).
 *
 * @param[in] data  Pointer to string bytes.
 * @param[in] len   Length of the string value in bytes.
 */
static void noxtls_asn1_decode_print_string(const uint8_t * const * data, uint32_t len)
{
#if !NOXTLS_ASN1_DEBUG
    (void)data;
    (void)len;
#else
    uint32_t i = 0U;
    const uint8_t * ptr = *data;

    NOXTLS_ASN1_PRINTF("\tString: ");
    for(i = 0U; i < len; i += 1U)
    {
        NOXTLS_ASN1_PRINTF("%c", ptr[i]);
    }

    NOXTLS_ASN1_PRINTF("\n");
#endif
}

/**
 * @brief Parse a tag and dispatch to the appropriate handler.
 *
 * @param[in] type  Tag type.
 * @param[in,out] data  Value bytes; advanced by @p len on exit for primitive types.
 * @param[in] len       Length of the TLV value field.
 * @return void
 */
/* Cursor advances by TLV length; extent established by caller after length check. */
static void parse_tag(uint8_t type, const uint8_t ** data, uint32_t len)
{
    const uint8_t tag = type;

    if(tag == (uint8_t)ASN1_TAG_EOC) {
        *data = &(*data)[len];
    } else if(tag == (uint8_t)ASN1_TAG_BOOLEAN) {
        NOXTLS_ASN1_PRINTF("Bool Val: %d", (*data)[0]);
        *data = &(*data)[len];
    } else if(tag == (uint8_t)ASN1_TAG_INTEGER) {
        (void)noxtls_asn1_decode_integer(data, len);
        *data = &(*data)[len];
    } else if(tag == (uint8_t)ASN1_TAG_BITSTRING) {
        (void)noxtls_asn1_decode_bitstring(data, len);
        *data = &(*data)[len];
    } else if((tag == (uint8_t)ASN1_TAG_OCTET_STR) || (tag == (uint8_t)ASN1_TAG_NULL)) {
        *data = &(*data)[len];
    } else if(tag == (uint8_t)ASN1_TAG_OBJ_IDENT) {
        (void)noxtls_asn1_decode_obj_ident(data, len);
        *data = &(*data)[len];
    } else if((tag == (uint8_t)ASN1_TAG_OBJECT) || (tag == (uint8_t)ASN1_TAG_EXTERNAL) ||
              (tag == (uint8_t)ASN1_TAG_REAL_FLOAT) || (tag == (uint8_t)ASN1_TAG_ENUMERATED) ||
              (tag == (uint8_t)ASN1_TAG_EMBEDDED) || (tag == (uint8_t)ASN1_TAG_UTF8STRING) ||
              (tag == (uint8_t)ASN1_TAG_RELATIVE_OID) || (tag == (uint8_t)ASN1_TAG_TIME)) {
        *data = &(*data)[len];
    } else if((tag == (uint8_t)ASN1_TAG_IA5STRING) || (tag == (uint8_t)ASN1_TAG_PRINTABLESTRING)) {
        (void)noxtls_asn1_decode_print_string(data, len);
        *data = &(*data)[len];
    } else if(tag == (uint8_t)ASN1_TAG_BMPSTRING) {
        *data = &(*data)[len];
    } else if((tag == (uint8_t)ASN1_TAG_SEQUENCE) || (tag == (uint8_t)ASN1_TAG_SET)) {
        /* Constructed types: no pointer advance in this debug helper */
    } else {
        *data = &(*data)[len];
    }

}

/** 
 * @brief Print a human-readable universal tag name (debug helper).
 *
 * @param[in] type Universal tag number (`ASN1_TAG_*`).
 * @return void
 */
static void print_tag_type(uint8_t type)
{
    switch(type)
    {
    case ASN1_TAG_EOC:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_EOC\n");
        break;
    case ASN1_TAG_BOOLEAN:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_BOOLEAN\n");
        break;
    case ASN1_TAG_INTEGER:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_INTEGER\n");
        break;
    case ASN1_TAG_BITSTRING:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_BITSTRING\n");
        break;
    case ASN1_TAG_OCTET_STR:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_OCTET_STR\n");
        break;
    case ASN1_TAG_NULL:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_NULL\n");
        break;
    case ASN1_TAG_OBJ_IDENT:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_OBJ_IDENT\n");
        break;
    case ASN1_TAG_OBJECT:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_OBJECT\n");
        break;
    case ASN1_TAG_EXTERNAL:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_EXTERNAL\n");
        break;
    case ASN1_TAG_REAL_FLOAT:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_REAL_FLOAT\n");
        break;
    case ASN1_TAG_ENUMERATED:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_ENUMERATED\n");
        break;
    case ASN1_TAG_EMBEDDED:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_EMBEDDED\n");
        break;
    case ASN1_TAG_UTF8STRING:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_UTF8STRING\n");
        break;
    case ASN1_TAG_RELATIVE_OID:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_RELATIVE_OID\n");
        break;
    case ASN1_TAG_TIME:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_TIME\n");
        break;
    case ASN1_TAG_IA5STRING:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_IA5STRING\n");
        break;
    case ASN1_TAG_PRINTABLESTRING:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_PRINTABLESTRING\n");
        break;
    case ASN1_TAG_BMPSTRING:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_BMPSTRING\n");
        break;
    case ASN1_TAG_SEQUENCE:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_SEQUENCE\n");
        break;
    case ASN1_TAG_SET:
        NOXTLS_ASN1_PRINTF("Type: ASN1_TAG_SET\n");
        break;
    default:
        NOXTLS_ASN1_PRINTF("Type: Unknown (0x%02x)\n", type);
        break;
    }
}

/* ========== ASN.1 DER encode API ========== */

/**
 * Copy @p n bytes to @p dst[@p off] when the write fits in @p dst_max.
 * Centralizes bounds proof for Mandatory Rule 21.18 on encode paths.
 */
static uint32_t asn1_write_bytes(uint8_t *dst, uint32_t dst_max, uint32_t off,
                                 const uint8_t *src, uint32_t n)
{
    uint32_t i = 0U;
    if((dst == NULL) || (src == NULL)) {
        return 0U;
    }
    if((n > dst_max) || (off > (dst_max - n))) {
        return 0U;
    }
    for(i = 0U; i < n; i += 1U) {
        dst[off + i] = src[i];
    }
    return 1U;
}

/**
 * @brief Encode a DER definite length field into @p out.
 *
 * @param[out] out  Output buffer (at least 5 bytes for longest form).
 * @param[in] len   Content length to encode.
 * @return Number of length bytes written (1–4), or 0 if @p len exceeds encodable range.
 */
/* Indexed writes into caller buffer; out must have room for the chosen length form. */
uint32_t noxtls_asn1_put_length(uint8_t *out, uint32_t out_max, uint32_t len)
{
    if(out == NULL) {
        return 0U;
    }
    if(len < 128U) {
        if(out_max < 1U) {
            return 0U;
        }
        out[0] = (uint8_t)len;
        return 1U;
    }
    if(len <= 0xFFU) {
        if(out_max < 2U) {
            return 0U;
        }
        out[0] = 0x81U;
        out[1] = (uint8_t)len;
        return 2U;
    }
    if(len <= 0xFFFFU) {
        if(out_max < 3U) {
            return 0U;
        }
        out[0] = 0x82U;
        out[1] = (uint8_t)(len >> 8U);
        out[2] = (uint8_t)len;
        return 3U;
    }
    if(len <= 0xFFFFFFU) {
        if(out_max < 4U) {
            return 0U;
        }
        out[0] = 0x83U;
        out[1] = (uint8_t)(len >> 16U);
        out[2] = (uint8_t)(len >> 8U);
        out[3] = (uint8_t)len;
        return 4U;
    }
    return 0U;
}

/**
 * @brief Encode a DER INTEGER from a big-endian magnitude buffer.
 *
 * @param[out] out        Output buffer for tag, length, and value.
 * @param[in] out_max     Size of @p out.
 * @param[in] value       Big-endian integer bytes (leading zeros stripped).
 * @param[in] value_len   Length of @p value.
 * @return Total bytes written, or 0 if @p out is too small or arguments are invalid.
 */
uint32_t noxtls_asn1_put_integer(uint8_t *out, uint32_t out_max, const uint8_t *int_be, uint32_t int_be_len)
{
    if((out == NULL) || (int_be == NULL) || (int_be_len == 0U)) {
        return 0U;
    }

    /* Skip leading zero bytes (keep at least one byte if value is zero) */
    const uint8_t *start = int_be;
    uint32_t be_len = int_be_len;
    while((be_len > 1U) && (*start == 0U)) {
        start = &start[1U];
        be_len -= 1U;
    }

    /* For positive INTEGER, if high bit is set we must prepend 0x00 */
    uint32_t need_zero = (uint32_t)((((be_len > 0U) && ((*start & 0x80U) != 0U)) ? 1U : 0U));
    uint32_t payload_len = (uint32_t)(be_len + need_zero);

    uint8_t len_buf[5];
    uint32_t lb = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), payload_len));
    if((lb == 0U) || ((1U + lb + payload_len) > out_max)) {
        return 0U;
    }

    out[0] = ASN1_TAG_INTEGER;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, lb) == 0U) {
        return 0U;
    }
    {
        uint32_t off = (uint32_t)(1U + lb);
        if(need_zero != 0U) {
            out[off] = 0x00U;
            off += 1U;
        }
        if(asn1_write_bytes(out, out_max, off, start, be_len) == 0U) {
            return 0U;
        }
        return off + be_len;
    }
}

/**
 * @brief Encode a constructed SEQUENCE (tag 0x30) wrapping @p contents.
 *
 * @param[out] out            Output buffer.
 * @param[in] out_max         Size of @p out.
 * @param[in] contents        Pre-encoded child TLV bytes (may be NULL if @p contents_len is 0).
 * @param[in] contents_len    Length of @p contents.
 * @return Total bytes written, or 0 on buffer overflow or invalid arguments.
 */
uint32_t noxtls_asn1_put_sequence(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if((out == NULL) || ((contents == NULL) && (contents_len != 0U))) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), contents_len));
    if(len_bytes == 0U) {
        return 0U;
    }
    if((1U + len_bytes + contents_len) > out_max) {
        return 0U;
    }
    out[0] = ASN1_DER_TAG_SEQUENCE;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if((contents != NULL) && (contents_len > 0U)) {
        if(asn1_write_bytes(out, out_max, 1U + len_bytes, contents, contents_len) == 0U) {
            return 0U;
        }
    }
    return 1U + len_bytes + contents_len;
}

/**
 * @brief Encode OBJECT IDENTIFIER (tag 0x06) from raw DER OID body bytes.
 *
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] oid       OID value octets (already DER-encoded arcs, without tag/length).
 * @param[in] oid_len   Length of @p oid.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_oid_raw(uint8_t *out, uint32_t out_max, const uint8_t *oid_bytes, uint32_t oid_bytes_len)
{
    if((out == NULL) || (oid_bytes == NULL) || (oid_bytes_len == 0U)) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), oid_bytes_len));
    if((len_bytes == 0U) || ((1U + len_bytes + oid_bytes_len) > out_max)) {
        return 0U;
    }
    out[0] = ASN1_TAG_OBJ_IDENT;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if(asn1_write_bytes(out, out_max, 1U + len_bytes, oid_bytes, oid_bytes_len) == 0U) {
        return 0U;
    }
    return 1U + len_bytes + oid_bytes_len;
}

/**
 * @brief Encode BIT STRING (tag 0x03) with zero unused bits prefix.
 *
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] data        Bit string payload (may be NULL if @p data_len is 0).
 * @param[in] data_len    Length of @p data in bytes.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_bit_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if((out == NULL) || ((data == NULL) && (data_len != 0U))) {
        return 0U;
    }
    /* BIT STRING: 1 byte unused bits (0) + data */
    uint32_t payload_len = (uint32_t)(1U + data_len);
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), payload_len));
    if((len_bytes == 0U) || ((1U + len_bytes + payload_len) > out_max)) {
        return 0U;
    }
    out[0] = ASN1_TAG_BITSTRING;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    out[1U + len_bytes] = 0x00U; /* unused bits */
    if((data != NULL) && (data_len > 0U)) {
        if(asn1_write_bytes(out, out_max, 1U + len_bytes + 1U, data, data_len) == 0U) {
            return 0U;
        }
    }
    return 1U + len_bytes + payload_len;
}

/**
 * @brief Encode UTCTime (tag 0x17) from an ASN.1 time string.
 *
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] time_str    UTCTime text, typically 13 bytes (`YYMMDDHHMMSSZ`).
 * @return Total bytes written, or 0 if @p time_str is empty, too long, or buffer is small.
 */
uint32_t noxtls_asn1_put_utc_time(uint8_t *out, uint32_t out_max, const uint8_t *time_str)
{
    if((out == NULL) || (time_str == NULL)) {
        return 0U;
    }
    /* UTCTime is typically 13 bytes: YYMMDDHHMMSSZ */
    uint32_t slen = 0U;
    while((slen < 32U) && (time_str[slen] != 0U)) {
        slen += 1U;
    }
    if((slen == 0U) || (slen > 32U)) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), slen));
    if((len_bytes == 0U) || ((1U + len_bytes + slen) > out_max)) {
        return 0U;
    }
    out[0] = 0x17U; /* UTCTime */
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if(asn1_write_bytes(out, out_max, 1U + len_bytes, (const uint8_t *)(const void *)time_str, slen) == 0U) {
        return 0U;
    }
    return 1U + len_bytes + slen;
}

/**
 * @brief Encode a context-specific constructed EXPLICIT wrapper `[tag_no]`.
 *
 * @param[out] out            Output buffer.
 * @param[in] out_max         Size of @p out.
 * @param[in] tag_no          Context tag number (0–31).
 * @param[in] contents        Wrapped TLV bytes (may be NULL if @p contents_len is 0).
 * @param[in] contents_len    Length of @p contents.
 * @return Total bytes written, or 0 if @p tag_no > 31 or buffer is too small.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
uint32_t noxtls_asn1_put_explicit(uint8_t *out, uint32_t out_max, uint8_t tag_no, const uint8_t *contents, uint32_t contents_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if((out == NULL) || ((contents == NULL) && (contents_len != 0U))) {
        return 0U;
    }
    if(tag_no > 31U) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), contents_len));
    if((len_bytes == 0U) || ((1U + len_bytes + contents_len) > out_max)) {
        return 0U;
    }
    out[0] = (uint8_t)(0x80U | 0x20U | tag_no); /* context-specific, constructed */
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if((contents != NULL) && (contents_len > 0U)) {
        if(asn1_write_bytes(out, out_max, 1U + len_bytes, contents, contents_len) == 0U) {
            return 0U;
        }
    }
    return 1U + len_bytes + contents_len;
}

/**
 * @brief Encode OCTET STRING (tag 0x04).
 *
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] data        Raw octets (may be NULL if @p data_len is 0).
 * @param[in] data_len    Length of @p data.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_octet_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if((out == NULL) || ((data == NULL) && (data_len != 0U))) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), data_len));
    if((len_bytes == 0U) || ((1U + len_bytes + data_len) > out_max)) {
        return 0U;
    }
    out[0] = ASN1_TAG_OCTET_STR;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if((data != NULL) && (data_len > 0U)) {
        if(asn1_write_bytes(out, out_max, 1U + len_bytes, data, data_len) == 0U) {
            return 0U;
        }
    }
    return 1U + len_bytes + data_len;
}

/**
 * @brief Encode a constructed SET (tag 0x31) wrapping @p contents.
 *
 * @param[out] out            Output buffer.
 * @param[in] out_max         Size of @p out.
 * @param[in] contents        Pre-encoded member TLV bytes (may be NULL if @p contents_len is 0).
 * @param[in] contents_len    Length of @p contents.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_set(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if((out == NULL) || ((contents == NULL) && (contents_len != 0U))) {
        return 0U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), contents_len));
    if((len_bytes == 0U) || ((1U + len_bytes + contents_len) > out_max)) {
        return 0U;
    }
    out[0] = 0x31U; /* SET, constructed */
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if((contents != NULL) && (contents_len > 0U)) {
        if(asn1_write_bytes(out, out_max, 1U + len_bytes, contents, contents_len) == 0U) {
            return 0U;
        }
    }
    return 1U + len_bytes + contents_len;
}

/**
 * @brief Encode PrintableString (tag 0x13) from a NUL-terminated C string
 *.
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] str       PrintableString characters (not NUL-terminated in DER).
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_printable_string(uint8_t *out, uint32_t out_max, const uint8_t *str)
{
    if((out == NULL) || (str == NULL)) {
        return 0U;
    }
    uint32_t slen = 0U;
    while((slen < 0xFFFFU) && (str[slen] != 0U)) {
        slen += 1U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), slen));
    if((len_bytes == 0U) || ((1U + len_bytes + slen) > out_max)) {
        return 0U;
    }
    out[0] = ASN1_TAG_PRINTABLESTRING;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if(asn1_write_bytes(out, out_max, 1U + len_bytes, (const uint8_t *)(const void *)str, slen) == 0U) {
        return 0U;
    }
    return 1U + len_bytes + slen;
}

/**
 * @brief Encode IA5String (tag 0x16) from a NUL-terminated C string.
 *
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] str       IA5 characters (not NUL-terminated in DER).
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_ia5_string(uint8_t *out, uint32_t out_max, const uint8_t *str)
{
    if((out == NULL) || (str == NULL)) {
        return 0U;
    }
    uint32_t slen = 0U;
    while((slen < 0xFFFFU) && (str[slen] != 0U)) {
        slen += 1U;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = (uint32_t)(noxtls_asn1_put_length(len_buf, (uint32_t)sizeof(len_buf), slen));
    if((len_bytes == 0U) || ((1U + len_bytes + slen) > out_max)) {
        return 0U;
    }
    out[0] = ASN1_TAG_IA5STRING;
    if(asn1_write_bytes(out, out_max, 1U, len_buf, len_bytes) == 0U) {
        return 0U;
    }
    if(asn1_write_bytes(out, out_max, 1U + len_bytes, (const uint8_t *)(const void *)str, slen) == 0U) {
        return 0U;
    }
    return 1U + len_bytes + slen;
}
