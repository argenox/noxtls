/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    asn1.c
* Summary: ASN1
*
*/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "noxtls_common.h"
#include "asn1.h"
#include "oids.h"

#if defined(NOXTLS_NO_ASN1_PRINTF)
#define NOXTLS_ASN1_PRINTF(...) ((void)0)
#else
#define NOXTLS_ASN1_PRINTF(...) printf(__VA_ARGS__)
#endif

#define GET_TAG_CLASS(X)      (((((1u << 7) | (1u << 6)) & (X))) >> 6)
#define GET_TAG_PRIM_CONST(X) ((((1u << 5) & (X))) >> 5)
#define GET_TAG_NUM(X)        ((X) & 0x1Fu)

#define GET_LENGTH(X)         ((X) & 0x7Fu)

#define ASN1_CLASS_TYPE_UNIVERSAL     0
#define ASN1_CLASS_TYPE_APPLICATION   1
#define ASN1_CLASS_TYPE_CONTEXT       2
#define ASN1_CLASS_TYPE_PRIVATE       3

#define ASN1_TAG_TYPE_PRIMITIVE                0
#define ASN1_TAG_TYPE_CONSTRUCTED              1

/**
 * @brief Parse one ASN.1 TLV at @p data and advance the cursor (debug helper).
 * @param[in,out] data  Current parse position; updated to end of this TLV on success.
 * @param[in] end       One past the last valid byte of the DER buffer.
 * @return 0 on success; 1 on parse error or truncated input.
 */
uint32_t noxtls_parse_tag(uint8_t ** data, uint8_t * end);

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
static void parse_tag(uint8_t type, uint8_t ** data, uint32_t len);

/**
 * @brief Walk the OID name table and print labels for a dotted OID string (debug helper).
 * @param[in,out] oid  Dotted decimal OID (modified in place by `strtok`).
 */
void noxtls_asn1_find_oid(char * oid);

/**
 * @brief Parse and pretty-print ASN.1 DER from a buffer (debug helper).
 * @param[in] data  Start of DER-encoded data.
 * @param[in] len   Number of bytes in @p data.
 * @return 0 if the buffer parsed without error; 1 on failure or invalid input.
 */
uint32_t noxtls_parse_der(uint8_t * data, uint32_t len)
{
    if(data == NULL || len == 0) {
        return 1;
    }
    uint8_t * ptr = data;
    uint8_t * end = data + len;

    uint32_t result = 0;

    while(ptr != end && result == 0)
    {
        result = noxtls_parse_tag(&ptr, end);

        //NOXTLS_ASN1_PRINTF("left: %ld\n", end - ptr);
    }

    return result;
}

uint32_t noxtls_parse_tag(uint8_t ** data, uint8_t * end)
{
    if(data == NULL || *data == NULL || end == NULL) {
        return 1;
    }
    if(*data >= end) {
        return 1;
    }
    uint8_t * ptr = *data;


    //NOXTLS_ASN1_PRINTF("0x%02x\n", *ptr);

//    NOXTLS_ASN1_PRINTF("0x%02x\n", GET_TAG_NUM(*ptr));

    uint8_t tag_num = GET_TAG_NUM(*ptr);

    print_tag_type(tag_num);

    ptr++;
    if(ptr >= end) {
        return 1;
    }
    //NOXTLS_ASN1_PRINTF("0x%02x\n", *ptr);

    uint32_t data_length = 0;
    if(*ptr & 0x80)
    {
        /* Definite */
        uint8_t length = GET_LENGTH(*ptr++);
        int i;
        if(length == 0 || length > 4 || (size_t)(end - ptr) < (size_t)length) {
            return 1;
        }
        //NOXTLS_ASN1_PRINTF("\tDefinite Length: %d\n", length);
        for(i = length - 1; i >= 0; i--)
        {
            uint8_t val = (*ptr++);
            NOXTLS_ASN1_PRINTF("\tval[%d]: %x\n", i, val);
            data_length |= ((uint32_t)val) << (i * 8);
        }

    }
    else
    {
        /* Short form */

        data_length = GET_LENGTH(*ptr++);

        //NOXTLS_ASN1_PRINTF("\tshort form: %d 0x%x\n", data_length, data_length);
    }

    //NOXTLS_ASN1_PRINTF("%p == %p ", ptr + data_length, end);
    if((uint32_t)(end - ptr) < data_length) {
        /* Length error */
        return 1;
    }
    //NOXTLS_ASN1_PRINTF("ptr[0]: %x\n", ptr[0]);
    parse_tag(tag_num, &ptr, data_length);


    if(end - ptr > 0)
    {
        if(noxtls_parse_tag(&ptr, end) != 0) {
            return 1;
        }
    }



    //NOXTLS_ASN1_PRINTF("\tLength: %d\n", data_length);
    //ptr += data_length;

    //NOXTLS_ASN1_PRINTF("Now on: %x\n", *ptr);
    *data = ptr;
    return 0;
}




/**
 * @brief Print an INTEGER value when it fits in 32 bits (debug helper).
 * @param[in] data  Pointer to big-endian integer bytes (not advanced).
 * @param[in] len   Length of the integer value in bytes (must be <= 4 to print).
 */
void noxtls_asn1_decode_integer(uint8_t ** data, uint32_t len)
{
    if(len <= 4)
    {
        const uint8_t * ptr = *data;
        uint32_t val = 0;
        uint32_t i;
        for(i = 0; i < len; i++) {
            val |= ((uint32_t)ptr[i]) << ((len - 1 - i) * 8);
        }

        NOXTLS_ASN1_PRINTF("\tInteger: 0x%lx (%lu)\n", (unsigned long)val, (unsigned long)val);
    }
}

/**
 * @brief Print BIT STRING length (debug helper; does not dump bits).
 * @param[in] data  BIT STRING contents (unused).
 * @param[in] len   Length of the BIT STRING value in bytes.
 */
void noxtls_asn1_decode_bitstring(uint8_t ** data, uint32_t len)
{
    (void)data;
    //uint32_t i;
    //int j;

    NOXTLS_ASN1_PRINTF("bit len: %u\n", (unsigned int)len);
    //for(i = 0; i < len; i++)
    {
      //  for(j = 7; j >= 0; j++)
        {
            //NOXTLS_ASN1_PRINTF("%d", ((*data[i] & (1 << j)) >> j));
        }
    }
}

/**
 * @brief Decode OBJECT IDENTIFIER contents to dotted decimal and print (debug helper).
 * @param[in] data  Pointer to DER OID body bytes (first/subsequent arc encoding).
 * @param[in] len   Length of the OID value field in bytes.
 */
void noxtls_asn1_decode_obj_ident(uint8_t ** data, uint32_t len)
{
    char oid_str[64] = {0};

    int j;
    uint32_t i;

    uint32_t obj_ident_vals[8] = {0};
    uint8_t obj_ident_cnt = 0;

    const uint8_t * ptr = *data;
    for(i = 0; i < len; i++)
    {
        if(i == 0) {
            /* First byte is always 40 * val1 + val2 */

            for(j = 2; j >= 0; j--) {
                if(ptr[i] - (40 * j) > 0) {
                    if(obj_ident_cnt + 2 > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                        return;
                    }
                    obj_ident_vals[obj_ident_cnt++] = (uint32_t)j;
                    obj_ident_vals[obj_ident_cnt++] = (uint32_t)(ptr[i] - (40*j));
                    break;
                }
            }
        }
        else
        {
            if(ptr[i] & 0x80) {
                /* Multiple byte OIDs numbers */
                uint32_t val = 0;
                val |= (ptr[i] & 0x7F);

                for(j = 1; j < 4; j++)
                {
                    if(i + (uint32_t)j >= len) {
                        return;
                    }
                    val *= 128;
                    val |= (ptr[i + j] & 0x7F);

                    if((ptr[i + j] & 0x80) == 0) {
                        /* Last one */
                        break;
                    }
                }

                if(obj_ident_cnt + 1 > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                    return;
                }
                obj_ident_vals[obj_ident_cnt++] = val;
                i += j;
            }
            else
            {
                if(obj_ident_cnt + 1 > (uint8_t)(sizeof(obj_ident_vals) / sizeof(obj_ident_vals[0]))) {
                    return;
                }
                obj_ident_vals[obj_ident_cnt++] = ptr[i];
            }
        }
    }

    i = 0;

    {
        size_t off = strlen(oid_str);
        snprintf(&oid_str[off], sizeof(oid_str) - off, "%lu", (unsigned long)obj_ident_vals[i]);
    }
    for(i = 1; i < obj_ident_cnt; i++)
    {
        size_t off = strlen(oid_str);
        snprintf(&oid_str[off], sizeof(oid_str) - off, ".%lu", (unsigned long)obj_ident_vals[i]);
    }

    NOXTLS_ASN1_PRINTF("OID_STR: %s\n", oid_str);
    noxtls_asn1_find_oid(oid_str);

    NOXTLS_ASN1_PRINTF("\n");
}

void noxtls_asn1_find_oid(char * oid)
{
    oid_item_t * oid_ptr = (oid_item_t *)&base_oids[0];
    const char * pch;
    uint32_t id;

#ifdef _MSC_VER
    char * context = NULL;
    pch = strtok_s(oid, ".", &context);
#else
    pch = strtok(oid, ".");
#endif

    while(pch != NULL)
    {
        id = (uint32_t) strtoul(pch, NULL, 10);
        //NOXTLS_ASN1_PRINTF("ID %d\n", id);

        while(oid_ptr != NULL)
        {
            //NOXTLS_ASN1_PRINTF("Cur ID %d %s == %d \n", oid_ptr->id,oid_ptr->name, id);
            if(oid_ptr->id == 0 &&
                    oid_ptr->name == NULL &&
                    oid_ptr->items == NULL)
            {
                //NOXTLS_ASN1_PRINTF("STOP\n");
                break;
            }
            else if(oid_ptr->id == id)
            {
                //NOXTLS_ASN1_PRINTF("ID Match \n");
                if(oid_ptr->name != NULL) {
                    NOXTLS_ASN1_PRINTF("%s ", oid_ptr->name);
                }

                if(oid_ptr->items != NULL) {
                    //NOXTLS_ASN1_PRINTF("Setting to items\n");
                    oid_ptr = (oid_item_t *)oid_ptr->items;
                }
                break;
            }
            else
            {
                //NOXTLS_ASN1_PRINTF("Increment oid\n");
                oid_ptr++;
            }
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

/**
 * @brief Print PrintableString or IA5String contents (debug helper).
 * @param[in] data  Pointer to string bytes.
 * @param[in] len   Length of the string value in bytes.
 */
void noxtls_asn1_decode_print_string(uint8_t ** data, uint32_t len)
{
    uint32_t i = 0;

    const uint8_t * ptr = *data;


    NOXTLS_ASN1_PRINTF("\tString: ");
    for(i = 0; i < len; i++)
    {
        NOXTLS_ASN1_PRINTF("%c", ptr[i]);
    }

    NOXTLS_ASN1_PRINTF("\n");
}


static void parse_tag(uint8_t type, uint8_t ** data, uint32_t len)
{

    switch(type)
    {
    case ASN1_TAG_EOC:
        *data += len;
        break;
    case ASN1_TAG_BOOLEAN:
        NOXTLS_ASN1_PRINTF("Bool Val: %d", *data[0]);
        *data += len;
        break;
    case ASN1_TAG_INTEGER:
        noxtls_asn1_decode_integer(data, len);
        *data += len;
        break;
    case ASN1_TAG_BITSTRING:
        noxtls_asn1_decode_bitstring(data, len);
        *data += len;
        break;
    case ASN1_TAG_OCTET_STR:
    case ASN1_TAG_NULL:
        *data += len;
        break;
    case ASN1_TAG_OBJ_IDENT:
        noxtls_asn1_decode_obj_ident(data, len);
        *data += len;
        break;
    case ASN1_TAG_OBJECT:
    case ASN1_TAG_EXTERNAL:
    case ASN1_TAG_REAL_FLOAT:
    case ASN1_TAG_ENUMERATED:
    case ASN1_TAG_EMBEDDED:
    case ASN1_TAG_UTF8STRING:
    case ASN1_TAG_RELATIVE_OID:
    case ASN1_TAG_TIME:
        *data += len;
        break;
    case ASN1_TAG_IA5STRING:
    case ASN1_TAG_PRINTABLESTRING:
        noxtls_asn1_decode_print_string(data, len);
        *data += len;
        break;
    case ASN1_TAG_BMPSTRING:
        *data += len;
        break;
    case ASN1_TAG_SEQUENCE:
    case ASN1_TAG_SET:
        /* Constructed types: no pointer advance in this debug helper */
        break;
    default:
        *data += len;

    }

}

static void print_tag_type(uint8_t type)
{
    //NOXTLS_ASN1_PRINTF("%x\n", type);
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

    }

}

/* ========== ASN.1 DER encode API ========== */

/**
 * @brief Encode a DER definite length field into @p out.
 * @param[out] out  Output buffer (at least 5 bytes for longest form).
 * @param[in] len   Content length to encode.
 * @return Number of length bytes written (1–4), or 0 if @p len exceeds encodable range.
 */
uint32_t noxtls_asn1_put_length(uint8_t *out, uint32_t len)
{
    if(out == NULL) {
        return 0;
    }
    if(len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if(len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    if(len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        return 3;
    }
    if(len <= 0xFFFFFF) {
        out[0] = 0x83;
        out[1] = (uint8_t)(len >> 16);
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
        return 4;
    }
    return 0;
}

/**
 * @brief Encode a DER INTEGER from a big-endian magnitude buffer.
 * @param[out] out        Output buffer for tag, length, and value.
 * @param[in] out_max     Size of @p out.
 * @param[in] value       Big-endian integer bytes (leading zeros stripped).
 * @param[in] value_len   Length of @p value.
 * @return Total bytes written, or 0 if @p out is too small or arguments are invalid.
 */
uint32_t noxtls_asn1_put_integer(uint8_t *out, uint32_t out_max, const uint8_t *value, uint32_t value_len)
{
    if(out == NULL || value == NULL || value_len == 0) {
        return 0;
    }

    /* Skip leading zero bytes (keep at least one byte if value is zero) */
    const uint8_t *start = value;
    while(value_len > 1 && *start == 0) {
        start++;
        value_len--;
    }

    /* For positive INTEGER, if high bit is set we must prepend 0x00 */
    int need_zero = (value_len > 0 && (*start & 0x80) != 0) ? 1 : 0;
    uint32_t payload_len = value_len + (uint32_t)need_zero;

    uint8_t len_buf[5];
    uint32_t lb = noxtls_asn1_put_length(len_buf, payload_len);
    if(lb == 0 || 1 + lb + payload_len > out_max) {
        return 0;
    }

    out[0] = ASN1_TAG_INTEGER;
    memcpy(out + 1, len_buf, lb);
    {
        uint32_t off = 1 + lb;
        if(need_zero) {
            out[off++] = 0x00;
        }
        memcpy(out + off, start, value_len);
        return off + value_len;
    }
}

/**
 * @brief Encode a constructed SEQUENCE (tag 0x30) wrapping @p contents.
 * @param[out] out            Output buffer.
 * @param[in] out_max         Size of @p out.
 * @param[in] contents        Pre-encoded child TLV bytes (may be NULL if @p contents_len is 0).
 * @param[in] contents_len    Length of @p contents.
 * @return Total bytes written, or 0 on buffer overflow or invalid arguments.
 */
uint32_t noxtls_asn1_put_sequence(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if(out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if(len_bytes == 0) {
        return 0;
    }
    if(1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = ASN1_DER_TAG_SEQUENCE;
    memcpy(out + 1, len_buf, len_bytes);
    if(contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

/**
 * @brief Encode OBJECT IDENTIFIER (tag 0x06) from raw DER OID body bytes.
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] oid       OID value octets (already DER-encoded arcs, without tag/length).
 * @param[in] oid_len   Length of @p oid.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_oid_raw(uint8_t *out, uint32_t out_max, const uint8_t *oid, uint32_t oid_len)
{
    if(out == NULL || oid == NULL || oid_len == 0) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, oid_len);
    if(len_bytes == 0 || 1 + len_bytes + oid_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_OBJ_IDENT;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, oid, oid_len);
    return 1 + len_bytes + oid_len;
}

/**
 * @brief Encode BIT STRING (tag 0x03) with zero unused bits prefix.
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] data        Bit string payload (may be NULL if @p data_len is 0).
 * @param[in] data_len    Length of @p data in bytes.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_bit_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if(out == NULL || (data == NULL && data_len != 0)) {
        return 0;
    }
    /* BIT STRING: 1 byte unused bits (0) + data */
    uint32_t payload_len = 1 + data_len;
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, payload_len);
    if(len_bytes == 0 || 1 + len_bytes + payload_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_BITSTRING;
    memcpy(out + 1, len_buf, len_bytes);
    out[1 + len_bytes] = 0x00; /* unused bits */
    if(data != NULL && data_len > 0) {
        memcpy(out + 1 + len_bytes + 1, data, data_len);
    }
    return 1 + len_bytes + payload_len;
}

/**
 * @brief Encode UTCTime (tag 0x17) from an ASN.1 time string.
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] time_str    UTCTime text, typically 13 bytes (`YYMMDDHHMMSSZ`).
 * @return Total bytes written, or 0 if @p time_str is empty, too long, or buffer is small.
 */
uint32_t noxtls_asn1_put_utc_time(uint8_t *out, uint32_t out_max, const char *time_str)
{
    if(out == NULL || time_str == NULL) {
        return 0;
    }
    /* UTCTime is typically 13 bytes: YYMMDDHHMMSSZ */
    uint32_t slen = 0;
    while(slen < 32 && time_str[slen] != '\0') {
        slen++;
    }
    if(slen == 0 || slen > 32) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if(len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = 0x17; /* UTCTime */
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, time_str, slen);
    return 1 + len_bytes + slen;
}

/**
 * @brief Encode a context-specific constructed EXPLICIT wrapper `[tag_no]`.
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
    if(out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    if(tag_no > 31) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if(len_bytes == 0 || 1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = (uint8_t)(0x80 | 0x20 | tag_no); /* context-specific, constructed */
    memcpy(out + 1, len_buf, len_bytes);
    if(contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

/**
 * @brief Encode OCTET STRING (tag 0x04).
 * @param[out] out        Output buffer.
 * @param[in] out_max     Size of @p out.
 * @param[in] data        Raw octets (may be NULL if @p data_len is 0).
 * @param[in] data_len    Length of @p data.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_octet_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if(out == NULL || (data == NULL && data_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, data_len);
    if(len_bytes == 0 || 1 + len_bytes + data_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_OCTET_STR;
    memcpy(out + 1, len_buf, len_bytes);
    if(data != NULL && data_len > 0) {
        memcpy(out + 1 + len_bytes, data, data_len);
    }
    return 1 + len_bytes + data_len;
}

/**
 * @brief Encode a constructed SET (tag 0x31) wrapping @p contents.
 * @param[out] out            Output buffer.
 * @param[in] out_max         Size of @p out.
 * @param[in] contents        Pre-encoded member TLV bytes (may be NULL if @p contents_len is 0).
 * @param[in] contents_len    Length of @p contents.
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_set(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if(out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if(len_bytes == 0 || 1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = 0x31; /* SET, constructed */
    memcpy(out + 1, len_buf, len_bytes);
    if(contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

/**
 * @brief Encode PrintableString (tag 0x13) from a NUL-terminated C string.
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] str       PrintableString characters (not NUL-terminated in DER).
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_printable_string(uint8_t *out, uint32_t out_max, const char *str)
{
    if(out == NULL || str == NULL) {
        return 0;
    }
    uint32_t slen = 0;
    while(slen < 0xFFFF && str[slen] != '\0') {
        slen++;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if(len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_PRINTABLESTRING;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, str, slen);
    return 1 + len_bytes + slen;
}

/**
 * @brief Encode IA5String (tag 0x16) from a NUL-terminated C string.
 * @param[out] out      Output buffer.
 * @param[in] out_max   Size of @p out.
 * @param[in] str       IA5 characters (not NUL-terminated in DER).
 * @return Total bytes written, or 0 on error.
 */
uint32_t noxtls_asn1_put_ia5_string(uint8_t *out, uint32_t out_max, const char *str)
{
    if(out == NULL || str == NULL) {
        return 0;
    }
    uint32_t slen = 0;
    while(slen < 0xFFFF && str[slen] != '\0') {
        slen++;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if(len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_IA5STRING;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, str, slen);
    return 1 + len_bytes + slen;
}
