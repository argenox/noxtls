/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
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

#define GET_TAG_CLASS(X)      ((((1 << 7) | (1 << 6)) & X) >> 6)
#define GET_TAG_PRIM_CONST(X) ((((1 << 5)) & X) >> 5)
#define GET_TAG_NUM(X)        (X & 0x1F)

#define GET_LENGTH(X)         (X & 0x7F)

#define ASN1_CLASS_TYPE_UNIVERSAL     0
#define ASN1_CLASS_TYPE_APPLICATION   1
#define ASN1_CLASS_TYPE_CONTEXT       2
#define ASN1_CLASS_TYPE_PRIVATE       3

#define ASN1_TAG_TYPE_PRIMITIVE                0
#define ASN1_TAG_TYPE_CONSTRUCTED              1

uint32_t noxtls_parse_tag(uint8_t ** data, uint8_t * end);
static void print_tag_type(uint8_t type);
static void parse_tag(uint8_t type, uint8_t ** data, uint32_t len);
void asn1_find_oid(char * oid);

/**
 * @brief Parse ASN.1 DER Data
 *
 * @param[in] data is a pointer to a pointer to the data to convert
 * @param[in] length is a pointer to the length
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
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

        //printf("left: %ld\n", end - ptr);
    }

    return 0;
}

/**
 * @brief Parse ASN.1 Tag
 *
 * @param[in] data is a pointer to a pointer to the data to convert
 * @param[in] length is a pointer to the length
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
uint32_t noxtls_parse_tag(uint8_t ** data, uint8_t * end)
{
    if(data == NULL || *data == NULL || end == NULL) {
        return 1;
    }
    if(*data >= end) {
        return 1;
    }
    uint8_t * ptr = *data;


    //printf("0x%02x\n", *ptr);

//    printf("0x%02x\n", GET_TAG_NUM(*ptr));

    uint8_t tag_num = GET_TAG_NUM(*ptr);

    print_tag_type(tag_num);

    ptr++;
    if(ptr >= end) {
        return 1;
    }
    //printf("0x%02x\n", *ptr);

    uint32_t data_length = 0;
    if(*ptr & 0x80)
    {
        /* Definite */
        uint8_t length = GET_LENGTH(*ptr++);
        int i;
        if(length == 0 || length > 4 || ptr + length > end) {
            return 1;
        }
        //printf("\tDefinite Length: %d\n", length);
        for(i = length - 1; i >= 0; i--)
        {
            uint8_t val = (*ptr++);
            printf("\tval[%d]: %x\n", i, val);
            data_length |= val << (i * 8);
        }

    }
    else
    {
        /* Short form */

        data_length = GET_LENGTH(*ptr++);

        //printf("\tshort form: %d 0x%x\n", data_length, data_length);
    }

    //printf("%p == %p ", ptr + data_length, end);
    if(ptr + data_length > end) {
        /* Length error */
        return 1;
    }
    //printf("ptr[0]: %x\n", ptr[0]);
    parse_tag(tag_num, &ptr, data_length);


    if(end - ptr > 0)
    {
        noxtls_parse_tag(&ptr, end);
    }



    //printf("\tLength: %d\n", data_length);
    //ptr += data_length;

    //printf("Now on: %x\n", *ptr);
    *data = ptr;
    return 0;
}




/**
 * @brief Decodes object identifier
 *
 * @param[in] data is a pointer to the data to convert
 * @param[in] length is the length of the PEM data
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
void asn1_decode_integer(uint8_t ** data, uint32_t len)
{
    if(len <= 4)
    {
        const uint8_t * ptr = *data;
        uint32_t val = 0;
        uint32_t i;
        for(i = 0; i < len; i++) {
            val |= ptr[i] << ((len - 1 - i) * 8);
        }

        printf("\tInteger: 0x%lx (%lu)\n", (unsigned long)val, (unsigned long)val);
    }
}

/**
 * @brief Decodes ASN.1 Bit String
 *
 * @param[in] data is a pointer to  a pointer of the data to convert
 * @param[in] len is the length of the data
 *
 * @return @see noxtls_return_t
 */
void asn1_decode_bitstring(uint8_t ** data, uint32_t len)
{
    (void)data;
    //uint32_t i;
    //int j;

    printf("bit len: %u\n", (unsigned int)len);
    //for(i = 0; i < len; i++)
    {
      //  for(j = 7; j >= 0; j++)
        {
            //printf("%d", ((*data[i] & (1 << j)) >> j));
        }
    }
}

/**
 * @brief Decodes object identifier
 *
 * @param[in] data is a pointer to the data to convert
 * @param[in] length is the length of the PEM data
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
void asn1_decode_obj_ident(uint8_t ** data, uint32_t len)
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

    printf("OID_STR: %s\n", oid_str);
    asn1_find_oid(oid_str);

    printf("\n");
}

/**
 * @brief Finds the OID description for an identifier
 *
 * @param[in] oid is the OID string
 *
 * @return @see noxtls_return_t
 */
void asn1_find_oid(char * oid)
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
        //printf("ID %d\n", id);

        while(oid_ptr != NULL)
        {
            //printf("Cur ID %d %s == %d \n", oid_ptr->id,oid_ptr->name, id);
            if(oid_ptr->id == 0 &&
                    oid_ptr->name == NULL &&
                    oid_ptr->items == NULL)
            {
                //printf("STOP\n");
                break;
            }
            else if(oid_ptr->id == id)
            {
                //printf("ID Match \n");
                if(oid_ptr->name != NULL) {
                    printf("%s ", oid_ptr->name);
                }

                if(oid_ptr->items != NULL) {
                    //printf("Setting to items\n");
                    oid_ptr = (oid_item_t *)oid_ptr->items;
                }
                break;
            }
            else
            {
                //printf("Increment oid\n");
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
 * @brief Decodes object identifier
 *
 * @param[in] data is a pointer to the data to convert
 * @param[in] length is the length of the PEM data
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
void asn1_decode_print_string(uint8_t ** data, uint32_t len)
{
    uint32_t i = 0;

    const uint8_t * ptr = *data;


    printf("\tString: ");
    for(i = 0; i < len; i++)
    {
        printf("%c", ptr[i]);
    }

    printf("\n");
}


static void parse_tag(uint8_t type, uint8_t ** data, uint32_t len)
{

    switch(type)
    {
    case ASN1_TAG_EOC:
        *data += len;
        break;
    case ASN1_TAG_BOOLEAN:
        printf("Bool Val: %d", *data[0]);
        *data += len;
        break;
    case ASN1_TAG_INTEGER:
        asn1_decode_integer(data, len);
        *data += len;
        break;
    case ASN1_TAG_BITSTRING:
        asn1_decode_bitstring(data, len);
        *data += len;
        break;
    case ASN1_TAG_OCTET_STR:
        *data += len;
        break;
    case ASN1_TAG_NULL:
        *data += len;
        break;
    case ASN1_TAG_OBJ_IDENT:
        asn1_decode_obj_ident(data, len);
        *data += len;
        break;
    case ASN1_TAG_OBJECT:
        *data += len;
        break;
    case ASN1_TAG_EXTERNAL:
        *data += len;
        break;
    case ASN1_TAG_REAL_FLOAT:
        *data += len;
        break;
    case ASN1_TAG_ENUMERATED:
        *data += len;
        break;
    case ASN1_TAG_EMBEDDED:
        *data += len;
        break;
    case ASN1_TAG_UTF8STRING:
        *data += len;
        break;
    case ASN1_TAG_RELATIVE_OID:
        *data += len;
        break;
    case ASN1_TAG_TIME:
        *data += len;
        break;
    case ASN1_TAG_IA5STRING:
        asn1_decode_print_string(data, len);
        *data += len;
        break;
    case ASN1_TAG_PRINTABLESTRING:
        asn1_decode_print_string(data, len);
        *data += len;
        break;
    case ASN1_TAG_BMPSTRING:
        *data += len;
        break;
    case ASN1_TAG_SEQUENCE:
        //*data += len;
        break;
    case ASN1_TAG_SET:

        break;
    default:
        *data += len;

    }

}

static void print_tag_type(uint8_t type)
{
    //printf("%x\n", type);
    switch(type)
    {
    case ASN1_TAG_EOC:
        printf("Type: ASN1_TAG_EOC\n");
        break;
    case ASN1_TAG_BOOLEAN:
        printf("Type: ASN1_TAG_BOOLEAN\n");
        break;
    case ASN1_TAG_INTEGER:
        printf("Type: ASN1_TAG_INTEGER\n");
        break;
    case ASN1_TAG_BITSTRING:
        printf("Type: ASN1_TAG_BITSTRING\n");
        break;
    case ASN1_TAG_OCTET_STR:
        printf("Type: ASN1_TAG_OCTET_STR\n");
        break;
    case ASN1_TAG_NULL:
        printf("Type: ASN1_TAG_NULL\n");
        break;
    case ASN1_TAG_OBJ_IDENT:
        printf("Type: ASN1_TAG_OBJ_IDENT\n");
        break;
    case ASN1_TAG_OBJECT:
        printf("Type: ASN1_TAG_OBJECT\n");
        break;
    case ASN1_TAG_EXTERNAL:
        printf("Type: ASN1_TAG_EXTERNAL\n");
        break;
    case ASN1_TAG_REAL_FLOAT:
        printf("Type: ASN1_TAG_REAL_FLOAT\n");
        break;
    case ASN1_TAG_ENUMERATED:
        printf("Type: ASN1_TAG_ENUMERATED\n");
        break;
    case ASN1_TAG_EMBEDDED:
        printf("Type: ASN1_TAG_EMBEDDED\n");
        break;
    case ASN1_TAG_UTF8STRING:
        printf("Type: ASN1_TAG_UTF8STRING\n");
        break;
    case ASN1_TAG_RELATIVE_OID:
        printf("Type: ASN1_TAG_RELATIVE_OID\n");
        break;
    case ASN1_TAG_TIME:
        printf("Type: ASN1_TAG_TIME\n");
        break;
    case ASN1_TAG_IA5STRING:
        printf("Type: ASN1_TAG_IA5STRING\n");
        break;
    case ASN1_TAG_PRINTABLESTRING:
        printf("Type: ASN1_TAG_PRINTABLESTRING\n");
        break;
    case ASN1_TAG_BMPSTRING:
        printf("Type: ASN1_TAG_BMPSTRING\n");
        break;
    case ASN1_TAG_SEQUENCE:
        printf("Type: ASN1_TAG_SEQUENCE\n");
        break;
    case ASN1_TAG_SET:
        printf("Type: ASN1_TAG_SET\n");
        break;
    default:
        printf("Type: Unknown (0x%02x)\n", type);

    }

}

/* ========== ASN.1 DER encode API ========== */

uint32_t noxtls_asn1_put_length(uint8_t *out, uint32_t len)
{
    if (out == NULL) {
        return 0;
    }
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xFFFF) {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        return 3;
    }
    if (len <= 0xFFFFFF) {
        out[0] = 0x83;
        out[1] = (uint8_t)(len >> 16);
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
        return 4;
    }
    return 0;
}

uint32_t noxtls_asn1_put_integer(uint8_t *out, uint32_t out_max, const uint8_t *value, uint32_t value_len)
{
    if (out == NULL || value == NULL || value_len == 0) {
        return 0;
    }

    /* Skip leading zero bytes (keep at least one byte if value is zero) */
    const uint8_t *start = value;
    while (value_len > 1 && *start == 0) {
        start++;
        value_len--;
    }

    /* For positive INTEGER, if high bit is set we must prepend 0x00 */
    int need_zero = (value_len > 0 && (*start & 0x80) != 0) ? 1 : 0;
    uint32_t payload_len = value_len + (uint32_t)need_zero;

    uint8_t len_buf[5];
    uint32_t lb = noxtls_asn1_put_length(len_buf, payload_len);
    if (lb == 0 || 1 + lb + payload_len > out_max) {
        return 0;
    }

    out[0] = ASN1_TAG_INTEGER;
    memcpy(out + 1, len_buf, lb);
    {
        uint32_t off = 1 + lb;
        if (need_zero) {
            out[off++] = 0x00;
        }
        memcpy(out + off, start, value_len);
        return off + value_len;
    }
}

uint32_t noxtls_asn1_put_sequence(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if (out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if (len_bytes == 0) {
        return 0;
    }
    if (1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = ASN1_DER_TAG_SEQUENCE;
    memcpy(out + 1, len_buf, len_bytes);
    if (contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

uint32_t noxtls_asn1_put_oid_raw(uint8_t *out, uint32_t out_max, const uint8_t *oid, uint32_t oid_len)
{
    if (out == NULL || oid == NULL || oid_len == 0) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, oid_len);
    if (len_bytes == 0 || 1 + len_bytes + oid_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_OBJ_IDENT;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, oid, oid_len);
    return 1 + len_bytes + oid_len;
}

uint32_t noxtls_asn1_put_bit_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if (out == NULL || (data == NULL && data_len != 0)) {
        return 0;
    }
    /* BIT STRING: 1 byte unused bits (0) + data */
    uint32_t payload_len = 1 + data_len;
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, payload_len);
    if (len_bytes == 0 || 1 + len_bytes + payload_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_BITSTRING;
    memcpy(out + 1, len_buf, len_bytes);
    out[1 + len_bytes] = 0x00; /* unused bits */
    if (data != NULL && data_len > 0) {
        memcpy(out + 1 + len_bytes + 1, data, data_len);
    }
    return 1 + len_bytes + payload_len;
}

uint32_t noxtls_asn1_put_utc_time(uint8_t *out, uint32_t out_max, const char *time_str)
{
    if (out == NULL || time_str == NULL) {
        return 0;
    }
    /* UTCTime is typically 13 bytes: YYMMDDHHMMSSZ */
    uint32_t slen = 0;
    while (slen < 32 && time_str[slen] != '\0') {
        slen++;
    }
    if (slen == 0 || slen > 32) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if (len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = 0x17; /* UTCTime */
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, time_str, slen);
    return 1 + len_bytes + slen;
}

uint32_t noxtls_asn1_put_explicit(uint8_t *out, uint32_t out_max, uint8_t tag_no, const uint8_t *contents, uint32_t contents_len)
{
    if (out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    if (tag_no > 31) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if (len_bytes == 0 || 1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = (uint8_t)(0x80 | 0x20 | tag_no); /* context-specific, constructed */
    memcpy(out + 1, len_buf, len_bytes);
    if (contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

uint32_t noxtls_asn1_put_octet_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len)
{
    if (out == NULL || (data == NULL && data_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, data_len);
    if (len_bytes == 0 || 1 + len_bytes + data_len > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_OCTET_STR;
    memcpy(out + 1, len_buf, len_bytes);
    if (data != NULL && data_len > 0) {
        memcpy(out + 1 + len_bytes, data, data_len);
    }
    return 1 + len_bytes + data_len;
}

uint32_t noxtls_asn1_put_set(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len)
{
    if (out == NULL || (contents == NULL && contents_len != 0)) {
        return 0;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, contents_len);
    if (len_bytes == 0 || 1 + len_bytes + contents_len > out_max) {
        return 0;
    }
    out[0] = 0x31; /* SET, constructed */
    memcpy(out + 1, len_buf, len_bytes);
    if (contents != NULL && contents_len > 0) {
        memcpy(out + 1 + len_bytes, contents, contents_len);
    }
    return 1 + len_bytes + contents_len;
}

uint32_t noxtls_asn1_put_printable_string(uint8_t *out, uint32_t out_max, const char *str)
{
    if (out == NULL || str == NULL) {
        return 0;
    }
    uint32_t slen = 0;
    while (slen < 0xFFFF && str[slen] != '\0') {
        slen++;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if (len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_PRINTABLESTRING;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, str, slen);
    return 1 + len_bytes + slen;
}

uint32_t noxtls_asn1_put_ia5_string(uint8_t *out, uint32_t out_max, const char *str)
{
    if (out == NULL || str == NULL) {
        return 0;
    }
    uint32_t slen = 0;
    while (slen < 0xFFFF && str[slen] != '\0') {
        slen++;
    }
    uint8_t len_buf[5];
    uint32_t len_bytes = noxtls_asn1_put_length(len_buf, slen);
    if (len_bytes == 0 || 1 + len_bytes + slen > out_max) {
        return 0;
    }
    out[0] = ASN1_TAG_IA5STRING;
    memcpy(out + 1, len_buf, len_bytes);
    memcpy(out + 1 + len_bytes, str, slen);
    return 1 + len_bytes + slen;
}
