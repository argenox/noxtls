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
* File:    utility.c
* Summary: NoxTLS Utility functions
*
*
*****************************************************************************/

/** @addtogroup noxtls_utility */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "noxtls_common.h"

static FILE *noxtls_fopen(const char *filename, const char *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}

/**
 * @brief Loads a binary file into a buffer
 *
 * @param[in] filename is the name of the file to create
 * @param[out] buffer is a pointer to the data to write
 * @param[in] len is the length of the output buffer
 * 
 * @note this function allocates memory to hold the data, which must be
 *       released by the called after it is complete
 *
 * 
 * @return on success, number of bytes written, otherwise negative error
 */
int noxtls_load_file(const char * filename, uint8_t ** buffer)
{
    int sz = 0;
    long file_size = 0L;

    FILE * fp = NULL;

    fp = noxtls_fopen(filename, "rb");
    if(fp == NULL) {
        printf("Cannot open file\n");
        return -1;
    }

    if(fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    file_size = ftell(fp);
    if(file_size <= 0L || file_size > (long)INT_MAX) {
        fclose(fp);
        return -1;
    }
    sz = (int)(file_size - 1L);

    printf("FIle Size: %d\n", sz);

    *buffer = (uint8_t *) malloc(sz * sizeof(uint8_t));
    if(*buffer == NULL) {
        printf("Cannot allocate\n");
        fclose(fp);
        return 1;
    }

    if(fseek(fp, 0L, SEEK_SET) != 0) {
        fclose(fp);
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    if (fread(*buffer, sizeof(uint8_t), (size_t)sz, fp) != (size_t)sz) {
        fclose(fp);
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    fclose(fp); /* fp is non-NULL here (we returned above on open failure) */
    return sz;
}

/**
 * @brief Loads a binary file into a buffer
 *
 * @param[in] filename is the name of the file to create
 * @param[out] buffer is a pointer to the data to write
 * @param[in] len is the length of the output buffer
 * 
 * @note this function allocates memory to hold the data, which must be
 *       released by the called after it is complete
 *
 * 
 * @return on success, number of bytes written, otherwise negative error
 */
int noxtls_load_text_file(const char * filename, uint8_t ** buffer)
{
    int sz = 0;
    long file_size = 0L;

    FILE * fp = NULL;

    fp = noxtls_fopen(filename, "r");
    if(fp == NULL) {
        printf("Cannot open file\n");
        return -1;
    }

    if(fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    file_size = ftell(fp);
    if(file_size < 0L || file_size > (long)INT_MAX) {
        fclose(fp);
        return -1;
    }
    sz = (int)file_size;

    printf("FIle Size: %d\n", sz);

    *buffer = (uint8_t *) malloc(sz * sizeof(uint8_t));
    if(*buffer == NULL) {
        fclose(fp);
        return 1;
    }

    if(fseek(fp, 0L, SEEK_SET) != 0) {
        fclose(fp);
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    if (fread(*buffer, sizeof(uint8_t), (size_t)sz, fp) != (size_t)sz) {
        fclose(fp);
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    fclose(fp); /* fp is non-NULL here (we returned above on open failure) */
    return sz;
}


/**
 * @brief Creates a new file and writes string data
 *
 * @param[in] filename is the name of the file to create
 * @param[out] buffer is a pointer to the data to write
 * @param[in] len is the length of the output buffer
 *
 * 
 * @return on success, number of bytes written, otherwise negative error
 */
int noxtls_write_text_file(const char * filename, const uint8_t * buffer, uint32_t len)
{
    size_t sz = 0;

    FILE * fp = NULL;

    fp = noxtls_fopen(filename, "w");
    if(fp == NULL) {
        printf("Cannot open file\n");
        return -1;
    }

    sz = fwrite(buffer, sizeof(uint8_t), len, fp);   

    fclose(fp); /* fp is non-NULL here (we returned above on open failure) */
    if(sz > INT_MAX) {
        return -1;
    }
    return (int)sz;
}


/**
 * @brief Creates a new file and writes binary data
 *
 * @param[in] filename is the name of the file to create
 * @param[out] buffer is a pointer to the data to write
 * @param[in] len is the length of the output buffer
 *
 * 
 * @return on success, number of bytes written, otherwise negative error
 */
int noxtls_write_file(const char * filename, const uint8_t * buffer, uint32_t len)
{
    size_t sz = 0;

    FILE * fp = NULL;

    fp = noxtls_fopen(filename, "wb");
    if(fp == NULL) {
        printf("Cannot open file\n");
        return -1;
    }

    sz = fwrite(buffer, sizeof(uint8_t), len, fp);

    fclose(fp); /* fp is non-NULL here (we returned above on open failure) */
    if(sz > INT_MAX) {
        return -1;
    }
    return (int)sz;
}