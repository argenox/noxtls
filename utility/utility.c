/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    utility.c
* Summary: NoxTLS Utility functions
*****************************************************************************/

/** @addtogroup noxtls_utility */

#include <stdint.h>
#include <string.h>
#include "noxtls_config.h"
#include "utility.h"
#include "noxtls_common.h"
#include "noxtls_memory.h"

#if NOXTLS_HAVE_FILE_IO
#include <stdio.h>
#include <limits.h>
#include <errno.h>

static FILE *noxtls_fopen(const uint8_t *filename, const uint8_t *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if (fopen_s(&fp, (const char *)(const void *)filename, (const char *)(const void *)mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen((const char *)(const void *)filename, (const char *)(const void *)mode);
#endif
}

int noxtls_load_file(const uint8_t * filename, uint8_t ** buffer)
{
    int32_t sz = 0;
    long file_size = 0L;
    FILE * fp = NULL;

    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }

    fp = noxtls_fopen(filename, (const uint8_t *)"rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        (void)fclose(fp);
        return -1;
    }
    errno = 0;
    file_size = ftell(fp);
    if (errno != 0) {
        (void)fclose(fp);
        return -1;
    }
    if ((file_size <= 0L) || (file_size > (long)INT_MAX)) {
        (void)fclose(fp);
        return -1;
    }
    sz = (int32_t)(file_size - 1L);

    *buffer = (uint8_t *)noxtls_malloc((size_t)sz * sizeof(uint8_t));
    if (*buffer == NULL) {
        (void)fclose(fp);
        return 1;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        (void)fclose(fp);
        noxtls_free(*buffer);
        *buffer = NULL;
        return -1;
    }

    if (fread(*buffer, sizeof(uint8_t), (size_t)sz, fp) != (size_t)sz) {
        (void)fclose(fp);
        noxtls_free(*buffer);
        *buffer = NULL;
        return -1;
    }

    (void)fclose(fp);
    return (int)sz;
}

int noxtls_load_text_file(const uint8_t * filename, uint8_t ** buffer)
{
    int32_t sz = 0;
    long file_size = 0L;
    FILE * fp = NULL;

    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }

    fp = noxtls_fopen(filename, (const uint8_t *)"r");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        (void)fclose(fp);
        return -1;
    }
    errno = 0;
    file_size = ftell(fp);
    if (errno != 0) {
        (void)fclose(fp);
        return -1;
    }
    if ((file_size < 0L) || (file_size > (long)INT_MAX)) {
        (void)fclose(fp);
        return -1;
    }
    sz = (int32_t)file_size;

    *buffer = (uint8_t *)noxtls_malloc((size_t)sz * sizeof(uint8_t));
    if (*buffer == NULL) {
        (void)fclose(fp);
        return 1;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        (void)fclose(fp);
        noxtls_free(*buffer);
        *buffer = NULL;
        return -1;
    }

    if (fread(*buffer, sizeof(uint8_t), (size_t)sz, fp) != (size_t)sz) {
        (void)fclose(fp);
        noxtls_free(*buffer);
        *buffer = NULL;
        return -1;
    }

    (void)fclose(fp);
    return (int)sz;
}

int noxtls_write_text_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len)
{
    size_t sz = 0U;
    FILE * fp = NULL;

    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }

    fp = noxtls_fopen(filename, (const uint8_t *)"w");
    if (fp == NULL) {
        return -1;
    }

    sz = fwrite(buffer, sizeof(uint8_t), (size_t)len, fp);

    (void)fclose(fp);
    if (sz > (size_t)INT_MAX) {
        return -1;
    }
    return (int)sz;
}

int noxtls_write_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len)
{
    size_t sz = 0U;
    FILE * fp = NULL;

    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }

    fp = noxtls_fopen(filename, (const uint8_t *)"wb");
    if (fp == NULL) {
        return -1;
    }

    sz = fwrite(buffer, sizeof(uint8_t), (size_t)len, fp);

    (void)fclose(fp);
    if (sz > (size_t)INT_MAX) {
        return -1;
    }
    return (int)sz;
}

#else /* !NOXTLS_HAVE_FILE_IO */

int noxtls_load_file(const uint8_t * filename, uint8_t ** buffer)
{
    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }
    (void)filename;
    *buffer = NULL;
    return -1;
}

int noxtls_load_text_file(const uint8_t * filename, uint8_t ** buffer)
{
    if ((filename == NULL) || (buffer == NULL)) {
        return -1;
    }
    (void)filename;
    *buffer = NULL;
    return -1;
}

int noxtls_write_text_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len)
{
    (void)filename;
    (void)buffer;
    (void)len;
    return -1;
}

int noxtls_write_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len)
{
    (void)filename;
    (void)buffer;
    (void)len;
    return -1;
}

#endif /* NOXTLS_HAVE_FILE_IO */
