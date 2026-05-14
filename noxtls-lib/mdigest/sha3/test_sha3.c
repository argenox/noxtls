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
* File:    test_sha3.c
* Summary: Simple test for SHA-3 implementation
*
*/

#include <stdio.h>
#include <string.h>
#include "noxtls_sha3.h"
#include "noxtls_hash.h"

int main(void)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t hash[64];
    const char *test = "abc";
    
    printf("Testing SHA3-256 with 'abc':\n");
    
    noxtls_sha3_256_init(&ctx);
    noxtls_sha3_update(&ctx, (uint8_t*)test, strlen(test));
    noxtls_sha3_finish(&ctx, hash);
    
    printf("Hash: ");
    noxtls_print_hash(hash, HASH_SHA3_256_OUT_LEN);
    printf("\n");
    
    printf("Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532\n");
    
    return 0;
}

