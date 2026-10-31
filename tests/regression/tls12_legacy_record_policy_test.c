/* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
#include "tls/noxtls_tls12.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
    return 77;
#else
    const uint16_t suites[] = {TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA,
                               TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA};
    tls12_context_t ctx;
    uint8_t input[32] = {0};
    uint8_t output[64];
    size_t i;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base.base.version = TLS_VERSION_1_2;
    ctx.base.base.role = TLS_ROLE_CLIENT;
    for(i = 0U; i < sizeof(suites) / sizeof(suites[0]); ++i) {
        uint32_t length = sizeof(output);
        uint32_t offset = 0U;
        ctx.cipher_suite = suites[i];
        memset(output, 0xA5, sizeof(output));
        if(noxtls_tls12_encrypt_record(&ctx, TLS_RECORD_APPLICATION_DATA,
                input, 1U, output, &length) != NOXTLS_RETURN_NOT_SUPPORTED ||
           noxtls_tls12_open_record(&ctx, TLS_RECORD_APPLICATION_DATA,
                input, sizeof(input), sizeof(input), &offset, &length) != NOXTLS_RETURN_NOT_SUPPORTED ||
           ctx.client_seq_num != 0U || ctx.server_seq_num != 0U || output[0] != 0xA5U) {
            fprintf(stderr, "3DES record API bypassed the disabled legacy policy\n");
            return 1;
        }
    }
    return 0;
#endif
}
