#ifndef NOXTLS_MLDSA_CONFIG_H
#define NOXTLS_MLDSA_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define MLD_CONFIG_NO_ASM
#define MLD_CONFIG_SERIAL_FIPS202_ONLY
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#define MLD_CONFIG_FIPS202_CUSTOM_HEADER "noxtls_fips202_noxtls_glue.h"

#if !defined(MLD_CONFIG_NAMESPACE_PREFIX)
#define MLD_CONFIG_NAMESPACE_PREFIX noxtls_mldsa
#endif

int noxtls_mldsa_randombytes_internal(uint8_t *out, size_t outlen);

static inline int noxtls_mld_randombytes(uint8_t *out, size_t outlen)
{
    return noxtls_mldsa_randombytes_internal(out, outlen);
}

#endif


