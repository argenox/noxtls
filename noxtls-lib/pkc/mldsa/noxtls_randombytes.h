#ifndef NOXTLS_MLDSA_RANDOMBYTES_H
#define NOXTLS_MLDSA_RANDOMBYTES_H

#include <stddef.h>

#include "noxtls_mldsa_internal_common.h"

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API) && !defined(MLD_CONFIG_CUSTOM_RANDOMBYTES)
MLD_MUST_CHECK_RETURN_VALUE
int noxtls_randombytes(uint8_t *out, size_t outlen);

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int noxtls_mld_randombytes(uint8_t *out, size_t outlen)
{
    return noxtls_randombytes(out, outlen);
}
#endif

#endif /* NOXTLS_MLDSA_RANDOMBYTES_H */
