#ifndef NOXTLS_MLDSA_SIGN_H
#define NOXTLS_MLDSA_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "noxtls_mldsa_internal_common.h"
#include "noxtls_poly.h"
#include "noxtls_polyvec.h"

#define noxtls_mld_sign_keypair_internal \
    MLD_NAMESPACE_KL(keypair_internal) MLD_CONTEXT_PARAMETERS_3
#define noxtls_mld_sign_keypair MLD_NAMESPACE_KL(keypair) MLD_CONTEXT_PARAMETERS_2
#define noxtls_mld_sign_signature_internal \
    MLD_NAMESPACE_KL(signature_internal) MLD_CONTEXT_PARAMETERS_9
#define noxtls_mld_sign_signature MLD_NAMESPACE_KL(signature) MLD_CONTEXT_PARAMETERS_7
#define noxtls_mld_sign_signature_extmu \
    MLD_NAMESPACE_KL(signature_extmu) MLD_CONTEXT_PARAMETERS_4
#define noxtls_mld_sign MLD_NAMESPACE_KL(sign) MLD_CONTEXT_PARAMETERS_7
#define noxtls_mld_sign_verify_internal \
    MLD_NAMESPACE_KL(verify_internal) MLD_CONTEXT_PARAMETERS_8
#define noxtls_mld_sign_verify MLD_NAMESPACE_KL(verify) MLD_CONTEXT_PARAMETERS_7
#define noxtls_mld_sign_verify_extmu \
    MLD_NAMESPACE_KL(verify_extmu) MLD_CONTEXT_PARAMETERS_4
#define noxtls_mld_sign_open MLD_NAMESPACE_KL(open) MLD_CONTEXT_PARAMETERS_7
#define noxtls_mld_sign_signature_pre_hash_internal \
    MLD_NAMESPACE_KL(signature_pre_hash_internal) MLD_CONTEXT_PARAMETERS_9
#define noxtls_mld_sign_verify_pre_hash_internal \
    MLD_NAMESPACE_KL(verify_pre_hash_internal) MLD_CONTEXT_PARAMETERS_8
#define noxtls_mld_sign_signature_pre_hash_shake256 \
    MLD_NAMESPACE_KL(signature_pre_hash_shake256) MLD_CONTEXT_PARAMETERS_8
#define noxtls_mld_sign_verify_pre_hash_shake256 \
    MLD_NAMESPACE_KL(verify_pre_hash_shake256) MLD_CONTEXT_PARAMETERS_7
#define noxtls_mld_prepare_domain_separation_prefix \
    MLD_NAMESPACE_KL(prepare_domain_separation_prefix)
#define noxtls_mld_sign_pk_from_sk \
    MLD_NAMESPACE_KL(pk_from_sk) MLD_CONTEXT_PARAMETERS_2

#define MLD_PREHASH_NONE 0
#define MLD_PREHASH_SHA2_224 1
#define MLD_PREHASH_SHA2_256 2
#define MLD_PREHASH_SHA2_384 3
#define MLD_PREHASH_SHA2_512 4
#define MLD_PREHASH_SHA2_512_224 5
#define MLD_PREHASH_SHA2_512_256 6
#define MLD_PREHASH_SHA3_224 7
#define MLD_PREHASH_SHA3_256 8
#define MLD_PREHASH_SHA3_384 9
#define MLD_PREHASH_SHA3_512 10
#define MLD_PREHASH_SHAKE_128 11
#define MLD_PREHASH_SHAKE_256 12

#define MLD_DOMAIN_SEPARATION_MAX_BYTES (2u + 255u + 11u + 64u)

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_keypair_internal(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                              uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                              const uint8_t seed[MLDSA_SEEDBYTES],
                              MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_keypair(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                     uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                     MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_internal(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t rnd[MLDSA_RNDBYTES],
                                const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                                int externalmu,
                                MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                       MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_extmu(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                             const uint8_t mu[MLDSA_CRHBYTES],
                             const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
             const uint8_t *ctx, size_t ctxlen,
             const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_internal(const uint8_t *sig, size_t siglen,
                             const uint8_t *m, size_t mlen,
                             const uint8_t *pre, size_t prelen,
                             const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                             int externalmu,
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                    size_t mlen, const uint8_t *ctx, size_t ctxlen,
                    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_extmu(const uint8_t *sig, size_t siglen,
                          const uint8_t mu[MLDSA_CRHBYTES],
                          const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                          MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                  const uint8_t *ctx, size_t ctxlen,
                  const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                  MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_pre_hash_internal(
    uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen, const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_pre_hash_shake256(
    uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen, const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_pre_hash_shake256(
    const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
size_t noxtls_mld_prepare_domain_separation_prefix(
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg);

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_pk_from_sk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                        const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                        MLD_CONFIG_CONTEXT_PARAMETER_TYPE context);

#endif /* NOXTLS_MLDSA_SIGN_H */
