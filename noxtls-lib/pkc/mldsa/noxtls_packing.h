#ifndef NOXTLS_MLDSA_PACKING_H
#define NOXTLS_MLDSA_PACKING_H

#include "noxtls_polyvec.h"

#define noxtls_mld_pack_pk MLD_NAMESPACE_KL(pack_pk)
MLD_INTERNAL_API
void noxtls_mld_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                 const uint8_t rho[MLDSA_SEEDBYTES],
                 const noxtls_mld_polyveck *t1);

#define noxtls_mld_unpack_pk MLD_NAMESPACE_KL(unpack_pk)
MLD_INTERNAL_API
void noxtls_mld_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
                   noxtls_mld_polyveck *t1,
                   const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES]);

#define noxtls_mld_pack_sk MLD_NAMESPACE_KL(pack_sk)
MLD_INTERNAL_API
void noxtls_mld_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                 const uint8_t rho[MLDSA_SEEDBYTES],
                 const uint8_t tr[MLDSA_TRBYTES],
                 const uint8_t key[MLDSA_SEEDBYTES],
                 const noxtls_mld_polyveck *t0,
                 const noxtls_mld_polyvecl *s1,
                 const noxtls_mld_polyveck *s2);

#define noxtls_mld_unpack_sk MLD_NAMESPACE_KL(unpack_sk)
MLD_INTERNAL_API
void noxtls_mld_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
                   uint8_t tr[MLDSA_TRBYTES],
                   uint8_t key[MLDSA_SEEDBYTES],
                   noxtls_mld_polyveck *t0,
                   noxtls_mld_polyvecl *s1,
                   noxtls_mld_polyveck *s2,
                   const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES]);

#define noxtls_mld_pack_sig_c_h MLD_NAMESPACE_KL(pack_sig_c_h)
MLD_INTERNAL_API
void noxtls_mld_pack_sig_c_h(uint8_t sig[MLDSA_CRYPTO_BYTES],
                      const uint8_t c[MLDSA_CTILDEBYTES],
                      const noxtls_mld_polyveck *h,
                      unsigned int number_of_hints);

#define noxtls_mld_pack_sig_z MLD_NAMESPACE_KL(pack_sig_z)
MLD_INTERNAL_API
void noxtls_mld_pack_sig_z(uint8_t sig[MLDSA_CRYPTO_BYTES],
                    const noxtls_mld_poly *zi,
                    unsigned int index);

#define noxtls_mld_unpack_sig MLD_NAMESPACE_KL(unpack_sig)
MLD_INTERNAL_API
MLD_MUST_CHECK_RETURN_VALUE
int noxtls_mld_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
                   noxtls_mld_polyvecl *z,
                   noxtls_mld_polyveck *h,
                   const uint8_t sig[MLDSA_CRYPTO_BYTES]);

#endif /* NOXTLS_MLDSA_PACKING_H */
