#ifndef NOXTLS_PQ_PARAM_TYPEDEFS_H_
#define NOXTLS_PQ_PARAM_TYPEDEFS_H_

#include <stdint.h>

#if !NOXTLS_FEATURE_ML_DSA
#ifndef NOXTLS_MLDSA_PARAM_T_DEFINED
#define NOXTLS_MLDSA_PARAM_T_DEFINED
typedef uint32_t noxtls_mldsa_param_t;
#endif
#ifndef NOXTLS_MLDSA_NONE
#define NOXTLS_MLDSA_NONE ((noxtls_mldsa_param_t)0u)
#endif
#ifndef NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN
#define NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN 1u
#endif
#ifndef NOXTLS_MLDSA_MAX_SECRET_KEY_LEN
#define NOXTLS_MLDSA_MAX_SECRET_KEY_LEN 1u
#endif
#endif

#if !NOXTLS_FEATURE_SLH_DSA
#ifndef NOXTLS_SLHDSA_PARAM_T_DEFINED
#define NOXTLS_SLHDSA_PARAM_T_DEFINED
typedef uint32_t noxtls_slhdsa_param_t;
#endif
#ifndef NOXTLS_SLHDSA_NONE
#define NOXTLS_SLHDSA_NONE ((noxtls_slhdsa_param_t)0u)
#endif
#ifndef NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN
#define NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN 1u
#endif
#ifndef NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN
#define NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN 1u
#endif
#endif

#if !NOXTLS_FEATURE_FALCON
#ifndef NOXTLS_FALCON_PARAM_T_DEFINED
#define NOXTLS_FALCON_PARAM_T_DEFINED
typedef uint32_t noxtls_falcon_param_t;
#endif
#ifndef NOXTLS_FALCON_NONE
#define NOXTLS_FALCON_NONE ((noxtls_falcon_param_t)0u)
#endif
#ifndef NOXTLS_FALCON_MAX_PUBLIC_KEY_LEN
#define NOXTLS_FALCON_MAX_PUBLIC_KEY_LEN 1u
#endif
#ifndef NOXTLS_FALCON_MAX_SECRET_KEY_LEN
#define NOXTLS_FALCON_MAX_SECRET_KEY_LEN 1u
#endif
#endif

#endif /* NOXTLS_PQ_PARAM_TYPEDEFS_H_ */
