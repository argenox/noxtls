#ifndef NOXTLS_MLDSA_DEBUG_H
#define NOXTLS_MLDSA_DEBUG_H

#include <stdint.h>

#include "noxtls_mldsa_internal_common.h"

#if defined(MLDSA_DEBUG)

#define noxtls_mld_debug_check_assert MLD_NAMESPACE(mldsa_debug_assert)
void noxtls_mld_debug_check_assert(const char *file, int line, int val);

#define noxtls_mld_debug_check_bounds MLD_NAMESPACE(mldsa_debug_check_bounds)
void noxtls_mld_debug_check_bounds(const char *file, int line, const int32_t *ptr,
                            unsigned len, int64_t lower_bound_exclusive,
                            int64_t upper_bound_exclusive);

#define noxtls_mld_assert(val) noxtls_mld_debug_check_assert(__FILE__, __LINE__, (val))
#define noxtls_mld_assert_bound(ptr, len, value_lb, value_ub)                    \
    noxtls_mld_debug_check_bounds(__FILE__, __LINE__, (const int32_t *)(ptr),    \
                           (len), ((int64_t)(value_lb)) - 1, (value_ub))
#define noxtls_mld_assert_abs_bound(ptr, len, value_abs_bd)                      \
    noxtls_mld_assert_bound((ptr), (len), (-((int64_t)(value_abs_bd)) + 1),      \
                     (value_abs_bd))
#define noxtls_mld_assert_bound_2d(ptr, len0, len1, value_lb, value_ub)          \
    noxtls_mld_assert_bound((ptr), ((len0) * (len1)), (value_lb), (value_ub))
#define noxtls_mld_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd)            \
    noxtls_mld_assert_abs_bound((ptr), ((len0) * (len1)), (value_abs_bd))

#elif defined(CBMC)

#include "noxtls_cbmc.h"

#define noxtls_mld_assert(val) cassert(val)
#define noxtls_mld_assert_bound(ptr, len, value_lb, value_ub) \
    cassert(array_bound(((int32_t *)(ptr)), 0, (len), (value_lb), (value_ub)))
#define noxtls_mld_assert_abs_bound(ptr, len, value_abs_bd) \
    cassert(array_abs_bound(((int32_t *)(ptr)), 0, (len), (value_abs_bd)))
#define noxtls_mld_assert_bound_2d(ptr, M, N, value_lb, value_ub)                \
    cassert(forall(kN, 0, (M),                                             \
                   array_bound(&((int32_t (*)[(N)])(ptr))[kN][0], 0, (N), \
                               (value_lb), (value_ub))))
#define noxtls_mld_assert_abs_bound_2d(ptr, M, N, value_abs_bd)                  \
    cassert(forall(kN, 0, (M),                                             \
                   array_abs_bound(&((int32_t (*)[(N)])(ptr))[kN][0], 0,  \
                                   (N), (value_abs_bd))))

#else

#define noxtls_mld_assert(val) do { } while(0)
#define noxtls_mld_assert_bound(ptr, len, value_lb, value_ub) do { } while(0)
#define noxtls_mld_assert_abs_bound(ptr, len, value_abs_bd) do { } while(0)
#define noxtls_mld_assert_bound_2d(ptr, len0, len1, value_lb, value_ub) do { } while(0)
#define noxtls_mld_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd) do { } while(0)

#endif

#endif /* NOXTLS_MLDSA_DEBUG_H */
