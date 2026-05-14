#include "noxtls_mldsa_internal_common.h"

#if !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED) && defined(MLDSA_DEBUG)

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "noxtls_debug.h"

#define MLD_DEBUG_ERROR_HEADER "[ERROR:%s:%04d] "

void noxtls_mld_debug_check_assert(const char *file, int line, int val)
{
    if(val == 0) {
        fprintf(stderr, MLD_DEBUG_ERROR_HEADER "Assertion failed (value %d)\n",
                file, line, val);
        exit(1);
    }
}

void noxtls_mld_debug_check_bounds(const char *file, int line, const int32_t *ptr,
                            unsigned len, int64_t lower_bound_exclusive,
                            int64_t upper_bound_exclusive)
{
    unsigned i;
    int err = 0;

    for(i = 0u; i < len; ++i) {
        int32_t val = ptr[i];
        if(!(val > lower_bound_exclusive && val < upper_bound_exclusive)) {
            fprintf(stderr,
                    MLD_DEBUG_ERROR_HEADER
                    "Bounds assertion failed: index %u, value %d out of (%" PRId64 ", %" PRId64 ")\n",
                    file, line, i, (int)val, lower_bound_exclusive, upper_bound_exclusive);
            err = 1;
        }
    }

    if(err != 0) {
        exit(1);
    }
}

#else

MLD_EMPTY_CU(debug)

#endif
