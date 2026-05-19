/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

#ifndef _NOXTLS_CT_H_
#define _NOXTLS_CT_H_

#include <stddef.h>
#include <stdint.h>
#include "noxtls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constant-time compare for secrets.
 * Returns 0 when equal, non-zero when different.
 */
int noxtls_ct_memcmp(const void *a, const void *b, size_t len);

/* Convenience wrapper for equality checks. */
int noxtls_ct_equal(const void *a, const void *b, size_t len);

/*
 * Profile-aware secret comparison:
 * - performance profile: may use regular memcmp
 * - balanced/constant_time_strict: uses constant-time compare
 */
int noxtls_secret_memcmp(const void *a, const void *b, size_t len);

/*
 * Zero memory in a way that avoids compiler elision.
 */
void noxtls_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CT_H_ */
