/**
 * @file noxtls_time.h
 * @brief Platform time accessors without exposing <time.h> to callers.
 */
#ifndef NOXTLS_TIME_H_
#define NOXTLS_TIME_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Signed Unix seconds since 1970-01-01 UTC (same role as POSIX time_t). */
typedef int64_t noxtls_unix_time_t;

/**
 * @brief Current calendar time in Unix seconds.
 * @return Seconds since epoch, or (noxtls_unix_time_t)-1 on failure / no time support.
 */
noxtls_unix_time_t noxtls_time_unix_seconds(void);

/**
 * @brief Monotonic-ish microsecond tick for profiling (best-effort).
 * @return Microseconds from an arbitrary epoch; 0 if unavailable.
 */
uint64_t noxtls_time_mono_us(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TIME_H_ */
