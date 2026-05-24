/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_bench_platform.c
* Summary: Platform abstraction for benchmark timer and logging output.
*
*/

#include "noxtls_bench_platform.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(NOXTLS_BENCH_USE_SEGGER_RTT)
#include "SEGGER_RTT.h"
#endif

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#include <time.h>
#endif

void noxtls_bench_platform_init(void)
{
#if defined(DWT) && defined(CoreDebug) && defined(CoreDebug_DEMCR_TRCENA_Msk) && defined(DWT_CTRL_CYCCNTENA_Msk)
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
#endif
}

uint64_t noxtls_bench_time_now_ns(void)
{
#if defined(DWT) && defined(SystemCoreClock) && defined(DWT_CTRL_CYCCNTENA_Msk)
    uint32_t cyc = DWT->CYCCNT;
    if (SystemCoreClock == 0u) {
        return 0u;
    }
    return ((uint64_t)cyc * 1000000000ull) / (uint64_t)SystemCoreClock;
#elif defined(_WIN32)
    LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (QueryPerformanceFrequency(&freq) == 0 || QueryPerformanceCounter(&now) == 0) {
        return 0u;
    }
    return ((uint64_t)now.QuadPart * 1000000000ull) / (uint64_t)freq.QuadPart;
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#elif defined(NOXTLS_BENCH_USE_HAL_TICK)
    extern uint32_t HAL_GetTick(void);
    return (uint64_t)HAL_GetTick() * 1000000ull;
#else
    return 0u;
#endif
}

void noxtls_bench_log(const char *fmt, ...)
{
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

#if defined(NOXTLS_BENCH_USE_SEGGER_RTT)
    SEGGER_RTT_WriteString(0, line);
#else
    (void)printf("%s", line);
#endif
}
