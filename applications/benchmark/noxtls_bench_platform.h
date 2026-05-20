/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_bench_platform.h
* Summary: Platform hooks for benchmark timing and output.
*
*/

#ifndef _NOXTLS_BENCH_PLATFORM_H_
#define _NOXTLS_BENCH_PLATFORM_H_

#include <stdint.h>

void noxtls_bench_platform_init(void);
uint64_t noxtls_bench_time_now_ns(void);
void noxtls_bench_log(const char *fmt, ...);

#endif /* _NOXTLS_BENCH_PLATFORM_H_ */
