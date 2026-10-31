/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    target_rt.h
* Summary: Interface between the shared bare-metal test runtime
*          (target_rt.c) and the per-architecture start-up files
*          (arm_rt.c for Cortex-M, riscv_rt.c for RISC-V).
*
*****************************************************************************/

#ifndef NOXTLS_TARGET_RT_H
#define NOXTLS_TARGET_RT_H

#include <stdint.h>

#define SEMIHOST_SYS_WRITE0 0x04
#define SEMIHOST_SYS_CLOCK 0x10
#define SEMIHOST_SYS_EXIT 0x18
#define ADP_STOPPED_APPLICATION_EXIT 0x20026UL
#define ADP_STOPPED_RUNTIME_ERROR 0x20023UL

/* Provided by the architecture file. */
int target_rt_semihost_call(int op, const void *arg);
void target_rt_semihost_exit(int status) __attribute__((noreturn));

/* Provided by target_rt.c. */
void target_rt_start(void) __attribute__((noreturn));
void target_rt_puts(const char *s);

#endif /* NOXTLS_TARGET_RT_H */
