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
* File:    riscv_rt.c
* Summary: RISC-V (RV32 / RV64, machine mode) start-up for the QEMU "virt"
*          semihosting test images: entry point, trap handler and the
*          RISC-V semihosting call. The rest of the runtime is target_rt.c.
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "target_rt.h"

void _start(void);
void pq_rv_trap_handler(void);

/* RISC-V semihosting: a0 = operation, a1 = argument, result in a0. The
 * three-instruction sequence must be uncompressed and must not cross a page,
 * hence norvc and the 16-byte alignment. */
int target_rt_semihost_call(int op, const void *arg)
{
    register uintptr_t a0 __asm__("a0") = (uintptr_t)(intptr_t)op;
    register uintptr_t a1 __asm__("a1") = (uintptr_t)arg;
    __asm__ volatile(".option push\n"
                     ".option norvc\n"
                     ".balign 16\n"
                     "slli x0, x0, 0x1f\n"
                     "ebreak\n"
                     "srai x0, x0, 7\n"
                     ".option pop\n"
                     : "+r"(a0)
                     : "r"(a1)
                     : "memory");
    return (int)(intptr_t)a0;
}

void target_rt_semihost_exit(int status)
{
#if (__riscv_xlen == 64)
    /* 64-bit semihosting: SYS_EXIT takes a block {reason, exit code}. */
    static uintptr_t block[2];
    block[0] = ADP_STOPPED_APPLICATION_EXIT;
    block[1] = (uintptr_t)(intptr_t)status;
    (void)target_rt_semihost_call(SEMIHOST_SYS_EXIT, block);
#else
    (void)target_rt_semihost_call(SEMIHOST_SYS_EXIT,
                                  (const void *)((status == 0) ? ADP_STOPPED_APPLICATION_EXIT
                                                               : ADP_STOPPED_RUNTIME_ERROR));
#endif
    for(;;) {
    }
}

static void put_hex(char *out, uintptr_t value)
{
    static const char digits[] = "0123456789abcdef";
    size_t i = 0U;
    size_t n = sizeof(uintptr_t) * 2U;
    for(i = 0U; i < n; i += 1U) {
        out[i] = digits[(value >> (4U * (n - 1U - i))) & 0xFU];
    }
    out[n] = '\0';
}

/* Any trap is unexpected in these images (no interrupts are enabled):
 * report mcause / mepc / mtval and stop with a failure status. */
__attribute__((aligned(4))) void pq_rv_trap_handler(void)
{
    char hex[2U * sizeof(uintptr_t) + 1U];
    uintptr_t mcause = 0U;
    uintptr_t mepc = 0U;
    uintptr_t mtval = 0U;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc" : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval" : "=r"(mtval));
    target_rt_puts("[arm] FAULT: unexpected RISC-V trap mcause=0x");
    put_hex(hex, mcause);
    target_rt_puts(hex);
    target_rt_puts(" mepc=0x");
    put_hex(hex, mepc);
    target_rt_puts(hex);
    target_rt_puts(" mtval=0x");
    put_hex(hex, mtval);
    target_rt_puts(hex);
    target_rt_puts("\n");
    target_rt_semihost_exit(3);
}

/* Entry at the start of RAM (QEMU virt with -bios none jumps there). Hart 0
 * runs the test; other harts, if any, park. */
__attribute__((naked, section(".text.start"))) void _start(void)
{
    __asm__ volatile(".option push\n"
                     ".option norelax\n"
                     "la gp, __global_pointer$\n"
                     ".option pop\n"
                     "csrr t0, mhartid\n"
                     "bnez t0, 1f\n"
                     "la sp, _estack\n"
                     "la t0, pq_rv_trap_handler\n"
                     "csrw mtvec, t0\n"
                     "j target_rt_start\n"
                     "1: wfi\n"
                     "j 1b\n");
}
