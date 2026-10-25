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
* File:    arm_rt.c
* Summary: Cortex-M start-up for the QEMU semihosting test images
*          (mps2-an385 / an386 / an500 / an505): vector table, reset handler,
*          fault handler and the ARM semihosting call. The rest of the
*          runtime is target_rt.c.
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "target_rt.h"

extern uint32_t _estack;

void Reset_Handler(void);
void pq_arm_fault_handler(void);

int target_rt_semihost_call(int op, const void *arg)
{
    register int r0 __asm__("r0") = op;
    register const void *r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt 0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void target_rt_semihost_exit(int status)
{
    (void)target_rt_semihost_call(SEMIHOST_SYS_EXIT,
                                  (const void *)((status == 0) ? ADP_STOPPED_APPLICATION_EXIT
                                                               : ADP_STOPPED_RUNTIME_ERROR));
    for(;;) {
    }
}

void pq_arm_fault_handler(void)
{
    target_rt_puts("[arm] FAULT: unexpected exception (HardFault/MemManage/BusFault/UsageFault)\n");
    target_rt_semihost_exit(3);
}

void Reset_Handler(void)
{
    target_rt_start();
}

typedef void (*pq_arm_vector_t)(void);

__attribute__((section(".isr_vector"), used))
const pq_arm_vector_t g_pq_arm_vectors[16] = {
    (pq_arm_vector_t)(uintptr_t)&_estack,
    Reset_Handler,
    pq_arm_fault_handler, /* NMI */
    pq_arm_fault_handler, /* HardFault */
    pq_arm_fault_handler, /* MemManage */
    pq_arm_fault_handler, /* BusFault */
    pq_arm_fault_handler, /* UsageFault */
    pq_arm_fault_handler, /* SecureFault (v8-M) */
    NULL, NULL, NULL,
    pq_arm_fault_handler, /* SVC */
    pq_arm_fault_handler, /* DebugMon */
    NULL,
    pq_arm_fault_handler, /* PendSV */
    pq_arm_fault_handler  /* SysTick */
};
