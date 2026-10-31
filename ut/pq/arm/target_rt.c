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
* File:    target_rt.c
* Summary: Architecture-independent part of the bare-metal runtime for the
*          QEMU semihosting test images (Cortex-M and RISC-V): newlib
*          syscalls over semihosting, stack painting and heap high-water
*          accounting, per-operation probes, the exit report and the C
*          start-up (data copy, bss clear, call main).
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include "target_rt.h"

/* Linker-script symbols. */
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _sstack;
extern uint32_t _estack;
extern uint8_t _heap_start;
extern uint8_t _heap_end;

int main(void);
void _exit(int status);

#define STACK_PAINT 0xA5A5A5A5UL

static uint8_t *g_heap_cur = &_heap_start;
static uint8_t *g_heap_max = &_heap_start;
static int g_clock_start = 0;

void target_rt_puts(const char *s)
{
    (void)target_rt_semihost_call(SEMIHOST_SYS_WRITE0, s);
}

/* ---- newlib syscalls ---------------------------------------------------- */

int _write(int fd, const char *buf, int len)
{
    char chunk[129];
    int done = 0;

    (void)fd;
    while(done < len) {
        int n = 0;
        while((n < 128) && (done < len)) {
            chunk[n] = buf[done];
            n += 1;
            done += 1;
        }
        chunk[n] = '\0';
        target_rt_puts(chunk);
    }
    return len;
}

void *_sbrk(ptrdiff_t incr)
{
    uint8_t *prev = g_heap_cur;
    if((incr > 0) && ((size_t)incr > (size_t)(&_heap_end - g_heap_cur))) {
        errno = ENOMEM;
        return (void *)-1;
    }
    g_heap_cur = &g_heap_cur[incr];
    if(g_heap_cur > g_heap_max) {
        g_heap_max = g_heap_cur;
    }
    return prev;
}

/* ---- heap accounting (-Wl,--wrap=malloc,...) ----------------------------
 * Every block carries an 8-byte header with its requested size so the live
 * byte count and its high-water mark are exact (allocator overhead excluded).
 * 8 bytes keep the returned pointer 8-byte aligned on 32- and 64-bit targets. */

void *__real_malloc(size_t n);
void __real_free(void *p);
void *__wrap_malloc(size_t n);
void __wrap_free(void *p);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *p, size_t n);

static size_t g_live_bytes = 0U;
static size_t g_live_peak = 0U;
static size_t g_run_peak = 0U;
static uint32_t g_stack_run_max = 0U;

void *__wrap_malloc(size_t n)
{
    uint8_t *p = (uint8_t *)__real_malloc(n + 8U);
    if(p == NULL) {
        return NULL;
    }
    *(size_t *)(void *)p = n;
    g_live_bytes += n;
    if(g_live_bytes > g_live_peak) {
        g_live_peak = g_live_bytes;
    }
    if(g_live_bytes > g_run_peak) {
        g_run_peak = g_live_bytes;
    }
    return &p[8];
}

void __wrap_free(void *ptr)
{
    uint8_t *p = (uint8_t *)ptr;
    if(p == NULL) {
        return;
    }
    p = &p[-8];
    g_live_bytes -= *(size_t *)(void *)p;
    __real_free(p);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    size_t n = nmemb * size;
    uint8_t *p = NULL;
    size_t i = 0U;
    if((size != 0U) && ((n / size) != nmemb)) {
        return NULL;
    }
    p = (uint8_t *)__wrap_malloc(n);
    if(p != NULL) {
        for(i = 0U; i < n; i += 1U) {
            p[i] = 0U;
        }
    }
    return p;
}

void *__wrap_realloc(void *ptr, size_t n)
{
    uint8_t *old = (uint8_t *)ptr;
    uint8_t *p = NULL;
    size_t old_n = 0U;
    size_t i = 0U;
    if(old == NULL) {
        return __wrap_malloc(n);
    }
    old_n = *(size_t *)(void *)&old[-8];
    p = (uint8_t *)__wrap_malloc(n);
    if(p == NULL) {
        return NULL;
    }
    for(i = 0U; (i < n) && (i < old_n); i += 1U) {
        p[i] = old[i];
    }
    __wrap_free(old);
    return p;
}

/* ---- per-operation probes (used by ut/pq/pq_test_common.c) --------------
 * The images are linked below 4 GB, so stack addresses fit in uint32_t on
 * 64-bit targets as well. */

uint32_t pq_arm_probe_begin(void);
void pq_arm_probe_end(uint32_t mark, uint32_t *stack_bytes, uint32_t *heap_bytes);

uint32_t pq_arm_probe_begin(void)
{
    uint32_t *sp_now = (uint32_t *)__builtin_frame_address(0);
    uint32_t *p = &_sstack;
    /* Paint everything below this frame (minus a margin) and restart the heap peak. */
    while(p < &sp_now[-32]) {
        *p = STACK_PAINT;
        p = &p[1];
    }
    g_live_peak = g_live_bytes;
    return (uint32_t)(uintptr_t)sp_now;
}

void pq_arm_probe_end(uint32_t mark, uint32_t *stack_bytes, uint32_t *heap_bytes)
{
    const uint32_t *p = &_sstack;
    while((p < &_estack) && (*p == STACK_PAINT)) {
        p = &p[1];
    }
    if(((uint32_t)((uintptr_t)&_estack - (uintptr_t)p)) > g_stack_run_max) {
        g_stack_run_max = (uint32_t)((uintptr_t)&_estack - (uintptr_t)p);
    }
    /* Depth below the probe caller's frame (the callee chain of the measured call). */
    *stack_bytes = (mark > (uint32_t)(uintptr_t)p) ? (mark - (uint32_t)(uintptr_t)p) : 0U;
    *heap_bytes = (uint32_t)(g_live_peak - g_live_bytes);
}

int _close(int fd) { (void)fd; return -1; }
int _open(const char *path, int flags, int mode) { (void)path; (void)flags; (void)mode; errno = ENOSYS; return -1; }
int _gettimeofday(void *tv, void *tz) { (void)tv; (void)tz; errno = ENOSYS; return -1; }
int _times(void *buf) { (void)buf; errno = ENOSYS; return -1; }
int _fstat(int fd, struct stat *st) { (void)fd; st->st_mode = S_IFCHR; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
int _lseek(int fd, int off, int whence) { (void)fd; (void)off; (void)whence; return 0; }
int _read(int fd, char *buf, int len) { (void)fd; (void)buf; (void)len; return 0; }
int _getpid(void) { return 1; }
int _kill(int pid, int sig) { (void)pid; (void)sig; errno = EINVAL; return -1; }

/* ---- reporting ---------------------------------------------------------- */

static uint32_t stack_high_water(void)
{
    const uint32_t *p = &_sstack;
    uint32_t used = 0U;
    while((p < &_estack) && (*p == STACK_PAINT)) {
        p = &p[1];
    }
    used = (uint32_t)((uintptr_t)&_estack - (uintptr_t)p);
    /* Probes repaint the stack; include the deepest point they observed. */
    return (used > g_stack_run_max) ? used : g_stack_run_max;
}

static void report_and_exit(int status) __attribute__((noreturn));

static void report_and_exit(int status)
{
    int ticks = target_rt_semihost_call(SEMIHOST_SYS_CLOCK, NULL) - g_clock_start;
    (void)fflush(stdout);
    printf("[arm] exit=%d stack_high_water=%lu/%lu bytes heap_live_peak=%lu bytes sbrk_high_water=%lu bytes"
           " host_time=%d0 ms\n",
           status,
           (unsigned long)stack_high_water(),
           (unsigned long)((uintptr_t)&_estack - (uintptr_t)&_sstack),
           (unsigned long)g_run_peak,
           (unsigned long)(g_heap_max - &_heap_start),
           ticks);
    (void)fflush(stdout);
    target_rt_semihost_exit(status);
}

void _exit(int status)
{
    report_and_exit(status);
}

/* ---- C start-up --------------------------------------------------------- */

void target_rt_start(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    uint32_t *sp_now = (uint32_t *)__builtin_frame_address(0);
    int rc = 0;

    while(dst < &_edata) {
        *dst = *src;
        dst = &dst[1];
        src = &src[1];
    }
    for(dst = &_sbss; dst < &_ebss; dst = &dst[1]) {
        *dst = 0U;
    }
    /* Paint the unused stack (leave 256 bytes below the current frame). */
    for(dst = &_sstack; dst < &sp_now[-64]; dst = &dst[1]) {
        *dst = STACK_PAINT;
    }
    g_clock_start = target_rt_semihost_call(SEMIHOST_SYS_CLOCK, NULL);
    (void)setvbuf(stdout, NULL, _IOLBF, 128);
    rc = main();
    report_and_exit(rc);
}
