    .section .text._start, "ax", @progbits
    .globl _start
_start:
    la sp, __StackTop
    call benchmark_entry
1:
    j 1b
