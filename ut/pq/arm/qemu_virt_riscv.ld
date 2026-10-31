/* QEMU RISC-V "virt" machine (RV32 or RV64), started with -bios none: RAM at
 * 0x80000000, execution starts there in machine mode. The first 4 MB hold
 * the image ("FLASH"), the next 4 MB data, heap and stack, the same sizes as
 * the Cortex-M images. Requires -mcmodel=medany on RV64. */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x80000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x80400000, LENGTH = 4M
}
PQ_ARM_STACK_SIZE = DEFINED(PQ_ARM_STACK_SIZE) ? PQ_ARM_STACK_SIZE : 0x10000;

ENTRY(_start)

SECTIONS
{
    .text :
    {
        KEEP(*(.text.start))
        *(.text*)
        KEEP(*(.init)) KEEP(*(.fini))
        . = ALIGN(8);
    } > FLASH

    .rodata : ALIGN(8)
    {
        *(.rodata*)
        *(.srodata*)
        . = ALIGN(8);
    } > FLASH

    .preinit_array : { PROVIDE_HIDDEN(__preinit_array_start = .); KEEP(*(.preinit_array*)) PROVIDE_HIDDEN(__preinit_array_end = .); } > FLASH
    .init_array : { PROVIDE_HIDDEN(__init_array_start = .); KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*)) PROVIDE_HIDDEN(__init_array_end = .); } > FLASH
    .fini_array : { PROVIDE_HIDDEN(__fini_array_start = .); KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*)) PROVIDE_HIDDEN(__fini_array_end = .); } > FLASH

    _sidata = LOADADDR(.data);
    .data : ALIGN(8)
    {
        _sdata = .;
        *(.data*)
        /* gp points 2 KB into the small-data area so +-2 KB offsets reach it. */
        __global_pointer$ = . + 0x800;
        *(.sdata*)
        . = ALIGN(8);
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) : ALIGN(8)
    {
        _sbss = .;
        *(.sbss*)
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _ebss = .;
    } > RAM

    .heap (NOLOAD) : ALIGN(8)
    {
        _heap_start = .;
        . = ORIGIN(RAM) + LENGTH(RAM) - PQ_ARM_STACK_SIZE;
        _heap_end = .;
    } > RAM

    .stack (NOLOAD) : ALIGN(16)
    {
        _sstack = .;
        . = . + PQ_ARM_STACK_SIZE;
        _estack = .;
    } > RAM

    /DISCARD/ : { *(.riscv.attributes) *(.comment) }
}
