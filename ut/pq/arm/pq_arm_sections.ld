/* Common section layout for the NoxTLS QEMU semihosting test images.
 * The including script defines the FLASH and RAM memory regions and
 * PQ_ARM_STACK_SIZE. */

ENTRY(Reset_Handler)

SECTIONS
{
    .isr_vector : ALIGN(128)
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.glue_7) *(.glue_7t)
        KEEP(*(.init)) KEEP(*(.fini))
        *(.rodata*)
        . = ALIGN(4);
    } > FLASH

    .ARM.extab : { *(.ARM.extab* .gnu.linkonce.armextab.*) } > FLASH
    .ARM.exidx : { __exidx_start = .; *(.ARM.exidx*) __exidx_end = .; } > FLASH

    .preinit_array : { PROVIDE_HIDDEN(__preinit_array_start = .); KEEP(*(.preinit_array*)) PROVIDE_HIDDEN(__preinit_array_end = .); } > FLASH
    .init_array : { PROVIDE_HIDDEN(__init_array_start = .); KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*)) PROVIDE_HIDDEN(__init_array_end = .); } > FLASH
    .fini_array : { PROVIDE_HIDDEN(__fini_array_start = .); KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*)) PROVIDE_HIDDEN(__fini_array_end = .); } > FLASH

    _sidata = LOADADDR(.data);
    .data : ALIGN(4)
    {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    .heap (NOLOAD) : ALIGN(8)
    {
        _heap_start = .;
        . = ORIGIN(RAM) + LENGTH(RAM) - PQ_ARM_STACK_SIZE;
        _heap_end = .;
    } > RAM

    .stack (NOLOAD) : ALIGN(8)
    {
        _sstack = .;
        . = . + PQ_ARM_STACK_SIZE;
        _estack = .;
    } > RAM

    /DISCARD/ : { *(.ARM.attributes) }
}
