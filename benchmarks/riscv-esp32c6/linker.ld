ENTRY(_start)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x42000000, LENGTH = 4096K
    RAM   (rwx) : ORIGIN = 0x40800000, LENGTH = 320K
}

SECTIONS
{
    .text :
    {
        KEEP(*(.text._start))
        KEEP(*(.text.startup*))
        *(.text*)
    } > FLASH

    .rodata :
    {
        *(.rodata*)
    } > FLASH

    .data :
    {
        __data_start__ = .;
        *(.data*)
        __data_end__ = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        __bss_start = .;
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        __bss_end__ = .;
        _end = .;
        end = .;
        __end__ = .;
    } > RAM

    PROVIDE(__global_pointer$ = __data_start__ + 0x800);
    __StackTop = ORIGIN(RAM) + LENGTH(RAM);
}
