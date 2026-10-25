/* QEMU mps2-an505 (Cortex-M33, boots Secure): 4 MB SSRAM1 secure alias at
 * 0x10000000 (code, initial VTOR), 2 MB SSRAM2 secure alias at 0x38000000. */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x38000000, LENGTH = 2M
}
PQ_ARM_STACK_SIZE = DEFINED(PQ_ARM_STACK_SIZE) ? PQ_ARM_STACK_SIZE : 0x10000;
INCLUDE pq_arm_sections.ld
