/* QEMU mps2-an386 (Cortex-M4): 4 MB ZBT SSRAM1 at 0x00000000 (code, vector
 * table), 4 MB SSRAM2/3 at 0x20000000 (data).  The same layout is valid for
 * mps2-an385 (Cortex-M3) and mps2-an500 (Cortex-M7). */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}
PQ_ARM_STACK_SIZE = DEFINED(PQ_ARM_STACK_SIZE) ? PQ_ARM_STACK_SIZE : 0x10000;
INCLUDE pq_arm_sections.ld
