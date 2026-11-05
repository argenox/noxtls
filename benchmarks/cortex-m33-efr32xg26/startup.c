#include <stdint.h>

extern int benchmark_entry(void);
extern uint32_t __StackTop;

void Reset_Handler(void)
{
    (void)benchmark_entry();

    for(;;) {
    }
}

void Default_Handler(void)
{
    for(;;) {
    }
}

__attribute__((section(".isr_vector")))
void (* const g_isr_vector[])(void) = {
    (void (*)(void))(&__StackTop),
    Reset_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
    Default_Handler,
};
