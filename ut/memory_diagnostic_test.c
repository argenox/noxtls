#include <stdint.h>
#include <stdio.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"

static int expect(int condition, const char *message)
{
    if(!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

int main(void)
{
    noxtls_mem_failure_t failure;
    uint32_t allocation_line;
    int ok = 1;

    noxtls_mem_clear_last_failure();
    ok &= expect(noxtls_mem_get_last_failure(&failure) == NOXTLS_RETURN_FAILED,
                 "clear removes previous allocator failure");
    allocation_line = (uint32_t)__LINE__ + 1U;
    ok &= expect(noxtls_calloc(SIZE_MAX, 2U) == NULL,
                 "overflowing calloc fails");
    ok &= expect(noxtls_mem_get_last_failure(&failure) == NOXTLS_RETURN_SUCCESS,
                 "overflowing calloc records diagnostics");
    ok &= expect(failure.operation == NOXTLS_MEM_OPERATION_CALLOC,
                 "diagnostic records calloc operation");
    ok &= expect(failure.reason == NOXTLS_MEM_FAILURE_SIZE_OVERFLOW,
                 "diagnostic records overflow reason");
    ok &= expect(failure.element_count == SIZE_MAX && failure.element_size == 2U,
                 "diagnostic records original calloc dimensions");
    ok &= expect(failure.file != NULL && failure.line == allocation_line,
                 "compatibility wrapper records allocation source location");

    return ok ? 0 : 1;
}
