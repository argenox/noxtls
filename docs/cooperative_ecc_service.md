# Cooperative software ECC service

A low-priority worker does not make long P-256 operations preemptible on a
cooperative RTOS. The embedding firmware can override `noxtls_ecc_yield()`
and yield from its active worker at bounded public loop boundaries. The
portable default does nothing; GNU/Clang weak linkage and MSVC fallback
aliases permit a strong port implementation.

`NOXTLS_ECC_COOPERATIVE_SERVICE_VERSION == 2` includes optimized point
precomputation/comb loops and P-256 field inversion. Inversion uses the same
Fermat power as the existing bignum fast path, with an explicit per-call
`noxtls_bn_mod_exp_service()` callback through software Montgomery setup,
precomputation, squaring and multiply steps, or the even-modulus ladder.
The original `noxtls_bn_mod_exp()` supplies NULL and retains its behavior.
Neither callback receives scalar bits or operand buffers.

Only yield in task context with interrupts enabled, outside allocator or
hardware ownership transitions. Preserve all inputs and live temporary
storage until the operation returns. If serviced tasks can themselves use
ECC, disable `NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE` and
`NOXTLS_ECC_SHARED_SCRATCH`, or otherwise serialize those callers. Firmware
should bind the hook to the worker's task identity so a nested Host/Controller
ECC call cannot accidentally yield the suspended worker's task state.

The hook does not change hardware accelerator arbitration or split an
individual field multiply. Measure the longest service gap on the actual
CPU/profile before deriving a queue or scheduling budget. A first board
increment that sliced only point loops still had 145-ms gaps and two FIFO
drops, so it is retained as a failed strict queue result.

Native regression vectors verify exact P-256 products, an affine inverse,
ECDH ownership, nested ECC with private storage, odd/even per-call powers,
nested bignum work, aliasing, NULL/legacy callbacks and invalid-input behavior.
These establish arithmetic and callback behavior, not radio qualification.
