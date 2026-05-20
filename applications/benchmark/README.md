# NoxTLS Benchmark Demo

This demo runs a portable benchmark set for enabled crypto primitives and prints
results as `ns/op` and `B/s`.

## Files

- `noxtls_benchmark_main.c` - benchmark harness + primitive list
- `noxtls_bench_platform.h` - platform abstraction API
- `noxtls_bench_platform.c` - default timer/output implementation

## Output

- Default: `printf()`
- SEGGER RTT: build with `-DNOXTLS_BENCH_USE_SEGGER_RTT` and add `SEGGER_RTT` sources/include

## Timing

Priority order used by `noxtls_bench_platform.c`:

1. Cortex-M DWT cycle counter (best on STM32)
2. platform monotonic timer (`clock_gettime`/QPC)
3. HAL millisecond tick fallback

## HW acceleration policy

`noxtls_config.h` now includes auto-detection:

- `noxtls-lib/vendor/st/noxtls_target_detect.h`
- `noxtls-lib/vendor/st/noxtls_hw_accel_autoconfig.h`

To disable auto-detect:

- Define `NOXTLS_DISABLE_PLATFORM_AUTOCONFIG=1`

To force explicit user values:

- Define `NOXTLS_HW_ACCEL_USER_OVERRIDE=1`
- Set `NOXTLS_FEATURE_AES_ACCEL_STM32`, `NOXTLS_FEATURE_HASH_ACCEL_STM32`,
  `NOXTLS_FEATURE_ECC_ACCEL_STM32` as needed.
