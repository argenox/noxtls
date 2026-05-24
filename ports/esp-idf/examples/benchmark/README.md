# NoxTLS benchmark (ESP-IDF)

Measures throughput and ops-per-second of the most common NoxTLS primitives on ESP32-family targets. No networking — runs in `app_main` and prints results over the default UART.

## What it benchmarks

| Group | Algorithm | Metric |
|-------|-----------|--------|
| Symmetric | SHA-256 | MB/s |
| Symmetric | AES-128-GCM (encrypt) | MB/s |
| Symmetric | ChaCha20-Poly1305 (encrypt) | MB/s |
| Symmetric | HMAC-SHA-256 | MB/s |
| Random   | CTR-DRBG (AES-256) | MB/s |
| Public-key | ECDSA P-256 sign / verify | ops/s |

Buffer size and iteration counts are configurable in `menuconfig` (`Component config -> NoxTLS benchmark example`). Defaults: 4 KB buffer, 256 iterations for symmetric primitives, 16 iterations for ECDSA.

## Build and run

```sh
cd noxtls/ports/esp-idf/examples/benchmark
idf.py set-target esp32
idf.py build flash monitor
```

Sample output (figures vary by target / clock):

```
NoxTLS ESP-IDF benchmark
------------------------
Chip:      model=1  cores=2  rev=3  features=0x00000032
Heap free: internal=276432  largest=110548
Buffer:    4096 bytes x 256 iterations  (PKC iterations=16)

Symmetric throughput:
  SHA-256                         12.345 MB/s  (1048576 B in 81234 us)
  AES-128-GCM (encrypt)            5.678 MB/s  ...
  ChaCha20-Poly1305 (encrypt)      9.012 MB/s  ...
  HMAC-SHA-256                    11.234 MB/s  ...

Random:
  CTR-DRBG (AES-256)               4.567 MB/s  ...

Public-key (ECDSA P-256):
  ECDSA P-256 sign                12.34 ops/s  ...
  ECDSA P-256 verify               6.78 ops/s  ...

Done.
```

## Tuning the test load

```sh
idf.py menuconfig
# Component config -> NoxTLS benchmark example
#   Symmetric primitive buffer size (bytes)         = 4096
#   Symmetric throughput iterations                 = 256
#   DRBG generate iterations                        = 256
#   Public-key operation iterations (ECDSA)         = 16
#   [ ] Run ECDSA P-256 benchmark
```

Or set them in `sdkconfig.defaults`:

```ini
CONFIG_NOXTLS_BENCH_BUFFER_SIZE=8192
CONFIG_NOXTLS_BENCH_THROUGHPUT_ITERATIONS=512
CONFIG_NOXTLS_BENCH_PKC_ITERATIONS=32
```

## Caveats

- The benchmark uses the `default` profile so most features are compiled in. Set a tighter profile (`CONFIG_NOXTLS_PROFILE_CRYPTO_ONLY=y`, plus disabling specific features) if you want to measure a smaller build.
- `CONFIG_COMPILER_OPTIMIZATION_PERF=y` is enabled by default so results reflect `-O2`. Switch to `_SIZE` to compare a size-optimized build.
- DRBG output rate measures the CTR-DRBG construction, not the underlying hardware RNG (which is used only at instantiation when `CONFIG_NOXTLS_USE_ESP_ENTROPY=y`).
- ECDSA timings include constant-time scalar multiplication. If you tuned `CONFIG_NOXTLS_ECC_POINT_MUL_WINDOW_SIZE`, expect a sign/verify time change but no security change for the default balanced profile.

## Further reading

- [ESP-IDF port README](../../README.md)
- [Configuration Guide](../../../../docs/docs/configuration-guide.md) — footprint and feature macros
