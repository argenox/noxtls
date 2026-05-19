# NoxTLS on Zephyr RTOS

This directory contains the Zephyr RTOS port for [NoxTLS](https://github.com/argenox/noxtls). The module entry point required by Zephyr lives at the repository root in [`zephyr/module.yml`](../../zephyr/module.yml); build integration files are here under `ports/zephyr/`.

Future ports for other RTOS or build systems will live alongside this one under `ports/` (for example `ports/freertos/`).

## West manifest

Add NoxTLS to your Zephyr workspace `west.yml`:

```yaml
manifest:
  projects:
    - name: noxtls
      url: https://github.com/argenox/noxtls
      revision: master
      path: modules/crypto/noxtls
```

Then update the workspace:

```sh
west update
```

## Enable in your application

In `prj.conf`:

```ini
CONFIG_NOXTLS=y
CONFIG_ENTROPY_GENERATOR=y
CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY=y
CONFIG_COMMON_LIBC_MALLOC=y
```

On `native_sim` for development and Twister, also enable:

```ini
CONFIG_TEST_RANDOM_GENERATOR=y
```

Link the library from your app `CMakeLists.txt`:

```cmake
target_link_libraries(app PRIVATE noxtls)
```

Entropy is registered automatically via `SYS_INIT` in `src/noxtls_zephyr_glue.c` when `CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY` is set.

## Build the sample

From your Zephyr workspace (with this module at `modules/crypto/noxtls`):

```sh
west build -b native_sim modules/crypto/noxtls/ports/zephyr/samples/tls_client
west build -t run
```

The sample prints `NoxTLS TLS sample ready` by default (TLS context init only). To attempt a live TLS 1.3 handshake, add to `prj.conf`:

```ini
CONFIG_NOXTLS_SAMPLE_TLS_CONNECT=y
CONFIG_NOXTLS_SAMPLE_TLS_HOST="example.com"
```

You must configure a trust anchor (X.509 CA) for production handshakes; see the [Porting Guide](../../docs/docs/porting-guide.md).

## Run integration tests (Twister)

```sh
twister -T modules/crypto/noxtls/ports/zephyr -p native_sim
twister -T modules/crypto/noxtls/ports/zephyr -p qemu_x86
```

## Kconfig

Run `west build -t menuconfig` and open **Modules → NoxTLS** to adjust profiles, TLS versions, and algorithms. Profiles mirror the CMake options documented in [BUILDING.md](../../BUILDING.md).

## Further reading

- [Porting Guide](../../docs/docs/porting-guide.md) — memory, entropy, and TLS transport
- [Configuration Guide](../../docs/docs/configuration-guide.md) — feature macros and footprint tuning
