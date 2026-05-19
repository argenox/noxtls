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

## Kconfig and `noxtls_config.h`

NoxTLS is configured in two cooperating layers:

1. **`noxtls_config.h`** — C preprocessor defaults, profile `#undef`/`#define` blocks, and compile-time checks in `noxtls_check_config.h`.
2. **Zephyr Kconfig** — `CONFIG_NOXTLS_*` symbols in `prj.conf` / `menuconfig`, generated from [`noxtls_config_catalog.xml`](../../noxtls_config_catalog.xml).

When you build for Zephyr, [`noxtls_zephyr_kconfig.cmake`](noxtls_zephyr_kconfig.cmake) (generated) maps each `CONFIG_NOXTLS_*` symbol to either:

- a **`NOXTLS_CFG_*` CMake cache variable** (controls which `.c` files are compiled), and/or
- a **`zephyr_compile_definitions()`** for header-only macros (buffer sizes, `NOXTLS_HAVE_TIME`, RSA tuning, and similar).

That mirrors standalone CMake, which uses `NOXTLS_CFG_FEATURE_*` and `add_compile_definitions(NOXTLS_FEATURE_*=…)`.

### Profile vs per-option tuning

| Profile in menuconfig | Effect |
|----------------------|--------|
| **default** | Individual Kconfig booleans/integers are applied to the build. |
| **minimal_tls_client**, **crypto_only**, etc. | Root [`CMakeLists.txt`](../../CMakeLists.txt) applies the same preset matrix as desktop builds; many per-option Kconfig values are overridden. |

Use profile **default** when you want `menuconfig` to drive every feature flag. Use a named profile for the same shortcuts as `-DNOXTLS_PROFILE=…` in CMake.

### menuconfig

Run `west build -t menuconfig` and open **Modules → NoxTLS**. Library options live under **NoxTLS library options (from noxtls_config.h)** (generated menu). Profiles and Zephyr hooks (entropy, heap) are in the parent menu.

You can also set options in `prj.conf`, for example:

```ini
CONFIG_NOXTLS_PROFILE_DEFAULT=y
CONFIG_NOXTLS_FEATURE_TLS13=y
CONFIG_NOXTLS_FEATURE_RSA=n
CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE=8192
```

### Tuning RAM usage (buffer sizes)

All integer tunables from `noxtls_config.h` are grouped in **NoxTLS library options → Buffer sizes and limits (RAM tuning)**. Lower these to shrink stack/heap on constrained targets. Each option has Kconfig `range` bounds enforced by `menuconfig`/`west build`.

Example `prj.conf` snippet for a footprint-conscious TLS 1.3 client (cuts the record buffers ~4×):

```ini
CONFIG_NOXTLS=y
CONFIG_NOXTLS_PROFILE_MINIMAL_TLS_CLIENT=y

# Record/handshake buffers — both peers must agree on smaller fragments
# (e.g. RFC 6066 max_fragment_length) when below 16384.
CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE=4096
CONFIG_NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH=4480
CONFIG_NOXTLS_TLS_MAX_HANDSHAKE_SIZE=4096

# Certificate parsing bounds — set to your worst-case cert/chain.
CONFIG_NOXTLS_MAX_CERT_SIZE=4096
CONFIG_NOXTLS_MAX_CERT_CHAIN_DEPTH=4

# Static-buffer allocator pool (only used when NOXTLS_USE_STATIC_BUFFERS=y).
CONFIG_NOXTLS_STATIC_BUFFER_SIZE=16384

# ECC scalar-mul table: 0 = Montgomery ladder only (smallest RAM).
CONFIG_NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0
```

Each `CONFIG_NOXTLS_*` integer becomes `-DNOXTLS_*=<value>` at compile time via `zephyr_compile_definitions()` in [`noxtls_zephyr_kconfig.cmake`](noxtls_zephyr_kconfig.cmake), so the value is visible to every NoxTLS source file. Profile-overridden settings still win at build time; pick `CONFIG_NOXTLS_PROFILE_DEFAULT=y` if you want pure Kconfig control.

### Regenerating Kconfig from the catalog

After editing [`noxtls_config.h`](../../noxtls_config.h), refresh the catalog and Zephyr files:

```sh
python noxtls/tools/config_catalog/generate_config_catalog.py
python noxtls/tools/zephyr_kconfig/generate_zephyr_kconfig.py
```

Commit the updated `noxtls_config_catalog.xml`, `ports/zephyr/Kconfig.noxtls.generated`, and `ports/zephyr/noxtls_zephyr_kconfig.cmake`.

To verify generated files are current:

```sh
python noxtls/tools/zephyr_kconfig/generate_zephyr_kconfig.py --check
```

## Further reading

- [Porting Guide](../../docs/docs/porting-guide.md) — memory, entropy, and TLS transport
- [Configuration Guide](../../docs/docs/configuration-guide.md) — feature macros and footprint tuning
