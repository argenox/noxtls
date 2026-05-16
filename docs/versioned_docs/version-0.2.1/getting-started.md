---
sidebar_position: 2
---

# Getting Started

## Prerequisites

- CMake 3.10 or newer
- C99 compiler (GCC, Clang, or MSVC)

## Building (standalone)

From the repository root:

```bash
cmake -B build
cmake --build build
```

Options:

- `-DWARNINGS_AS_ERRORS=ON` – Treat compiler warnings as errors
- `-DNOXTLS_CFG_FEATURE_ML_KEM=ON` – Enable ML-KEM
- `-DNOXTLS_CFG_FEATURE_ML_DSA=ON` – Enable ML-DSA

For platform-specific and advanced build recipes, see [`BUILDING.md`](https://github.com/argenox/noxtls/blob/main/noxtls/BUILDING.md).

## Using as a library (Zephyr)

From your Zephyr application CMake:

1. Add the library: `add_subdirectory(path/to/noxtls)` (only the library subtree, not `ut`).
2. Set `NOXTLS_OMIT_UT_SOURCES ON` so unit-test-only sources are not built.
3. Link your app to the noxtls targets and `zephyr_interface` so everything uses the same ABI.

## Next steps

- [Architecture](/docs/architecture) – Library layout and design
- [Security](/docs/security) – Security considerations
- [Configuration Guide](/docs/configuration-guide) – Build/profile and feature flags
- [Crypto API](/docs/api) – C API by module
