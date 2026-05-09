# Building NoxTLS

This guide covers building the NoxTLS library and optional applications on Windows, macOS, and Linux.

## Prerequisites

- CMake 3.10 or newer
- A C compiler:
  - Linux/macOS: GCC or Clang
  - Windows: MSVC (Visual Studio) or MinGW

Check tool versions:

```bash
cmake --version
```

## Quick Build (Library + Applications)

From the repository root:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
cmake --build build --config Release
```

Notes:
- `BUILD_APPLICATIONS` is `ON` by default, so this builds the library and apps.
- Application executables are written to the `binary/` directory at the repository root.

## Build Library Only (No Applications)

```bash
cmake -S . -B build -D BUILD_APPLICATIONS=OFF -D BUILD_TESTS=OFF
cmake --build build --config Release
```

## Platform-Specific Examples

## Linux

Using default generator (usually Unix Makefiles or Ninja):

```bash
cmake -S . -B build/linux -D BUILD_TESTS=OFF
cmake --build build/linux -j
```

## macOS

### Installing CMake on macOS

If you don't have CMake installed, the easiest way is with [Homebrew](https://brew.sh/):

```bash
brew install cmake
```

Using Apple Clang with default generator:

```bash
cmake -S . -B build/macos -D BUILD_TESTS=OFF
cmake --build build/macos -j
```

## Windows

### Option A: Visual Studio (MSVC)

```powershell
cmake -S . -B build\windows-msvc -G "Visual Studio 17 2022" -A x64 -D BUILD_TESTS=OFF
cmake --build build\windows-msvc --config Release
```

### Option B: MinGW

```powershell
cmake -S . -B build\windows-mingw -G "MinGW Makefiles" -D BUILD_TESTS=OFF
cmake --build build\windows-mingw --config Release
```

## Optional CMake Build Profiles

Set `NOXTLS_PROFILE` to tune enabled features:

- `default` (default)
- `minimal_tls_client`
- `tls_server_pki`
- `crypto_only`
- `fips_like_profile`

Example:

```bash
cmake -S . -B build -D NOXTLS_PROFILE=crypto_only -D BUILD_APPLICATIONS=OFF
cmake --build build --config Release
```

## Ed448 / EdDSA (optional)

Ed448 requires SHA-3 (SHAKE256). Enable both when configuring:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_SHA3=ON -D NOXTLS_CFG_FEATURE_ED448=ON
cmake --build build --config Release
```

`NOXTLS_CFG_FEATURE_ED448` defaults to `OFF` in the top-level `CMakeLists.txt`. With Ed448 enabled, TLS 1.3 advertises signature scheme **0x0808** (Ed448), X.509 parses **id-Ed448** (1.3.101.113) subject public keys, and the **certgen** tool provides `gened448`. Unit tests under `ut/pkc/` exercise Ed448 and Ed25519ctx/Ed25519ph when these flags are on.

## Common Build Flags

- `-D BUILD_APPLICATIONS=OFF`: Build library only
- `-D BUILD_TESTS=OFF`: Disable test apps in normal builds
- `-D WARNINGS_AS_ERRORS=ON`: Treat warnings as errors (non-MSVC)
- `-D BUILD_SHARED_LIBS=ON`: Build shared libs

## Troubleshooting

- Clean and reconfigure:

  ```bash
  cmake --build build --target clean
  rm -rf build
  ```

  On PowerShell:

  ```powershell
  cmake --build build --target clean
  Remove-Item -Recurse -Force build
  ```

- If using MSVC and a specific app fails, try MinGW or WSL for that target.
- If generator errors occur, specify one explicitly with `-G`.
