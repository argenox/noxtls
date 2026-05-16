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

### Ubuntu packages

Install baseline build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config
```

Useful optional packages:

```bash
sudo apt install -y clang ccache openssl git
```

Notes:
- `build-essential` provides GCC/G++ and Make.
- `ninja-build` is recommended for faster incremental builds (use `-G Ninja`).
- `openssl` is useful for generating local test certificates for TLS applications.

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

Set `NOXTLS_SIDECHANNEL_PROFILE` to tune timing-side-channel behavior:

- `performance`: keeps legacy comparison behavior (opt-in).
- `balanced` (default): enables constant-time secret comparisons for protocol verification/tag checks.
- `constant_time_strict`: keeps balanced behavior and enables strict hardening gates intended for higher assurance builds.

Example:

```bash
cmake -S . -B build -D NOXTLS_SIDECHANNEL_PROFILE=constant_time_strict -D BUILD_APPLICATIONS=OFF
cmake --build build --config Release
```

## TLS 1.2 legacy cipher suites (opt-in)

NoxTLS is secure by default for TLS 1.2 cipher-suite negotiation:

- Legacy TLS 1.2 CBC-mode and RSA key-exchange suites are disabled by default.
- Default TLS 1.2 client/server negotiation focuses on modern AEAD suites.

To explicitly enable legacy TLS 1.2 suites (for compatibility with older peers):

```bash
cmake -S . -B build -D NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES=ON
cmake --build build --config Release
```

For non-CMake integrations, set:

- `NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES=1` in `noxtls_config.h` (or compiler defines).

Keep this setting `OFF` unless required for legacy interoperability.

## Ed448 / EdDSA (optional)

Ed448 requires SHA-3 (SHAKE256). Enable both when configuring:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_SHA3=ON -D NOXTLS_CFG_FEATURE_ED448=ON
cmake --build build --config Release
```

`NOXTLS_CFG_FEATURE_ED448` defaults to `OFF` in the top-level `CMakeLists.txt`. With Ed448 enabled, TLS 1.3 advertises signature scheme **0x0808** (Ed448), X.509 parses **id-Ed448** (1.3.101.113) subject public keys, and the **certgen** tool provides `gened448`. Unit tests under `ut/pkc/` exercise Ed448 and Ed25519ctx/Ed25519ph when these flags are on.

## Post-Quantum TLS 1.3 (experimental)

Enable ML-KEM and ML-DSA feature gates when configuring:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_ML_KEM=ON -D NOXTLS_CFG_FEATURE_ML_DSA=ON
cmake --build build --config Release
```

Current experimental scope:
- ML-KEM-512/768/1024 APIs (`pkc/mlkem`)
- ML-DSA-44/65/87 APIs (`pkc/mldsa`)
- TLS 1.3 advertisement and keyshare processing for pure ML-KEM and X25519+ML-KEM hybrid groups
- TLS 1.3 CertificateVerify paths for ML-DSA signature schemes

See `PQC_STATUS.md` for implementation and interop status by algorithm/mode.
Use `ctest --output-on-failure` in a PQ-enabled test build to run KAT and conformance/fuzz-smoke targets (for example `mlkem_kat_test`, `mldsa_kat_test`, `pqc_fuzz_smoke_test`).

Enable strict official-output vector checks (experimental):

```bash
cmake -S . -B build-pqc-strict -D BUILD_TESTS=ON -D BUILD_APPLICATIONS=OFF -D NOXTLS_CFG_FEATURE_ML_KEM=ON -D NOXTLS_CFG_FEATURE_ML_DSA=ON -D NOXTLS_CFG_PQC_STRICT_OFFICIAL_VECTORS=ON
cmake --build build-pqc-strict --config Release
ctest --test-dir build-pqc-strict --output-on-failure -R "mlkem_official_keygen_conformance_test"
```

To include ML-DSA keygen strict checks in the same run:

```bash
ctest --test-dir build-pqc-strict --output-on-failure -R "mlkem_official_keygen_conformance_test|mldsa_official_keygen_conformance_test|mldsa_official_siggen_conformance_test|mldsa_official_sigver_conformance_test"
```

## Common Build Flags

- `-D BUILD_APPLICATIONS=OFF`: Build library only
- `-D BUILD_TESTS=OFF`: Disable test apps in normal builds
- `-D NOXTLS_SIDECHANNEL_PROFILE=balanced`: Choose timing-hardening profile (`performance|balanced|constant_time_strict`)
- `-D NOXTLS_CFG_FEATURE_ML_KEM=ON`: Enable ML-KEM primitives and TLS PQ keyshare paths
- `-D NOXTLS_CFG_FEATURE_ML_DSA=ON`: Enable ML-DSA primitives and TLS PQ signature paths
- `-D WARNINGS_AS_ERRORS=ON`: Treat warnings as errors (non-MSVC)
- `-D BUILD_SHARED_LIBS=ON`: Build shared libs

## Static Analysis

NoxTLS provides local and CI static-analysis coverage:

- `cppcheck` (fast/portable rule-based checks)
- `clang-tidy` (AST-aware correctness/style checks)
- `scan-build` (Clang Static Analyzer, path-sensitive checks)
- `Semgrep` (`p/ci` security and bug patterns)
- `CodeQL` (already configured in `.github/workflows/codeql.yml`)

### Run local analysis and capture reports

From the repository root:

```bash
./scripts/run_static_analysis.sh
```

The script writes results to:

- `reports/static-analysis/cppcheck.txt`
- `reports/static-analysis/clang-tidy.txt`
- `reports/static-analysis/summary.txt`

If local analyzers are unavailable in system PATH, the script also checks user-local extractions under `.local-tools/root/`.

**Cppcheck data files:** Debian/Ubuntu `cppcheck` expects `std.cfg` under `/usr/lib/x86_64-linux-gnu/cppcheck/cfg/`. A binary unpacked from a `.deb` alone often cannot run until those cfg files exist at that path (or you use a newer cppcheck that supports `--data-dir`). If preflight fails, the script writes an explanation to `reports/static-analysis/cppcheck.txt` and skips cppcheck unless you set `REQUIRE_CPPCHECK=1` (then the script exits with an error).

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
