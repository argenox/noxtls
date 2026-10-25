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
- Short generic CLI names are installed as `noxtls-*` (for example `noxtls-base64`) to avoid PATH collisions; see [applications/README.md](applications/README.md).

## Install (SDK layout)

Install static libraries, public headers, CMake package files, pkg-config metadata, and CLIs:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF -D BUILD_APPLICATIONS=ON -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --config Release
cmake --install build
```

After install:

- Libraries: `${prefix}/lib/libnoxtls_*.a`
- Headers: `${prefix}/include/` (root `noxtls*.h`, plus `noxtls-lib/` and `utility/`)
- CMake package: `find_package(NoxTLS)` → link `NoxTLS::noxtls`
- pkg-config: `pkg-config --libs --cflags noxtls`
- CLIs: `${prefix}/bin/` (`noxtls`, `tlscurl`, `certgen`, …)

## Homebrew

macOS/Linux users can install the full SDK from the [argenox/homebrew-noxtls](https://github.com/argenox/homebrew-noxtls) tap:

```bash
brew tap argenox/noxtls
brew install noxtls
```

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

## Embedded targets (Cortex-M and RISC-V)

Toolchain files in `cmake/toolchains/` cross-build the static libraries:

| Target | Toolchain file | Compiler |
|---|---|---|
| Cortex-M0+ | `arm-none-eabi-cortex-m0plus.cmake` | `arm-none-eabi-gcc` |
| Cortex-M4 (M3, M7 with `-DNOXTLS_ARM_CPU_FLAGS=...`) | `arm-none-eabi-cortex-m4.cmake` | `arm-none-eabi-gcc` |
| Cortex-M33 | `arm-none-eabi-cortex-m33.cmake` | `arm-none-eabi-gcc` |
| RV32IMAC (ilp32) | `riscv-none-elf-rv32imac.cmake` | `riscv-none-elf-gcc` |
| RV64IMAC (lp64) | `riscv-none-elf-rv64imac.cmake` | `riscv-none-elf-gcc` |

For RISC-V, use a `riscv-none-elf` GCC with newlib, such as the [xPack GNU RISC-V Embedded GCC](https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/). Put it on `PATH` or set `RISCV_GNU_TOOLCHAIN_ROOT` to its install folder. Override the RISC-V flags with `-DNOXTLS_RISCV_CPU_FLAGS=...`, for example `-march=rv32imc_zicsr -mabi=ilp32` for an ESP32-C3.

```sh
cmake -S . -B build-rv32 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/riscv-none-elf-rv32imac.cmake \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_TESTS=OFF -DBUILD_APPLICATIONS=OFF
cmake --build build-rv32
```

### Running the known-answer tests under QEMU

`scripts/run_arm_tests.sh` builds bare-metal semihosting test images and runs them under QEMU. The images cover the post-quantum KATs and the freestanding classic KATs (Ed25519, AES-GCM, CMAC). Each one reports its stack and heap high-water marks.

| `--cpu` | Core | QEMU machine |
|---|---|---|
| `m3` | Cortex-M3 | `qemu-system-arm -M mps2-an385` |
| `m4` (default) | Cortex-M4 | `qemu-system-arm -M mps2-an386` |
| `m7` | Cortex-M7 | `qemu-system-arm -M mps2-an500` |
| `m33` | Cortex-M33 | `qemu-system-arm -M mps2-an505` |
| `rv32` | RV32IMAC | `qemu-system-riscv32 -M virt -bios none` |
| `rv64` | RV64IMAC | `qemu-system-riscv64 -M virt -bios none` |

```sh
scripts/run_arm_tests.sh --cpu rv32 --features pq   # pq (default) or default
```

QEMU is found on `PATH`, through `QEMU_SYSTEM_ARM` / `QEMU_SYSTEM_RISCV`, or in `C:/Program Files/qemu`. `--no-run` builds without QEMU. The `arm-pq.yml` workflow runs this matrix in CI.

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
- `constant_time_strict`: currently the same as `balanced`. The additional strict hardening it is meant to add is not implemented yet (known anomaly NOXTLS-KA-0.3.15-14).

Example:

```bash
cmake -S . -B build -D NOXTLS_SIDECHANNEL_PROFILE=constant_time_strict -D BUILD_APPLICATIONS=OFF
cmake --build build --config Release
```

## TLS 1.2 legacy cipher suites and SHA-1 signatures (opt-in)

By default TLS 1.2 and DTLS 1.2 (plain `noxtls_tls12_*` contexts, the TLS 1.2 path of the unified connection API and DTLS 1.2) use only forward-secret AEAD cipher suites and never use SHA-1 signatures:

- Client offer and server selection: ECDHE-ECDSA with AES-128/256-GCM, ChaCha20-Poly1305, AES-128/256-CCM and AES-128/256-CCM_8; ECDHE-RSA with AES-128/256-GCM and ChaCha20-Poly1305; DHE-RSA with AES-128/256-GCM, ChaCha20-Poly1305, AES-128/256-CCM and AES-128/256-CCM_8.
- A server never negotiates a CBC-mode, static-RSA or 3DES suite, even when an application allowlist (`noxtls_tls12_set_server_cipher_suites()`, `--cipher-suites`) names one. A ClientHello that offers nothing else fails with `handshake_failure`.
- signature_algorithms offered by the client: rsa_pkcs1_sha256/384/512, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha256/384/512. A ServerKeyExchange signed with any other scheme (SHA-1, MD5) is rejected with `illegal_parameter`; so is a ServerHello that selects a suite the client did not offer.
- The server signs ServerKeyExchange only with a SHA-256 or stronger scheme the client listed. Behaviour change: a client that omits signature_algorithms (RFC 5246 7.4.1.4.1 then implies SHA-1) now gets `handshake_failure` instead of a SHA-1 (RSA) signature. CertificateRequest lists only SHA-256 / SHA-384 schemes and MD5 is never negotiated, as before.

Two switches, both `OFF` by default, restore the earlier behaviour (with both on, offers and acceptance are the same as in 0.3.15):

| CMake option | `noxtls_config.h` macro | Enables |
|--------------|-------------------------|---------|
| `NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES` | `NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES` | Every CBC-mode suite (AES-CBC, ARIA-CBC, 3DES), every static-RSA key exchange suite (`TLS_RSA_WITH_*`, including the AES-GCM and AES-CCM ones). 3DES also needs `NOXTLS_FEATURE_DES=1`. |
| `NOXTLS_CFG_TLS12_ENABLE_SHA1_SIGNATURES` | `NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES` | rsa_pkcs1_sha1 (0x0201) and ecdsa_sha1 (0x0203): offered and accepted by the client; used by the server when the client lists them or omits signature_algorithms. Needs `NOXTLS_FEATURE_SHA1=1`. |

```bash
cmake -S . -B build -D NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES=ON -D NOXTLS_CFG_TLS12_ENABLE_SHA1_SIGNATURES=ON
cmake --build build --config Release
```

For non-CMake integrations set `NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES=1` and/or `NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES=1` in `noxtls_config.h` (or as compiler defines).

TLS 1.0 and TLS 1.1 (`NOXTLS_CFG_FEATURE_TLS10` / `NOXTLS_CFG_FEATURE_TLS11`, off by default) have nothing but CBC suites with RSA key exchange and fixed MD5/SHA-1 signatures. A connection that runs TLS 1.0 or 1.1 keeps them whatever these switches say; enabling TLS 1.0/1.1 does not turn the legacy algorithms on for TLS 1.2 connections in the same build.

Keep both switches `OFF` unless a peer cannot do better.

## Ed448 / EdDSA (optional)

Ed448 requires SHA-3 (SHAKE256). Enable both when configuring:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_SHA3=ON -D NOXTLS_CFG_FEATURE_ED448=ON
cmake --build build --config Release
```

`NOXTLS_CFG_FEATURE_ED448` defaults to `OFF` in the top-level `CMakeLists.txt`. With Ed448 enabled, TLS 1.3 advertises signature scheme **0x0808** (Ed448), X.509 parses **id-Ed448** (1.3.101.113) subject public keys, and the **certgen** tool provides `gened448`. Unit tests under `ut/pkc/` exercise Ed448 and Ed25519ctx/Ed25519ph when these flags are on.

## SPAKE2+, Matter PASE and PBKDF2 (optional)

SPAKE2+ (RFC 9383, P-256/SHA-256/HKDF/HMAC), the Matter draft-01 SPAKE2+ profile, Matter PASE helpers and PBKDF2 are disabled by default:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_SPAKE2P=ON                      # RFC 9383 profile
cmake -S . -B build -D NOXTLS_CFG_FEATURE_PBKDF2=ON -D NOXTLS_CFG_FEATURE_SPAKE2P=ON       -D NOXTLS_CFG_FEATURE_SPAKE2P_MATTER=ON -D NOXTLS_CFG_FEATURE_MATTER_PASE=ON   # + Matter PASE
```

`NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383` (ON) and `NOXTLS_CFG_FEATURE_SPAKE2P_MATTER` (OFF) select which key-schedule profiles are compiled; at least one is required. Unit tests: add `-D BUILD_TESTS=ON -D NOXTLS_BUILD_PAKE_TESTS=ON -D NOXTLS_ERROR_UTNOX=<utnox checkout>`. See `docs/docs/spake2p.md`.

## EC-JPAKE and the DTLS 1.2 EC-JPAKE suite (optional)

EC-JPAKE (RFC 8236 / RFC 8235 over P-256) and `TLS_ECJPAKE_WITH_AES_128_CCM_8` for TLS 1.2 / DTLS 1.2 (draft-cragie-tls-ecjpake-01, as used by Thread MeshCoP commissioning) are disabled by default:

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_ECJPAKE=ON                                        # primitive only
cmake -S . -B build -D NOXTLS_CFG_FEATURE_ECJPAKE=ON -D NOXTLS_CFG_FEATURE_DTLS_ECJPAKE=ON   # + DTLS 1.2 suite
```

Unit tests: add `-D BUILD_TESTS=ON -D NOXTLS_BUILD_PAKE_TESTS=ON -D NOXTLS_ERROR_UTNOX=<utnox checkout>`. See `docs/docs/ecjpake.md`.

## Self-Signed Certificate Generation (certgen)

The X.509 write/generate APIs in `noxtls-lib/certs/noxtls_x509_write.c` are gated by `NOXTLS_HAVE_CERT_WRITE`, which is now **ON by default** in the `default`, `tls_server_pki` and `fips_like_profile` profiles. They are required to use the `certgen req -new -x509` command. To explicitly toggle:

```bash
cmake -S . -B build -D NOXTLS_CFG_HAVE_CERT_WRITE=ON   # enable (default)
cmake -S . -B build -D NOXTLS_CFG_HAVE_CERT_WRITE=OFF  # strip the writer
```

`certgen req -new -x509` can sign certificates with any key type supported by `noxtls_x509_private_key_sign_data`:

| Private key      | Subject PK algorithm | Signature algorithm                            |
|------------------|----------------------|------------------------------------------------|
| RSA              | `rsaEncryption` (with explicit NULL params, RFC 3279/8017) | `sha256WithRSAEncryption` |
| ECC (NIST/Brainpool/secp-K1) | `id-ecPublicKey` with namedCurve OID | `ecdsa-with-SHA256/384/512` (sized to curve) |
| Ed25519 / Ed448  | `id-Ed25519` / `id-Ed448` (RFC 8410) | PureEdDSA, same OID |
| ML-DSA           | `id-ml-dsa-{44,65,87}` (NIST CSOR) | same OID |
| SLH-DSA          | `id-slh-dsa-*` (NIST CSOR) | same OID |

For RSA the AlgorithmIdentifier carries an explicit ASN.1 NULL as required by strict parsers (OpenSSL, mbedTLS); for ECC the namedCurve OID is embedded as parameters; for the other algorithms the parameters field is absent. Self-signed certs produced this way verify cleanly with `openssl verify -CAfile`.

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
