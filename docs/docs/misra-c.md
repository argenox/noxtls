---
sidebar_position: 2
title: MISRA C:2025
description: "NoxTLS 0.3.0 and MISRA C:2025: target standard, analysis status, coding conventions, how to verify, and integration guidance for safety-related, automotive, and industrial projects."
keywords:
  - noxtls
  - misra c
  - misra c:2025
  - functional safety
  - automotive
  - industrial
  - embedded tls
  - c cryptography
---

# MISRA C:2025

:::info New in NoxTLS 0.3.0
NoxTLS 0.3.0 is the first release built against **MISRA C:2025**. The MISRA work fixed Mandatory and Required findings **in the code itself**, with no suppressions or blanket exemptions. It changed types, bounded copies, control flow, and how the library uses the C standard library. This page covers what was done, what the recorded analysis shows, what changes for you, and how to check the result in your own configuration.
:::

## At a glance

| Topic | 0.3.0 |
|---|---|
| Target guideline set | MISRA C:2025 |
| How findings were resolved | Code changes. The MISRA clean-up used no exemptions. |
| Mandatory findings | 0 in every recorded library scan (see [Analysis status](#analysis-status)) |
| Required findings | 0 after the MISRA clean-up. After the upstream 0.2.72 integration, 24 remain with draft technical dispositions awaiting project sign-off. |
| Advisory findings | Not claimed. 2174 were reported in the most recent recorded scan. |
| Certification | None. NoxTLS is not certified or qualified under ISO 26262, IEC 61508, or any other functional-safety standard. |
| Library allocator rule | Raw `malloc`/`calloc`/`realloc`/`free` are allowed only in the allocator implementation. A test enforces this. |
| Host stdio | Optional. `NOXTLS_HAVE_FILE_IO=0` compiles out the library's file I/O (`fopen`/`fread`/`fwrite` helpers). Debug printing compiles to a no-op unless you opt in. |

## Analysis status

The MISRA history in the 0.3.0 line has three stages:

| Stage | Commit | What was recorded |
|---|---|---|
| MISRA clean-up | `6327562`: *feat(misra): clear Required/Mandatory MISRA C:2025 findings without exemptions* | Mandatory and Required findings fixed in code: fixed-width `uint8_t` APIs, bounded copy and fill helpers, control-flow and shift hardening, and host stdio gated behind `NOXTLS_HAVE_FILE_IO`. On the scanned profile: **Mandatory = 0, Required = 0**. |
| Integration with upstream 0.2.72 and PR 34 | `0a1c948` (merged through `9b7c164`, `752a572`, `356d064`) | Scans of both the private-state and shared-state configurations covered **96 translation units** each: **0 Mandatory, 24 Required, 2174 Advisory**. The 24 Required findings have draft technical dispositions that still need project sign-off. The raw gate is **not** clear. |
| Release-branch integration | `9413b02` (*Merge origin/feat/misra-work into release/0.3.00rc*), then `d518cf9` and `432f2b6` | Conflicts with the other 0.3.0 features were resolved in the MISRA style. This covered the AES modes, CCM, GCM, CMAC, XTS, DRBG, Ed25519, the X.509 policy API, the TLS 1.2 policy and workspace changes, PBKDF2, AES key wrap, and the allocator checker. **This repository has no MISRA scan result for the final merged tree.** |

What this means for 0.3.0:

- **Mandatory:** no Mandatory findings in any recorded library scan.
- **Required:** fixed without exemptions in the clean-up. The integration scan then reported 24 Required findings with draft dispositions. Read 0.3.0 as "Required findings resolved, or under draft disposition", not as a zero-finding gate.
- **Later features:** some modules were added on the release branch after the recorded scans:
  - SPAKE2+ and the Matter PASE helpers (`noxtls-lib/pake`)
  - the raw X.509 extension walker
  - the CC13xx, nRF54 CRACEN, and NoxV hardware ports

  Their MISRA status has not been recorded separately. For example, the SPAKE2+ public header still uses C `enum` types, while the core modules have moved to fixed-width typedefs.
- **Coverage:** the scan covers only the translation units compiled in the scanned configuration. Code outside it is not covered, including optional hardware backends, vendor SDK code, sample applications, unit tests, and host tools.
- **Advisory:** not claimed.

:::note Evidence
This repository does not include the analysis reports or the draft dispositions. If your safety case needs them, contact Argenox at info@argenox.com.
:::

## What changed in the code

Most of these changes are invisible at the call site. The ones below affect integrators.

### Fixed-width types instead of enums

Many public enum types are now **`uint32_t` typedefs** with unsigned `#define` constants. This means constants have the same essential type as the variables and return values that hold them (Rule 10.3). **Numeric values are unchanged.**

| Type | Header |
|---|---|
| `noxtls_return_t` | `noxtls_common.h` |
| `noxtls_hash_algos_t` | `mdigest/noxtls_hash.h` |
| `noxtls_aes_type_t`, `noxtls_aes_mode_t`, `noxtls_aes_operation_t` | `encryption/aes/noxtls_aes.h` |
| `ecc_curve_t`, `rsa_key_size_t` | `pkc/ecc/noxtls_ecc.h`, `pkc/rsa/noxtls_rsa.h` |
| `x509_private_key_type_t`, `x509_private_key_format_t` | `certs/noxtls_x509.h` |
| `noxtls_mlkem_param_t`, `noxtls_mldsa_param_t`, `noxtls_slhdsa_param_t`, ... | `pkc/mlkem/`, `pkc/mldsa/`, `pkc/slhdsa/` headers |

Code that compares against or switches on these constants keeps working. Code that forward-declares one of these as an `enum`, or depends on its signedness, needs updating.

### Text is `uint8_t`, not `char`

Public APIs that take or return text now use `const uint8_t *` / `uint8_t *`. MISRA treats plain `char` as a separate essential type, and its signedness is implementation-defined. This affects:

- hostnames, SNI, and ALPN lists
- file paths and passwords
- distinguished-name and time strings written by the X.509 parser
- debug format strings

For example:

```c
/* 0.2.x */
noxtls_x509_certificate_matches_hostname(&cert, "device.example.com", 0);

/* 0.3.0 */
noxtls_x509_certificate_matches_hostname(&cert, (const uint8_t *)"device.example.com", 0U);
```

Structure fields such as `x509_certificate_t::subject_dn`, `issuer_dn`, and the SAN arrays are `uint8_t` arrays. For NUL-terminated `uint8_t` text, `noxtls_ct.h` provides `noxtls_u8_strlen()`, `noxtls_u8_strcmp()`, and `noxtls_u8_strncmp()`, so you don't need to cast back to `char *` for the libc string functions.

### Bounded byte helpers

Inside the library, `memcpy`/`memset`/`memmove` were replaced by size-checked helpers from `noxtls_ct.h`. These support Mandatory Rule 21.18 (size arguments to `<string.h>` functions must be valid):

```c
void noxtls_copy_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n); /* non-overlapping */
void noxtls_move_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n); /* overlap-safe */
void noxtls_fill_u8(uint8_t *dst, size_t dst_cap, uint8_t fill_byte, size_t n);
```

Each helper writes `min(n, dst_cap)` bytes. That makes it memory-safe, but if you call these helpers from your own code, check lengths first: a too-short destination is **truncated silently**, not reported. Use `noxtls_secure_zero()` to erase secrets.

### Allocator routing (no raw allocator calls)

- Library code allocates through `NOXTLS_MALLOC`, `NOXTLS_CALLOC`, and `NOXTLS_REALLOC`, which record the source location, and releases through `noxtls_free()`. See [Memory usage](./memory-usage.md#last-allocation-failure) for details.
- Raw `malloc`/`calloc`/`realloc`/`free` may appear only in `noxtls-lib/common/noxtls_memory.c` and `noxtls_memory_stdlib.c`. The checker `scripts/check_allocator_policy.py` enforces this.
- **Rule 21.2:** `noxtls_memory_compat.h` no longer `#define`s `malloc`, `free`, `calloc`, or `realloc` to NoxTLS functions, because redefining standard-library names is not allowed. If your port code relied on that remap, call `noxtls_malloc()`/`noxtls_free()` (or the uppercase macros) explicitly.
- With `NOXTLS_USE_STATIC_BUFFERS=1`, the allocator never includes `<stdlib.h>`, so static-pool builds never see `malloc`/`free` (Rule 21.3).

### Host stdio is opt-in

- **`NOXTLS_HAVE_FILE_IO`** (default `1`, in `noxtls_config.h` and the ESP-IDF/Zephyr Kconfig): define it to `0` to build without the stdio file helpers. These functions then return `NOXTLS_RETURN_FAILED`:
  - `noxtls_load_file()`, `noxtls_load_text_file()`, `noxtls_write_file()`, `noxtls_write_text_file()`
  - `noxtls_x509_certificate_load_file()`, `noxtls_x509_private_key_load_file()`, `noxtls_x509_crl_load_file()`

  Load credentials from memory instead (`*_parse_der()` / `*_parse_pem()`). The TLS 1.3 key log (`noxtls_tls13_set_keylog_file()`) also stops writing files. The TLS record-dump helper has its own compile-time switch, `NOXTLS_TLS_RECORD_DUMP`, which defaults to `0`; keep it off in production builds.

  A few translation units still include `<stdio.h>` without calling its I/O functions, for example the ECC, bignum, and RSA sources. Rule 21.6 restricts calls to the I/O functions, not the include itself.
- **`noxtls_debug_printf()`** is a no-op by default. The stdio/`stdarg` implementation (Rules 17.1 and 21.6) is compiled only when you configure CMake with `-DNOXTLS_DEBUG_PRINTF_STDIO=ON`. **Debug output is therefore off in default 0.3.0 builds.** Turn it on for host debugging only.

### Rule 8.7 reference units

Each library module has a `*_api_refs.c` translation unit that takes the address of the module's public functions through `NOXTLS_MISRA_REF_FN()` from `noxtls_misra_refs.h`. This shows analyzers that external linkage is justified (Rule 8.7) without function-pointer conversions (Rule 11.1). The units export no symbols.

On GCC and Clang they use `__attribute__((used))` and `__typeof__`. Other compilers, including MSVC, get plain `(void)` references, a 0.3.0 portability fix. Include these files when you feed the library to your analyzer.

### Control flow and arithmetic

You will see these patterns in the source. Behavior is unchanged.

- Explicit comparisons (`!= 0U`) instead of implicit truth tests.
- A final `else` on `if … else if` chains (Rule 15.7).
- Shift counts bounded by construction (Rule 12.2).
- An iterative ASN.1 TLV walk instead of recursion (Rule 17.2).
- String literals replaced by explicit `uint8_t` arrays where the bytes are used as data (Rule 7.4).
- File-scope objects moved to block scope where they are used once (Rule 8.9).

## How to verify

### 1. Allocator policy (every build)

```bash
python3 scripts/check_allocator_policy.py
# Allocator policy: PASS
```

With `BUILD_TESTS=ON`, the same check runs under CTest as `allocator_policy_check`:

```bash
ctest --test-dir build -R allocator_policy --output-on-failure
```

### 2. Run your MISRA C:2025 analyzer on your configuration

MISRA results depend on the configuration: feature gates decide which translation units and branches are compiled. Analyze the exact configuration you ship:

```bash
cmake -S . -B build-misra \
  -D BUILD_APPLICATIONS=OFF -D BUILD_TESTS=OFF \
  -D CMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -D NOXTLS_DEBUG_PRINTF_STDIO=OFF \
  -D CMAKE_C_FLAGS="-DNOXTLS_HAVE_FILE_IO=0"
cmake --build build-misra
# Feed build-misra/compile_commands.json to your MISRA C:2025 checker.
```

Add your own feature knobs (see the [Configuration guide](./configuration-guide.md)) and, for static-pool builds, `NOXTLS_USE_STATIC_BUFFERS=1` in your configuration header. Run the analysis on both the private-state default and any shared-state options you enable (`NOXTLS_HMAC_SHA256_SHARED_STATE`, `NOXTLS_ECC_SHARED_SCRATCH`).

### 3. Functional regression

The MISRA rewrite changed a lot of code: `6327562` alone touched almost 300 files. Run the unit and known-answer tests on the target after changing configuration:

```bash
cmake -S . -B build -D BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The repository also runs general static analysis in CI (`.github/workflows/static-analysis.yml`: cppcheck, clang-tidy, scan-build). These are **not** MISRA checkers and don't replace step 2.

## Guidance for safety-related, automotive, and industrial projects

- **Treat NoxTLS as a third-party (SOUP/COTS) component.** MISRA C:2025 conformance evidence is one input to your safety or cybersecurity case (for example ISO 26262, IEC 61508, ISO/SAE 21434, or IEC 62443). It doesn't replace your own requirements, testing, tool qualification, or impact analysis.
- **Pin and minimize the configuration.** Turn off every algorithm and protocol you don't use. This shrinks both the analyzed code and the attack surface. MISRA evidence is valid only for the configuration that was analyzed.
- **Recommended build settings for safety-oriented targets:**
  - `NOXTLS_HAVE_FILE_IO=0` and `NOXTLS_DEBUG_PRINTF_STDIO=OFF`
  - `NOXTLS_USE_STATIC_BUFFERS=1` with a sized pool (see [Memory usage](./memory-usage.md))
  - a `balanced` or `constant_time_strict` [side-channel profile](./configuration-guide.md#side-channel-profiles)
- **Keep per-context crypto state** (the default). Turn on `NOXTLS_HMAC_SHA256_SHARED_STATE` or `NOXTLS_ECC_SHARED_SCRATCH` only if you serialize all access, including from interrupts. See [Concurrent crypto scratch storage](./memory-usage.md#concurrent-crypto-scratch-storage).
- **Review hardware backends separately.** Ports under `noxtls-lib/vendor/` and the accelerator callback ports interface with vendor registers and SDKs. Where they need inline assembly, the source records it as a Dir 4.3 deviation (for example the nRF54 CRACEN backend). Vendor SDK code is outside NoxTLS's scope.
- **Check your own call sites.** Calling the `uint8_t` text APIs with string literals needs a cast. Handle it under your project's MISRA policy (or keep identifiers in `uint8_t` arrays), and record any deviations in your own deviation log.
- **Plan for the formal compliance statement.** A MISRA compliance claim for your product also needs a guideline enforcement plan, a guideline re-categorization plan, and deviation records (see *MISRA Compliance:2020*). NoxTLS supplies the library-side input to these, not the finished claim.

## Upgrading from 0.2.x

| Change | What to do |
|---|---|
| Text parameters and fields are `uint8_t` | Cast string literals at call sites. Read DN/SAN/time fields as `uint8_t` text. |
| Enums became `uint32_t` typedefs | Same constants and values. Remove any `enum` forward declarations of these types. |
| `noxtls_memory_compat.h` no longer remaps `malloc`/`free` | Call `noxtls_malloc()`/`noxtls_free()` (or `NOXTLS_MALLOC`) explicitly in code that relied on the remap. |
| `noxtls_debug_printf()` is a no-op by default | Configure with `-DNOXTLS_DEBUG_PRINTF_STDIO=ON` for host debugging. |
| File helpers can be compiled out | With `NOXTLS_HAVE_FILE_IO=0`, load certificates and keys from memory. |

See the [0.3.0 release notes](./release-notes.md) for the full list of changes in this release.
