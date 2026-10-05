# NoxTLS BT7 crypto reconciliation

Updated: 2026-10-05, America/Chicago (CDT). This report describes the reviewed merge candidate before its merge commit.

## Exact source history

- Worktree: `C:\NoxADK_work\NoxADK_thread\.codex-tmp\noxtls-bt7-reconciliation`.
- Branch: `merge/bluenox-bt7-crypto`.
- Validated parent: `ebc5a0fd3f3cacc312a9a1743efe572ac4d0fc5a`.
- Incoming parent: `508cc33cf36125abe06214c66bcd64f573bfb541`.
- Merge base: `3e6c69e6e47bc50496f66000d7277848343e8b47`.
- Incoming version header selects NoxTLS **0.2.71**. The versioned 0.2.70 release page remains historical; it must not be reverted to the incoming 0.2.60 text.
- This audit does not change the BlueNox validated dependency pin. Prior Nordic air results using `ebc5a0fd` do not certify this new NoxTLS candidate.

## Incoming functionality and preserved fixes

The genuinely new adapter work is NoxV SHA-256 and P-256 from `508cc33c`. The NoxV AES backend from `208b56e` is already in the validated parent. Ed25519 streaming verification from `96c18f1` is also already present there, together with later optimized field/group/scalar code, cached signing APIs and Cortex-M assembly selection guards. The reconciliation retains that implementation instead of reinstating the older verification kernel.

Current Nordic AES ROM tables (`ebc5a0fd`), ECB preemption handling (`3aa4ff8`), enabled-primitive keygen DRBG (`566c6f7`), direct CC310/CC312 P-256 selection, CRACEN result verification (`932bca6`), allocation failure diagnostics and compact P-256 memory options are preserved. TLS polling, nonblocking records, certificate-chain checks and PQ sources are preserved. Incoming SDK-nrfxlib/PSA CC310 additions would supersede the later direct Nordic backend under the same option; they are excluded from the reconciled candidate.

## All 15 original conflict decisions

Paths below are relative to the NoxTLS root. Decisions apply to inspected conflict hunks; surrounding incoming additions were checked separately.

| Conflicted path                                       | Reconciliation and reason                                                                              |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `docs/versioned_docs/version-0.2.70/release-notes.md` | Retain 0.2.70 release history; incoming erroneously restores 0.2.60 text.                              |
| `noxtls-lib/encryption/aes/noxtls_aes_cmac.c`         | Retain one streaming implementation; restore init setup dropped by automatic merge.                    |
| `noxtls-lib/pkc/CMakeLists.txt`                       | Keep direct Nordic/ESP backends and generic ECDH hook; select new NoxV P-256 port in its own slot.     |
| `noxtls-lib/pkc/ecc/noxtls_ecc.c`                     | Keep stack buffer, AES128-aware DRBG, stable diagnostics and compact math; merge gated timing helpers. |
| `noxtls-lib/pkc/ecc/noxtls_ecc.h`                     | Keep compact P-256 options; remove conflicting duplicate telemetry declaration; preserve `int` ABI.    |
| `noxtls-lib/pkc/ecdh/noxtls_ecdh.h`                   | Keep allocation failure diagnostic in addition to incoming detailed ECDH errors.                       |
| `noxtls-lib/pkc/ed25519/noxtls_ed25519.c`             | Keep optimized verification equation; streaming functions already present.                             |
| `noxtls-lib/pkc/ed25519/noxtls_ed25519.h`             | Preserve cached-keypair API plus existing streaming API.                                               |
| `noxtls-lib/pkc/rsa/noxtls_bignum.c`                  | Preserve allocation failure propagation and correct stack inverse cleanup.                             |
| `noxtls-lib/tls/noxtls_tls12.c`                       | Preserve later certificate-chain/bounds/Finished fixes; incoming unique commits add no TLS feature.    |
| `noxtls-lib/tls/noxtls_tls_common.c`                  | Preserve current nonblocking/overflow handling and balanced function closures.                         |
| `noxtls-lib/tls/noxtls_tls_record.c`                  | Preserve hardened record implementation and MAC/EtM initialization explanation.                        |
| `noxtls_common.h`                                     | Preserve WANT_READ/WANT_WRITE return codes and detailed ECDH diagnostics.                              |
| `ut/CMakeLists.txt`                                   | Keep TLS-linked diagnostic target; remove duplicate incoming target; add local runnable crypto gates.  |
| `ut/ecdh_diagnostic_test.c`                           | Keep current superset: DRBG selection, arbitrary-peer P-256 KAT and TLS provenance.                    |

## Defects found during validation

1. **NoxV SHA partial-batch fallback:** an accepted first block advanced the caller hash state before a later block timed out. Existing software fallback replayed the full batch from that advanced state. The real-port regression failed five checks before the fix; the adapter now publishes caller state only after the entire batch succeeds. Known independent 128/192-byte hashes, timeout, invalid result, continuation and IRQ restoration pass.
2. **Inherited packed Ed25519 conversion:** the exact `ebc5a0fd` baseline fails the packed-u32 versus limb diagnostic. The fast encoder packed balanced negative limbs without the canonical carry step. It now reuses the existing canonical encoder, preserving assembly entrypoints/ABI. Added 64 signed-limb conversion patterns, independent dense modular-product vectors, `(p-1)^2`, `(p-1)*(p-2)`, streaming verification and cached signing all pass. Cortex-M performance and hardware execution remain to be measured.
3. **Allocator gate packaging/routing:** the registered policy script was absent. Restored the known historical checker and made its routing model recognize only the verified, unconditional compatibility-header mapping. It scans whole-source tokens with mapping state at each source offset, including names separated from `(` by newlines. Negative fixtures reject conditional includes, later undef/redefine, guarded reinclusion and split-line unmapped calls; mapped split-line calls remain accepted and diagnostics preserve source line numbers. HMAC, TLS KDF and unified TLS now route their remaining standard names through NoxTLS. Actual GCC preprocessing and compiled-object symbol checks confirm all four maps and no raw allocator imports in those three objects.
4. **AES128-only fixture:** AES-GCM previously demanded a disabled AES256 KAT. Enabled-key-size known-answer tests remain mandatory; disabled key sizes must return NOT_SUPPORTED.
5. **Full PQ build:** Falcon-enabled certificate code called its static OID helper before its declaration. A gated forward declaration restores this build; no PQ primitive implementation is replaced.

## Validation matrix

Native compiler: GNU GCC 13.1.0, Ninja, Release `-O2`, Windows x64. No physical board is programmed by this matrix.

| Configuration                              | Evidence                                              | Result                                |
| ------------------------------------------ | ----------------------------------------------------- | ------------------------------------- |
| Exact validated `ebc5a0fd` baseline        | `baseline-ed25519-before.log`                         | Inherited packed conversion FAIL      |
| Default, TLS1.2/1.3, full classic crypto   | `default-final.log`                                   | Build PASS; CTest 10/10 PASS          |
| AES128 only, compact P-256, perf enabled   | `constrained-final.log`                               | Build PASS; CTest 10/10 PASS          |
| NoxV feature enabled                       | `noxv-production-final.log`                           | Actual adapter libraries build PASS   |
| All six configured PQ features enabled     | `pq-production-after.log`                             | Production build PASS                 |
| Actual NoxV ECC adapter with mocked MMIO   | Included in default/constrained tests                 | Success/error/timeout/fallback PASS   |
| Actual NoxV SHA adapter with mocked MMIO   | `sha-before.log`, `sha-after.log`, final CTest        | Reproduced FAIL; corrected PASS       |
| Actual allocator macros and object imports | `allocator-routing-proof.json`                        | Three corrected objects verified      |

The ten tests are P-256 regression, NoxV ECC adapter, NoxV SHA fallback, allocator policy, allocator checker negative fixtures, nonblocking TLS, detailed ECDH, Ed25519 RFC/field/streaming, AES-GCM NIST, and AES-CMAC RFC4493. CMAC runs all four RFC vectors at every two-chunk split, including empty chunks and finalization checks.

This is native functional and build evidence. It does not establish physical NoxV accelerator correctness, fresh Nordic firmware/air acceptance, PQ conformance suites, TLS peer interoperability or full PTS acceptance. Full PTS remains deferred.

## Reproduce

Run these PowerShell commands from the NoxTLS worktree. Use separate build directories for each configuration.

```powershell
$nativeArgs = @('-G', 'Ninja', '-DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe',
  '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_APPLICATIONS=OFF', '-DBUILD_TESTS=ON',
  '-DNOXTLS_BUILD_REGRESSION_TESTS=ON')
cmake -S . -B ../noxtls-bt7-audit-default @nativeArgs
cmake --build ../noxtls-bt7-audit-default --parallel 8
ctest --test-dir ../noxtls-bt7-audit-default --output-on-failure

cmake -S . -B ../noxtls-bt7-audit-constrained @nativeArgs `
  -DNOXTLS_CFG_FEATURE_AES_256=OFF -DNOXTLS_CFG_FEATURE_AES_192=OFF `
  -DNOXTLS_ECC_P256_FLASH_PRECOMPUTE=ON -DNOXTLS_ECC_P256_LOW_RAM_VERIFY=ON `
  -DNOXTLS_ECC_PERFORMANCE_DIAGNOSTICS=ON
cmake --build ../noxtls-bt7-audit-constrained --parallel 8
ctest --test-dir ../noxtls-bt7-audit-constrained --output-on-failure

cmake -S . -B ../noxtls-bt7-audit-noxv @nativeArgs `
  -DBUILD_TESTS=OFF -DNOXTLS_BUILD_REGRESSION_TESTS=OFF -DNOXTLS_CFG_FEATURE_NOXV_HW_ACCEL=ON
cmake --build ../noxtls-bt7-audit-noxv --target noxtls_hash noxtls_encryption noxtls_pkc --parallel 8

cmake -S . -B ../noxtls-bt7-audit-pq @nativeArgs `
  -DBUILD_TESTS=OFF -DNOXTLS_BUILD_REGRESSION_TESTS=OFF `
  -DNOXTLS_CFG_FEATURE_ML_KEM=ON -DNOXTLS_CFG_FEATURE_ML_DSA=ON `
  -DNOXTLS_CFG_FEATURE_SLH_DSA=ON -DNOXTLS_CFG_FEATURE_FALCON=ON `
  -DNOXTLS_CFG_FEATURE_LMS_HSS=ON -DNOXTLS_CFG_FEATURE_XMSS=ON
cmake --build ../noxtls-bt7-audit-pq --parallel 8
```

Do not run ordinary NoxV-enabled native applications against the default physical MMIO addresses. The adapter fixtures deliberately override the real ports' MMIO hooks; production-library compilation is a separate check.
