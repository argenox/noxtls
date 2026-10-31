Notes kept by the NoxTLS maintainers next to the automated scan. Update them when the code, the analyzer or the assessment changes.

### Baseline

`misra/misra-baseline.json` was regenerated on 2026-10-24 from the 0.3.15 scan (PR #58) with CodeNox 0.2.1. It holds 4,145 findings: 28 Mandatory, 940 Required and 3,177 Advisory, counted per category, confidence, rule and file. The gate fails only when a conclusive Mandatory or Required count rises above the baseline. The baselined findings remain open and are counted in every report.

The first baseline (an earlier tree of PR #58, CodeNox 0.2.0, 5,060 findings) included about 935 Rule 5.3 false positives; see below.

### Scope

- **What is analyzed:** every library source (`noxtls-lib/`, `utility/`) compiled for an Arm Cortex-M4 build with all post-quantum features enabled.
- **What is not analyzed:**
  - vendor SDK code under `noxtls-lib/vendor/`;
  - optional hardware back ends that this configuration does not compile;
  - applications, unit tests and host tools.
- **Features off in this configuration:** EC-JPAKE, SPAKE2+, PBKDF2, Ed448, MD4 and TLS 1.0/1.1 are off by default, so their sources are only partly covered.

### Fixed analyzer issue: Rule 5.3 false positives (CodeNox 0.2.0, fixed in 0.2.1)

- **The defect.** CodeNox 0.2.0 treats parameter names declared inside a function-pointer type (a `typedef` or a struct member, which only have function-prototype scope) as if they were file-scope identifiers. Every later parameter with the same name is then reported as hiding it.
- **Reproduction:** a header containing `typedef int32_t (*cb_t)(const int32_t *ctx, int32_t n);` followed by `int32_t f(const int32_t *ctx, int32_t n);` reports Rule 5.3 on `f`'s parameters.
- **Effect in NoxTLS.** The function-pointer types in `noxtls-lib/tls/noxtls_dtls_common.h` (and similar callback types) name parameters `ctx`, `type`, `in`, `in_len`, `out`, `out_len`, `epoch`, `inner`, `length` and `sequence`. This accounted for about 935 of the 947 Rule 5.3 findings in the first 0.3.15 scan.
- **Real findings.** The 12 Rule 5.3 findings that remain are genuine: parameters named `index`, `y0`, `y1` and `j1` hide the C library functions of the same name (`<strings.h>` and `<math.h>` under `-std=gnu99`), in `noxtls_x509.c`/`.h`, `noxtls_falcon_internal.c` and `noxtls_tls_common.c`.
- **Status:** fixed in CodeNox 0.2.1, which gives function-type parameters their own prototype scope. Rule 5.3 went from 947 findings to 12. CodeNox 0.2.1 also tells colliding fingerprints apart by order instead of by line and column, so they no longer change when unrelated lines move.

### Mandatory findings

All Mandatory findings in the 0.3.15 scan are *inconclusive*:

- **Rule 21.18:** string or memory operation sizes that could not be proven valid for every object, mostly in Falcon.
- **Rule 22.2:** a release of storage that could not be proven dynamically allocated, in the allocator implementation.

Each one needs a manual review record. None is yet confirmed as a defect.
