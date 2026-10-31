# MISRA C:2025 checking

NoxTLS is checked against MISRA C:2025 with the CodeNox analyzer. The scan covers every library source in an Arm Cortex-M4 build (arm-gnu 14.2, `-std=gnu99`, all post-quantum features enabled). The findings are evidence for a MISRA assessment, not a compliance certificate.

## Run it

```sh
python scripts/misra/run_codenox.py --out-dir build/misra
```

- **Requirements:** CodeNox (`--codenox <exe>`, `$CODENOX`, or the default `D:/codecnox/codenox/build/install/bin/codenox.exe`) and the Arm GNU toolchain (`--toolchain-root` or `$ARM_GNU_TOOLCHAIN_ROOT`).
- **Run time:** a first run takes about 10–15 minutes. Later runs reuse the CodeNox cache in `<out-dir>/build/.codenox-cache` and only re-analyze changed files.

Outputs in `--out-dir`:

| File | Content |
|---|---|
| `misra-report.md` | Human-readable report: totals, findings by rule and module, guideline coverage, analyst notes |
| `misra-summary.json` | The same data, machine-readable (schema 1); `noxtls-oem` release packages read it |
| `codenox-results.json` | Raw CodeNox output, with every finding and its location |
| `codenox.yml`, `codenox-profile.json`, `compile_commands.json` | The exact analysis inputs, kept as a record |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Policy gate passed: no conclusive Mandatory or Required count above the baseline |
| 1 | A conclusive Mandatory or Required count rose above the baseline, or any such finding with `--no-baseline` |
| 2 | Configuration or build error |
| 3 | Analysis incomplete |
| 5 | CodeNox not installed |

## As a test

Configure with `-DNOXTLS_MISRA_CHECK=ON` to register the `misra_codenox` ctest (label `misra`, so run it with `ctest -L misra`). The test is skipped when CodeNox is not installed. It fails when a conclusive Mandatory or Required count rises above the baseline. Set `-DNOXTLS_MISRA_BASELINE=` (empty) to gate on every finding.

## Baseline

`misra/misra-baseline.json` records the findings of the 0.3.15 scan (PR #58) with CodeNox 0.2.1: 4,145 findings (28 Mandatory, 940 Required, 3,177 Advisory). It stores finding **counts per category, confidence, rule and file**. The gate fails when a conclusive Mandatory or Required count rises above the baseline, so every change is checked without first clearing the existing debt.

- **Why counts, not CodeNox fingerprints.** CodeNox's own baseline matches fingerprints. Before 0.2.1, CodeNox told several identical findings in one function apart by line and column, so an unrelated edit higher in the file made hundreds of baselined findings look new. 0.2.1 orders them instead, but the fingerprints still include the enclosing symbol and token context. Counts per rule and file do not depend on any of these.
- **Trade-off.** A new finding that replaces a fixed one of the same rule in the same file is not flagged. The full findings list in every report still shows it.
- **Baselined findings are still open work.** They stay in every report, with their counts, and the release MISRA report shows them.
- **Using it.** The script uses the baseline by default; `--no-baseline` shows the full gate. Each report lists every (rule, file) whose count went above the baseline.
- **Shrinking it.** When findings are fixed, regenerate the baseline from a fresh scan so it only shrinks:

  ```sh
  python scripts/misra/run_codenox.py --out-dir build/misra --no-baseline --write-baseline misra/misra-baseline.json
  ```

  Review the diff: counts should go down, never up. Raising a count to make the gate pass needs the same approval as a deviation.
- **Re-checking an existing scan.** `--results <dir>/codenox-results.json` re-runs the gate and the report without re-analysing.
- **Analyzer updates.** After a CodeNox upgrade, re-scan and regenerate the baseline, and record the tool version in `analysis-notes.md`. The 0.2.1 upgrade removed about 935 Rule 5.3 false positives (5,060 to 4,145 findings). Each report records the CodeNox version and the SHA-256 of its executable.

## Keeping it clean over time

1. **Fix findings in the code first.** Do not add suppressions casually.
2. **Deviations need approval.** A deviation (an inline `codenox: deviate` comment, or a record in a deviations file passed with `--deviations`) needs a written rationale and approval from the project owner. Mandatory rules cannot be deviated.
3. **Keep the baseline shrinking.** See [Baseline](#baseline): regenerate it after fixes, and never grow it without approval.
4. **Record the assessment.** Keep `misra/analysis-notes.md` up to date. The report includes it, so the human assessment (scope, known analyzer issues, reviews of inconclusive findings) travels with every scan.
