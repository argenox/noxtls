#!/usr/bin/env python3
"""Run the CodeNox MISRA C:2025 analyzer over the NoxTLS library.

Configures an Arm Cortex-M4 build of the library (all post-quantum features on,
so every library source is analyzed), exports its compilation database, probes
a CodeNox toolchain profile that matches the compile flags, and runs a full
project analysis.

Writes into --out-dir:
  codenox-results.json  raw CodeNox output (findings, coverage, audit)
  misra-summary.json    totals per category / rule / module (schema 1)
  misra-report.md       human-readable report
  codenox.yml, codenox-profile.json, compile_commands.json  the exact inputs

Exit codes: 0 gate passed, 1 findings fail the gate (the normal result while
findings exist), 2 configuration or input error, 3 analysis incomplete,
5 CodeNox not installed.

CodeNox findings are evidence for a MISRA assessment, not a compliance
certificate.
"""
import argparse
import collections
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CODENOX = "D:/codecnox/codenox/build/install/bin/codenox.exe"
DEFAULT_ARM_ROOT = "C:/ARM/arm-gnu-toolchain-14.2.rel1-mingw-w64-x86_64-arm-none-eabi"
PQ_FEATURES = ["ML_KEM", "ML_DSA", "FALCON", "SLH_DSA", "LMS_HSS", "XMSS"]
EXIT_NOT_INSTALLED = 5


def find_codenox(explicit):
    for cand in (explicit, os.environ.get("CODENOX"), DEFAULT_CODENOX, shutil.which("codenox")):
        if cand and Path(cand).is_file():
            return str(Path(cand))
    return None


def run(cmd, log, cwd=None):
    with open(log, "w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT, check=False)
    return proc.returncode


def git_commit():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True, check=True).stdout.strip()
        return out + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def split_command(cmd):
    if '"' not in cmd and "'" not in cmd:
        return cmd.split()
    return [tok.strip('"') for tok in shlex.split(cmd, posix=False)]


def prepare_compile_db(build_dir, out_dir):
    """Keep C sources only, use `arguments`, drop duplicate translation units."""
    entries = json.loads((build_dir / "compile_commands.json").read_text(encoding="utf-8"))
    seen = set()
    result = []
    for entry in entries:
        if not entry["file"].lower().endswith(".c"):
            continue
        key = os.path.normcase(os.path.abspath(entry["file"]))
        if key in seen:
            continue
        seen.add(key)
        args = entry.get("arguments") or split_command(entry["command"])
        result.append({"directory": entry["directory"], "file": entry["file"], "arguments": args})
    (out_dir / "compile_commands.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result


def flag_value(args, prefix, default):
    for arg in args:
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return default


def module_of(path):
    p = path.replace("\\", "/")
    m = re.search(r"noxtls-lib/([^/]+)/(?:([^/.]+)/)?", p)
    if not m:
        m2 = re.search(r"/(utility)/", p)
        return m2.group(1) if m2 else "other"
    return m.group(1) + ("/" + m.group(2) if m.group(2) else "")


def rule_key(rule_id):
    tail = rule_id.split(":")[-1]
    kind = 0 if tail.startswith("dir-") else 1
    nums = [int(x) for x in re.findall(r"\d+", tail)]
    return (kind, nums)


def rel_path(path):
    p = path.replace("\\", "/")
    root = ROOT.as_posix().rstrip("/") + "/"
    if p.lower().startswith(root.lower()):
        p = p[len(root):]
    return p


def baseline_key(f):
    """Line-independent identity of a finding class: category, confidence, rule and file."""
    return "|".join((f.get("category", "advisory"), f.get("confidence", "conclusive"),
                     f["ruleId"].split(":")[-1], rel_path(f.get("path", ""))))


def baseline_counts(findings):
    return dict(sorted(collections.Counter(baseline_key(f) for f in findings).items()))


def write_baseline(findings, path, commit, tool_version):
    doc = {"schema": 1, "tool": "CodeNox", "tool_version": tool_version, "noxtls_commit": commit,
           "description": "Accepted MISRA findings, counted per category|confidence|rule|file. The gate fails "
                          "when a conclusive Mandatory or Required count rises above its baseline.",
           "total": len(findings), "counts": baseline_counts(findings)}
    Path(path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


def compare_baseline(findings, baseline_path):
    base = json.loads(Path(baseline_path).read_text(encoding="utf-8"))["counts"]
    now = baseline_counts(findings)
    increases = []
    for key, n in now.items():
        b = base.get(key, 0)
        if n > b:
            cat, conf, rule, path = key.split("|", 3)
            increases.append({"category": cat, "confidence": conf, "rule": rule, "path": path,
                              "baseline": b, "now": n})
    new_total = sum(i["now"] - i["baseline"] for i in increases)
    gating = sum(i["now"] - i["baseline"] for i in increases
                 if i["category"] in ("mandatory", "required") and i["confidence"] == "conclusive")
    return {"new": new_total, "new_gating": gating, "baselined": len(findings) - new_total,
            "increases": sorted(increases, key=lambda i: (i["category"], i["rule"], i["path"]))}


def gate_exit(results, findings, cmp):
    if not results.get("analysisComplete"):
        return 3
    if cmp is not None:
        return 1 if cmp["new_gating"] else 0
    return 1 if any(f.get("category") in ("mandatory", "required") and f.get("confidence") == "conclusive"
                    for f in findings) else 0


def summarize(results, args, tool_version, exit_code, tu_count, notes, cmp=None):
    findings = results.get("findings", [])
    cats = ("mandatory", "required", "advisory")
    totals = {c: 0 for c in cats}
    conclusive = {c: 0 for c in cats}
    by_rule = collections.OrderedDict()
    by_module = collections.defaultdict(lambda: {c: 0 for c in cats})
    for f in findings:
        cat = f.get("category", "advisory")
        totals[cat] = totals.get(cat, 0) + 1
        if f.get("confidence") == "conclusive":
            conclusive[cat] = conclusive.get(cat, 0) + 1
        rid = f["ruleId"]
        entry = by_rule.setdefault(rid, {"rule": rid.split(":")[-1], "category": cat, "count": 0, "inconclusive": 0})
        entry["count"] += 1
        if f.get("confidence") != "conclusive":
            entry["inconclusive"] += 1
        by_module[module_of(f.get("path", ""))][cat] += 1
    coverage = collections.Counter(c.get("state", "unknown") for c in results.get("coverage", []))
    manual = sorted((c["guidelineId"].split(":")[-1] for c in results.get("coverage", [])
                     if c.get("state") == "manual-evidence-required"), key=lambda r: rule_key(r))
    rules = sorted(by_rule.values(), key=lambda r: (cats.index(r["category"]), -r["count"], rule_key(r["rule"])))
    modules = sorted(({"module": m, **v} for m, v in by_module.items()),
                     key=lambda m: (-(m["mandatory"] + m["required"]), m["module"]))
    return {
        "schema": 1,
        "performed": True,
        "tool": "CodeNox",
        "tool_version": tool_version,
        "tool_sha256": getattr(args, "tool_sha256", None),
        "standard": "MISRA C:2025",
        "target": args.target_desc,
        "noxtls_commit": git_commit(),
        "translation_units": tu_count,
        "analysis_complete": bool(results.get("analysisComplete")),
        "exit_code": exit_code,
        "totals": totals,
        "conclusive": conclusive,
        "by_rule": rules,
        "by_module": modules,
        "coverage": dict(coverage),
        "manual_evidence_required": manual,
        "deviations": deviation_record(findings, args.deviations),
        "baseline": {"used": cmp is not None,
                     "file": Path(args.baseline).name if cmp is not None else None,
                     "method": "counts per category|confidence|rule|file" if cmp is not None else None,
                     "new": cmp["new"] if cmp is not None else None,
                     "new_gating": cmp["new_gating"] if cmp is not None else None,
                     "baselined": cmp["baselined"] if cmp is not None else None,
                     "increases": cmp["increases"] if cmp is not None else []},
        "notes_markdown": notes,
    }


def deviation_record(findings, deviations_file):
    """Applied deviation permits: findings not in the 'active' compliance state."""
    states = collections.Counter(f.get("complianceState", "active") for f in findings)
    refs = []
    if deviations_file and Path(deviations_file).is_file():
        try:
            import yaml
            doc = yaml.safe_load(Path(deviations_file).read_text(encoding="utf-8")) or {}
            refs = sorted({str(d.get("reference")) for d in doc.get("deviations", []) if d.get("reference")})
        except Exception as exc:  # the record is informational; never fail the scan on it
            refs = [f"unreadable deviations file: {exc}"]
    return {
        "file": Path(deviations_file).name if deviations_file else None,
        "applied": sum(n for s, n in states.items() if s != "active"),
        "by_state": dict(states),
        "references": refs,
    }


def render_report(s):
    t = s["totals"]
    c = s["conclusive"]
    lines = [
        "# MISRA C:2025 analysis — NoxTLS library",
        "",
        f"- **Tool:** {s['tool']} {s['tool_version']}"
        + (f" (executable SHA-256 `{s['tool_sha256']}`)" if s.get("tool_sha256") else ""),
        f"- **Target:** {s['target']}",
        f"- **NoxTLS commit:** `{s['noxtls_commit']}`",
        f"- **Translation units analyzed:** {s['translation_units']}",
        f"- **Analysis complete:** {'yes' if s['analysis_complete'] else 'NO (results are partial)'}",
        f"- **Gate result (exit code {s['exit_code']}):** "
        + {0: "passed" + (" (no new Mandatory/Required findings against the baseline)" if s["baseline"]["used"] else ""),
           1: "failed (Mandatory/Required findings" + (" not in the baseline)" if s["baseline"]["used"] else ")"),
           3: "incomplete analysis"}.get(s["exit_code"], "error"),
        "",
        "These findings are evidence for a MISRA assessment. They are not a compliance certificate.",
        "Inconclusive findings come from undecidable rules and need review; they are not confirmed defects.",
        "",
        "## Totals",
        "",
        "| Category | Findings | Conclusive | Inconclusive |",
        "|---|---:|---:|---:|",
    ]
    for cat in ("mandatory", "required", "advisory"):
        lines.append(f"| {cat.capitalize()} | {t[cat]:,} | {c[cat]:,} | {t[cat] - c[cat]:,} |")
    if s["baseline"]["used"]:
        b = s["baseline"]
        lines += ["", f"Baseline `{b['file']}` (counts per category, confidence, rule and file): "
                  f"**{b['new']:,} finding(s) above the baseline**, of which {b['new_gating']:,} conclusive "
                  f"Mandatory/Required (these fail the gate); {b['baselined']:,} covered by the baseline. "
                  "Baselined findings remain open work and are listed in the tables above."]
        if b["increases"]:
            lines += ["", "| Category | Confidence | Rule | File | Baseline | Now |", "|---|---|---|---|---:|---:|"]
            for i in b["increases"]:
                lines.append(f"| {i['category']} | {i['confidence']} | {i['rule']} | {i['path']} | "
                             f"{i['baseline']} | {i['now']} |")
    lines += ["", "## Findings by rule", "", "| Rule | Category | Findings | Inconclusive |", "|---|---|---:|---:|"]
    for r in s["by_rule"]:
        lines.append(f"| {r['rule']} | {r['category']} | {r['count']:,} | {r['inconclusive']:,} |")
    lines += ["", "## Findings by module", "", "| Module | Mandatory | Required | Advisory |", "|---|---:|---:|---:|"]
    for m in s["by_module"]:
        lines.append(f"| {m['module']} | {m['mandatory']:,} | {m['required']:,} | {m['advisory']:,} |")
    lines += ["", "## Guideline coverage", "", "| State | Guidelines |", "|---|---:|"]
    for state, n in sorted(s["coverage"].items()):
        lines.append(f"| {state} | {n} |")
    d = s["deviations"]
    lines += ["", "## Deviations", ""]
    if d["applied"]:
        lines.append(f"{d['applied']:,} finding(s) are covered by deviation permits"
                     + (f" from `{d['file']}`" if d["file"] else "") + ": "
                     + ", ".join(f"{k} {v:,}" for k, v in sorted(d["by_state"].items()) if k != "active") + ".")
        if d["references"]:
            lines.append("Permit references: " + ", ".join(d["references"]) + ".")
    else:
        lines.append("No deviation permits are applied" + (f" (deviations file `{d['file']}`)." if d["file"] else "."))
    if s["manual_evidence_required"]:
        lines += ["", "Guidelines that need manual evidence (not decided by the tool): "
                  + ", ".join(s["manual_evidence_required"]) + "."]
    if s["notes_markdown"].strip():
        lines += ["", "## Analyst notes", "", s["notes_markdown"].strip()]
    return "\n".join(lines) + "\n"


def write_not_performed(out_dir, reason):
    summary = {"schema": 1, "performed": False, "tool": "CodeNox", "tool_version": None,
               "standard": "MISRA C:2025", "noxtls_commit": git_commit(), "analysis_complete": False,
               "exit_code": EXIT_NOT_INSTALLED, "reason": reason}
    (out_dir / "misra-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    (out_dir / "misra-report.md").write_text(
        f"# MISRA C:2025 analysis — NoxTLS library\n\nMISRA analysis was **not performed**: {reason}\n",
        encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--codenox", help="codenox executable (default: $CODENOX or %s)" % DEFAULT_CODENOX)
    ap.add_argument("--build-dir", help="CMake build directory (default: <out-dir>/build)")
    ap.add_argument("--toolchain-root", default=os.environ.get("ARM_GNU_TOOLCHAIN_ROOT", DEFAULT_ARM_ROOT))
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--baseline", default=str(ROOT / "misra" / "misra-baseline.json"),
                    help="accepted-findings baseline (counts per category|confidence|rule|file); the gate fails "
                         "only when a conclusive Mandatory/Required count rises above it "
                         "(default: misra/misra-baseline.json)")
    ap.add_argument("--no-baseline", action="store_true", help="gate on every finding, ignoring the baseline")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="after the analysis, write a baseline of the current findings to FILE "
                         "(the project owner approves baseline changes)")
    ap.add_argument("--results", metavar="FILE",
                    help="re-evaluate an existing codenox-results.json instead of running the analysis")
    ap.add_argument("--deviations", help="CodeNox deviations file (.codenox-deviations.yml)")
    ap.add_argument("--notes", default=str(ROOT / "misra" / "analysis-notes.md"),
                    help="Markdown analyst notes included in the report")
    ap.add_argument("--no-build", action="store_true", help="configure only; do not compile the library")
    ap.add_argument("--cmake-arg", action="append", default=[], help="extra -D option for the library build")
    args = ap.parse_args()

    if args.no_baseline or not Path(args.baseline).is_file():
        args.baseline = None
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    build_dir = Path(args.build_dir).resolve() if args.build_dir else out_dir / "build"

    if args.results:
        results = json.loads(Path(args.results).read_text(encoding="utf-8"))
        cc = Path(args.results).parent / "compile_commands.json"
        tu_count = len(json.loads(cc.read_text(encoding="utf-8"))) if cc.is_file() else 0
        found = find_codenox(args.codenox)
        tool_version = "unknown"
        if found:
            tool_version = re.sub(r"^CodeNox\s+", "", subprocess.run([found, "--version"], capture_output=True,
                                                                       text=True).stdout.strip())
            args.tool_sha256 = hashlib.sha256(Path(found).read_bytes()).hexdigest()
        args.target_desc = f"re-evaluated from {Path(args.results).name}"
        return finish(args, out_dir, results, tool_version, tu_count)

    codenox = find_codenox(args.codenox)
    if not codenox:
        write_not_performed(out_dir, "the CodeNox analyzer is not installed on this machine")
        print("CodeNox not found; MISRA analysis not performed", file=sys.stderr)
        return EXIT_NOT_INSTALLED
    tool_version = subprocess.run([codenox, "--version"], capture_output=True, text=True).stdout.strip()
    tool_version = re.sub(r"^CodeNox\s+", "", tool_version)
    args.tool_sha256 = hashlib.sha256(Path(codenox).read_bytes()).hexdigest()

    tc_root = Path(args.toolchain_root)
    gcc = tc_root / "bin" / ("arm-none-eabi-gcc.exe" if os.name == "nt" else "arm-none-eabi-gcc")
    if not gcc.is_file():
        found = shutil.which("arm-none-eabi-gcc")
        if not found:
            print("arm-none-eabi-gcc not found; set --toolchain-root", file=sys.stderr)
            return 2
        gcc = Path(found)
        tc_root = gcc.parent.parent

    cmake_cmd = ["cmake", "-S", str(ROOT), "-B", str(build_dir), "-G", "Ninja",
                 f"-DCMAKE_TOOLCHAIN_FILE={ROOT / 'cmake/toolchains/arm-none-eabi.cmake'}",
                 f"-DARM_GNU_TOOLCHAIN_ROOT={tc_root.as_posix()}",
                 "-DCMAKE_C_FLAGS=-mcpu=cortex-m4 -mthumb -mfloat-abi=soft",
                 "-DCMAKE_BUILD_TYPE=MinSizeRel", "-DBUILD_TESTS=OFF", "-DBUILD_APPLICATIONS=OFF",
                 "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
    cmake_cmd += [f"-DNOXTLS_CFG_FEATURE_{f}=ON" for f in PQ_FEATURES] + args.cmake_arg
    if run(cmake_cmd, out_dir / "cmake-configure.log") != 0:
        print("CMake configure failed; see cmake-configure.log", file=sys.stderr)
        return 2
    if not args.no_build and run(["cmake", "--build", str(build_dir), "-j", str(args.jobs)],
                                 out_dir / "cmake-build.log") != 0:
        print("Library build failed; see cmake-build.log", file=sys.stderr)
        return 2

    entries = prepare_compile_db(build_dir, out_dir)
    first = entries[0]["arguments"]
    std = flag_value(first, "-std=", "gnu99")
    cpu = flag_value(first, "-mcpu=", "cortex-m4")
    float_abi = flag_value(first, "-mfloat-abi=", "soft")
    environment = "freestanding" if "-ffreestanding" in first else "hosted"
    args.target_desc = f"{cpu}, arm-gnu-14.2, -std={std}, float ABI {float_abi}, {environment}, all PQ features on"
    profile = out_dir / "codenox-profile.json"
    probe = [codenox, "toolchain", "probe", "--compiler", first[0], "--adapter", "arm-gnu-14.2", "--cpu", cpu,
             "--float-abi", float_abi, "--std", std, "--environment", environment, "--output", str(profile)]
    if run(probe, out_dir / "codenox-probe.log") != 0:
        print("CodeNox toolchain probe failed; see codenox-probe.log", file=sys.stderr)
        return 2

    cfg = [
        "schema_version: 1",
        "standard: misra-c-2025",
        f"project_root: {ROOT.as_posix()}",
        f"jobs: {args.jobs}",
    ]
    if args.deviations:
        cfg.append(f"deviations: {Path(args.deviations).resolve().as_posix()}")
    cfg += [
        "targets:",
        "  m4:",
        f"    compilation_database: {(out_dir / 'compile_commands.json').as_posix()}",
        "    compiler_adapter: arm-gnu-14.2",
        f"    toolchain_profile: {profile.as_posix()}",
        "source:",
        "  project_roots:",
        "    - .",
        "  vendor_roots:",
        "    - noxtls-lib/vendor",
        "analysis:",
        "  timeout_seconds: 600",
        "  memory_limit_mib: 4096",
        f"  cache_directory: {(build_dir / '.codenox-cache').as_posix()}",
        "policy:",
        "  fail_mandatory: true",
        "  fail_required: true",
        "  fail_advisory: false",
        "  fail_inconclusive: false",
        "  fail_incomplete: true",
    ]
    cfg_path = out_dir / "codenox.yml"
    cfg_path.write_text("\n".join(cfg) + "\n", encoding="utf-8")
    if run([codenox, "config", "validate", str(cfg_path)], out_dir / "codenox-config.log") != 0:
        print("CodeNox rejected the configuration; see codenox-config.log", file=sys.stderr)
        return 2

    results_path = out_dir / "codenox-results.json"
    code = run([codenox, "analyze", "-p", str(out_dir), "--target", "m4", "--config", str(cfg_path),
                "--format", "json", "--output", str(results_path)], out_dir / "codenox-analyze.log")
    if code in (2, 4) or not results_path.is_file():
        print(f"CodeNox analysis failed (exit {code}); see codenox-analyze.log", file=sys.stderr)
        return 2
    results = json.loads(results_path.read_text(encoding="utf-8"))
    return finish(args, out_dir, results, tool_version, len(entries))


def finish(args, out_dir, results, tool_version, tu_count):
    """Gate against the baseline, write summary and report. CodeNox's own exit code is not used for the
    gate: its baseline fingerprints shift with line numbers when identical findings share a function."""
    findings = results.get("findings", [])
    cmp = compare_baseline(findings, args.baseline) if args.baseline else None
    code = gate_exit(results, findings, cmp)
    notes_path = Path(args.notes)
    notes = notes_path.read_text(encoding="utf-8") if notes_path.is_file() else ""
    summary = summarize(results, args, tool_version, code, tu_count, notes, cmp)
    if args.write_baseline:
        write_baseline(findings, args.write_baseline, summary["noxtls_commit"], tool_version)
        print(f"Wrote baseline {args.write_baseline} ({len(findings)} findings)")
    (out_dir / "misra-summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    (out_dir / "misra-report.md").write_text(render_report(summary), encoding="utf-8")
    t = summary["totals"]
    print(f"MISRA C:2025 ({tool_version}): {tu_count} TUs, complete={summary['analysis_complete']}, "
          f"mandatory={t['mandatory']} required={t['required']} advisory={t['advisory']} (exit {code})")
    print(f"Report: {out_dir / 'misra-report.md'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
