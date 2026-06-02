#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""
Generate RTOS port Kconfig and CMake mapping from noxtls_config_catalog.xml.

Outputs Zephyr (ports/zephyr) and ESP-IDF (ports/esp-idf) integration files.

Usage:
  python generate_kconfig.py
  python generate_kconfig.py --check
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
NOXTLS_ROOT = SCRIPT_DIR.parent.parent
CATALOG_XML = NOXTLS_ROOT / "noxtls_config_catalog.xml"
GENERATOR_REL = "noxtls/tools/kconfig_gen/generate_kconfig.py"

SKIP_CATEGORY_IDS = frozenset({"profiles", "sidechannel"})
SKIP_SETTING_IDS = frozenset(
    {
        "NOXTLS_CT_COMPARE",
    }
)

# Root CMake maps these via NOXTLS_CFG_* / noxtls_define_bool (see noxtls/CMakeLists.txt).
CMAKE_BOOL_CACHE_VARS: frozenset[str] = frozenset(
    {
        "NOXTLS_FEATURE_HASH",
        "NOXTLS_FEATURE_HMAC",
        "NOXTLS_FEATURE_HKDF",
        "NOXTLS_FEATURE_ENCRYPTION",
        "NOXTLS_FEATURE_DRBG",
        "NOXTLS_FEATURE_PKC",
        "NOXTLS_FEATURE_CERT",
        "NOXTLS_FEATURE_TLS",
        "NOXTLS_FEATURE_TLS10",
        "NOXTLS_FEATURE_TLS11",
        "NOXTLS_FEATURE_TLS12",
        "NOXTLS_FEATURE_TLS13",
        "NOXTLS_FEATURE_DTLS",
        "NOXTLS_HAVE_CERT_WRITE",
        "NOXTLS_FEATURE_MD4",
        "NOXTLS_FEATURE_MD5",
        "NOXTLS_FEATURE_SHA1",
        "NOXTLS_FEATURE_SHA224",
        "NOXTLS_FEATURE_SHA256",
        "NOXTLS_FEATURE_SHA384",
        "NOXTLS_FEATURE_SHA512",
        "NOXTLS_FEATURE_SHA3",
        "NOXTLS_FEATURE_RIPEMD160",
        "NOXTLS_FEATURE_BLAKE2",
        "NOXTLS_FEATURE_AES",
        "NOXTLS_FEATURE_AES_128",
        "NOXTLS_FEATURE_AES_192",
        "NOXTLS_FEATURE_AES_256",
        "NOXTLS_FEATURE_AES_ECB",
        "NOXTLS_FEATURE_AES_CBC",
        "NOXTLS_FEATURE_AES_CTR",
        "NOXTLS_FEATURE_AES_CFB",
        "NOXTLS_FEATURE_AES_OFB",
        "NOXTLS_FEATURE_AES_XTS",
        "NOXTLS_FEATURE_AES_GCM",
        "NOXTLS_FEATURE_AES_CCM",
        "NOXTLS_FEATURE_AES_CMAC",
        "NOXTLS_FEATURE_AES_ACCEL_NI",
        "NOXTLS_FEATURE_AES_ACCEL_APPLE",
        "NOXTLS_FEATURE_ARIA",
        "NOXTLS_FEATURE_CAMELLIA",
        "NOXTLS_FEATURE_CHACHA20_POLY1305",
        "NOXTLS_FEATURE_DES",
        "NOXTLS_FEATURE_RC4",
        "NOXTLS_FEATURE_RSA",
        "NOXTLS_FEATURE_ECC",
        "NOXTLS_FEATURE_ECDSA",
        "NOXTLS_FEATURE_ECDH",
        "NOXTLS_FEATURE_DH",
        "NOXTLS_FEATURE_X25519",
        "NOXTLS_FEATURE_X448",
        "NOXTLS_FEATURE_ED25519",
        "NOXTLS_FEATURE_ED448",
        "NOXTLS_FEATURE_DSA",
        "NOXTLS_FEATURE_ML_KEM",
        "NOXTLS_FEATURE_ML_DSA",
        "NOXTLS_FEATURE_SLH_DSA",
        "NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES",
    }
)

EXPR_RE = re.compile(r"\(\s*(\d+)\s*\*\s*(\d+)\s*\)")

BUFFER_SETTING_IDS: tuple[str, ...] = (
    "NOXTLS_TLS_MAX_RECORD_SIZE",
    "NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH",
    "NOXTLS_TLS_MAX_HANDSHAKE_SIZE",
    "NOXTLS_MAX_CERT_SIZE",
    "NOXTLS_MAX_CERT_CHAIN_DEPTH",
    "NOXTLS_STATIC_BUFFER_SIZE",
)

INT_METADATA: dict[str, dict[str, object]] = {
    "NOXTLS_TLS_MAX_RECORD_SIZE": {
        "prompt": "Max TLS record payload size (bytes)",
        "range": (256, 16384),
    },
    "NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH": {
        "prompt": "Max TLS wire record length (bytes)",
        "range": (256, 65535),
    },
    "NOXTLS_TLS_MAX_HANDSHAKE_SIZE": {
        "prompt": "Max TLS handshake message size (bytes)",
        "range": (256, 65536),
    },
    "NOXTLS_MAX_CERT_SIZE": {
        "prompt": "Max single X.509 certificate size (bytes)",
        "range": (256, 65536),
    },
    "NOXTLS_MAX_CERT_CHAIN_DEPTH": {
        "prompt": "Max X.509 certificate chain depth",
        "range": (1, 64),
    },
    "NOXTLS_STATIC_BUFFER_SIZE": {
        "prompt": "Static allocator pool size (bytes)",
        "range": (1024, 1048576),
    },
    "NOXTLS_RSA_MAX_PRIME_ATTEMPTS": {
        "prompt": "RSA: max prime generation attempts",
        "range": (1000, 1000000),
    },
    "NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL": {
        "prompt": "RSA: Miller-Rabin iterations (small primes)",
        "range": (1, 32),
    },
    "NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE": {
        "prompt": "RSA: Miller-Rabin iterations (large primes)",
        "range": (1, 64),
    },
    "NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS": {
        "prompt": "RSA: small-prime size threshold (bits)",
        "range": (64, 4096),
    },
    "NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL": {
        "prompt": "RSA: debug progress interval (0=off)",
        "range": (0, 100000),
    },
    "NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL": {
        "prompt": "RSA: debug primality interval (0=off)",
        "range": (0, 100000),
    },
    "NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL": {
        "prompt": "RSA: debug rejected-candidate interval (0=off)",
        "range": (0, 100000),
    },
    "NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS": {
        "prompt": "RSA: debug rejected-candidate max attempts",
        "range": (0, 100000),
    },
    "NOXTLS_ECC_POINT_MUL_WINDOW_SIZE": {
        "prompt": "ECC: point-multiplication window size (0=Montgomery only)",
        "range": (0, 8),
    },
}


@dataclass(frozen=True)
class PortOutput:
    name: str
    flavor: str
    kconfig_out: Path
    cmake_out: Path


PORTS: tuple[PortOutput, ...] = (
    PortOutput(
        name="zephyr",
        flavor="zephyr",
        kconfig_out=NOXTLS_ROOT / "ports" / "zephyr" / "Kconfig.noxtls.generated",
        cmake_out=NOXTLS_ROOT / "ports" / "zephyr" / "noxtls_zephyr_kconfig.cmake",
    ),
    PortOutput(
        name="esp-idf",
        flavor="esp-idf",
        kconfig_out=NOXTLS_ROOT / "ports" / "esp-idf" / "Kconfig.noxtls.generated",
        cmake_out=NOXTLS_ROOT / "ports" / "esp-idf" / "noxtls_esp_idf_kconfig.cmake",
    ),
)

GENERATOR_TS_RE = re.compile(r"^# Generator: .+ \(([^)]+)\)$", re.MULTILINE)


@dataclass
class Setting:
    id: str
    name: str
    type: str
    default: str
    default_value: str | None
    legacy: bool
    description: str
    depends: list[tuple[str, str]] = field(default_factory=list)


def macro_to_cmake_cache(macro_id: str) -> str | None:
    if macro_id in CMAKE_BOOL_CACHE_VARS:
        if macro_id.startswith("NOXTLS_FEATURE_"):
            return "NOXTLS_CFG_" + macro_id[len("NOXTLS_") :]
        if macro_id == "NOXTLS_HAVE_CERT_WRITE":
            return "NOXTLS_CFG_HAVE_CERT_WRITE"
        if macro_id == "NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES":
            return "NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES"
    return None


def should_skip_setting(setting_id: str, setting_type: str) -> bool:
    if setting_id in SKIP_SETTING_IDS:
        return True
    if setting_type == "profile":
        return True
    if setting_id.startswith("NOXTLS_PROFILE_"):
        return True
    if setting_id.startswith("NOXTLS_SIDECHANNEL_PROFILE_"):
        return True
    return False


def parse_int_default(raw: str) -> str:
    raw = raw.strip()
    m = EXPR_RE.fullmatch(raw)
    if m:
        return str(int(m.group(1)) * int(m.group(2)))
    if raw.isdigit():
        return raw
    return raw


def kconfig_bool_default(default: str, default_value: str | None) -> str:
    if default_value in ("0", "1"):
        return "y" if default_value == "1" else "n"
    if default == "enabled":
        return "y"
    if default == "disabled":
        return "n"
    return "y"


def escape_kconfig_help(text: str) -> str:
    text = text.replace("&quot;", '"').replace("&gt;", ">").replace("&lt;", "<")
    text = text.replace('"', '\\"')
    return text.strip()


def collect_dependencies(elem: ET.Element) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    deps_elem = elem.find("dependencies")
    if deps_elem is None:
        return deps
    for allof in deps_elem.findall("allOf"):
        for dep in allof.findall("dependency"):
            ref = dep.attrib.get("ref", "")
            value = dep.attrib.get("value", "1")
            if ref:
                deps.append((ref, value))
    return deps


def parse_setting(elem: ET.Element) -> Setting | None:
    setting_id = elem.attrib.get("id", "")
    setting_type = elem.attrib.get("type", "boolean")
    if should_skip_setting(setting_id, setting_type):
        return None
    desc_elem = elem.find("description")
    description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
    return Setting(
        id=setting_id,
        name=elem.attrib.get("name", setting_id),
        type=setting_type,
        default=elem.attrib.get("default", ""),
        default_value=elem.attrib.get("default-value"),
        legacy=elem.attrib.get("legacy", "false") == "true",
        description=description,
        depends=collect_dependencies(elem),
    )


def walk_settings(parent: ET.Element, out: list[Setting]) -> None:
    for child in parent:
        if child.tag == "setting":
            s = parse_setting(child)
            if s is not None:
                out.append(s)
            sub = child.find("suboptions")
            if sub is not None:
                walk_settings(sub, out)
        elif child.tag == "suboptions":
            walk_settings(child, out)


def emit_kconfig_setting(s: Setting, indent: str) -> list[str]:
    lines: list[str] = []
    sym = s.id
    if s.type == "boolean":
        default_line = kconfig_bool_default(s.default, s.default_value)
        lines.append(f'{indent}config {sym}')
        lines.append(f'{indent}\tbool "{s.name}"')
        if s.legacy:
            lines.append(f'{indent}\t# legacy algorithm / option')
        lines.append(f'{indent}\tdefault {default_line}')
        for ref, value in s.depends:
            if value == "1":
                lines.append(f"{indent}\tdepends on {ref}")
            else:
                lines.append(f"{indent}\tdepends on !{ref}")
        if s.description:
            lines.append(f'{indent}\thelp')
            for part in s.description.split("\n"):
                part = part.strip()
                if part:
                    lines.append(f'{indent}\t  {escape_kconfig_help(part)}')
        lines.append("")
    elif s.type == "integer":
        default_line = parse_int_default(s.default)
        meta = INT_METADATA.get(s.id, {})
        prompt = meta.get("prompt", s.name)
        lines.append(f'{indent}config {sym}')
        lines.append(f'{indent}\tint "{prompt}"')
        if default_line.isdigit():
            lines.append(f"{indent}\tdefault {default_line}")
        rng = meta.get("range")
        if isinstance(rng, tuple) and len(rng) == 2:
            lines.append(f"{indent}\trange {rng[0]} {rng[1]}")
        for ref, value in s.depends:
            if value == "1":
                lines.append(f"{indent}\tdepends on {ref}")
        if s.description:
            lines.append(f'{indent}\thelp')
            for part in s.description.split("\n"):
                part = part.strip()
                if part:
                    lines.append(f'{indent}\t  {escape_kconfig_help(part)}')
        lines.append("")
    return lines


def generate_kconfig(catalog: ET.Element, ts: str) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Generated from noxtls_config_catalog.xml — do not edit by hand.",
        f"# Generator: {GENERATOR_REL} ({ts})",
        "",
        'menu "NoxTLS library options (from noxtls_config.h)"',
        "",
    ]
    categories = catalog.find("categories")
    if categories is None:
        return "\n".join(lines) + "\n"

    all_settings: list[Setting] = []
    by_category: list[tuple[str, list[Setting]]] = []
    for category in categories.findall("category"):
        cat_id = category.attrib.get("id", "")
        cat_name = category.attrib.get("name", cat_id).strip()
        if cat_id in SKIP_CATEGORY_IDS:
            continue
        settings: list[Setting] = []
        walk_settings(category, settings)
        if not settings:
            continue
        by_category.append((cat_name or "Other", settings))
        all_settings.extend(settings)

    int_settings: list[Setting] = [s for s in all_settings if s.type == "integer"]
    int_ids = {s.id for s in int_settings}

    if int_settings:
        ordered: list[Setting] = []
        seen: set[str] = set()
        by_id = {s.id: s for s in int_settings}
        for sid in BUFFER_SETTING_IDS:
            if sid in by_id and sid not in seen:
                ordered.append(by_id[sid])
                seen.add(sid)
        for s in sorted(int_settings, key=lambda x: x.id):
            if s.id not in seen:
                ordered.append(s)
                seen.add(s.id)

        lines.append('\tmenu "Buffer sizes and limits (RAM tuning)"')
        lines.append('\t\tcomment "Reduce these to lower RAM/stack usage on constrained targets."')
        lines.append("")
        for s in ordered:
            lines.extend(emit_kconfig_setting(s, "\t\t"))
        lines.append("\tendmenu")
        lines.append("")

    for menu_title, settings in by_category:
        feature_settings = [s for s in settings if s.id not in int_ids]
        if not feature_settings:
            continue
        lines.append(f'\tmenu "{menu_title}"')
        for s in feature_settings:
            lines.extend(emit_kconfig_setting(s, "\t\t"))
        lines.append("\tendmenu")
        lines.append("")

    lines.append("endmenu")
    lines.append("")
    return "\n".join(lines)


def generate_cmake(settings: list[Setting], flavor: str, ts: str) -> str:
    if flavor == "zephyr":
        map_macro = "noxtls_zephyr_map_bool"
        compile_def = lambda sym, val: f"zephyr_compile_definitions({sym}={val})"
    elif flavor == "esp-idf":
        map_macro = "noxtls_esp_idf_map_bool"
        compile_def = lambda sym, val: (
            f"target_compile_definitions(${{COMPONENT_LIB}} PUBLIC {sym}={val})"
        )
    else:
        raise ValueError(f"unknown flavor: {flavor}")

    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Generated from noxtls_config_catalog.xml — do not edit by hand.",
        f"# Generator: {GENERATOR_REL} ({ts})",
        "",
        "if(NOT CONFIG_NOXTLS)",
        "  return()",
        "endif()",
        "",
        f"macro({map_macro} kconfig_sym cache_var)",
        "  if(DEFINED ${kconfig_sym} AND ${kconfig_sym})",
        "    set(${cache_var} ON CACHE BOOL \"\" FORCE)",
        "  else()",
        "    set(${cache_var} OFF CACHE BOOL \"\" FORCE)",
        "  endif()",
        "endmacro()",
        "",
    ]

    cache_mapped: list[Setting] = []
    header_bools: list[Setting] = []
    header_ints: list[Setting] = []

    for s in sorted(settings, key=lambda x: x.id):
        cache_var = macro_to_cmake_cache(s.id)
        if s.type == "boolean":
            if cache_var is not None:
                cache_mapped.append(s)
            else:
                header_bools.append(s)
        elif s.type == "integer":
            header_ints.append(s)

    lines.append("# --- CMake cache variables (control which sources are built) ---")
    for s in cache_mapped:
        cache_var = macro_to_cmake_cache(s.id)
        assert cache_var is not None
        lines.append(f"{map_macro}(CONFIG_{s.id} {cache_var})")
    lines.append("")

    lines.append("# --- Preprocessor definitions (noxtls_config.h tunables) ---")
    for s in header_bools:
        lines.append(f"if(CONFIG_{s.id})")
        lines.append(f"  {compile_def(s.id, 1)}")
        lines.append("else()")
        lines.append(f"  {compile_def(s.id, 0)}")
        lines.append("endif()")
        lines.append("")

    for s in header_ints:
        lines.append(compile_def(s.id, f"${{CONFIG_{s.id}}}"))

    lines.append("")
    return "\n".join(lines)


def generate_esp_config_header_cmake(settings: list[Setting], ts: str) -> str:
    """CMake fragment: write noxtls_config_features.h from CONFIG_NOXTLS_* (sdkconfig)."""
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "# Generated from noxtls_config_catalog.xml — do not edit by hand.",
        f"# Generator: {GENERATOR_REL} ({ts})",
        "",
        "function(noxtls_esp_idf_write_config_features_header out_file)",
        "  if(NOT out_file)",
        '    message(FATAL_ERROR "noxtls_esp_idf_write_config_features_header: out_file required")',
        "  endif()",
        '  set(_noxtls_hdr "")',
        '  string(APPEND _noxtls_hdr "/* Generated from ESP-IDF sdkconfig (menuconfig).\\n")',
        '  string(APPEND _noxtls_hdr " * Do not edit; regenerate via tools/kconfig_gen/generate_kconfig.py. */\\n\\n")',
        '  string(APPEND _noxtls_hdr "#ifndef _NOXTLS_CONFIG_FEATURES_H_\\n")',
        '  string(APPEND _noxtls_hdr "#define _NOXTLS_CONFIG_FEATURES_H_\\n\\n")',
        "",
    ]

    for s in sorted(settings, key=lambda x: x.id):
        if s.type == "boolean":
            cache_var = macro_to_cmake_cache(s.id)
            if cache_var is not None:
                lines.append(f"if({cache_var})")
            else:
                lines.append(f"if(CONFIG_{s.id})")
            lines.append(f'  string(APPEND _noxtls_hdr "#define {s.id} 1\\n")')
            lines.append("else()")
            lines.append(f'  string(APPEND _noxtls_hdr "#define {s.id} 0\\n")')
            lines.append("endif()")
            lines.append("")
        elif s.type == "integer":
            lines.append(
                f'string(APPEND _noxtls_hdr "#define {s.id} ${{CONFIG_{s.id}}}\\n")'
            )
            lines.append("")

    lines.extend(
        [
            "if(CONFIG_NOXTLS_SIDECHANNEL_PERFORMANCE)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE 1\\n")',
            '  string(APPEND _noxtls_hdr "#define NOXTLS_CT_COMPARE 0\\n")',
            "elseif(CONFIG_NOXTLS_SIDECHANNEL_CONSTANT_TIME_STRICT)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT 1\\n")',
            '  string(APPEND _noxtls_hdr "#define NOXTLS_CT_COMPARE 1\\n")',
            "else()",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_SIDECHANNEL_PROFILE_BALANCED 1\\n")',
            '  string(APPEND _noxtls_hdr "#define NOXTLS_CT_COMPARE 1\\n")',
            "endif()",
            "if(CONFIG_NOXTLS_PROFILE_MINIMAL_TLS_CLIENT)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_PROFILE_MINIMAL_TLS_CLIENT 1\\n")',
            "endif()",
            "if(CONFIG_NOXTLS_PROFILE_TLS_SERVER_PKI)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_PROFILE_TLS_SERVER_PKI 1\\n")',
            "endif()",
            "if(CONFIG_NOXTLS_PROFILE_CRYPTO_ONLY)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_PROFILE_CRYPTO_ONLY 1\\n")',
            "endif()",
            "if(CONFIG_NOXTLS_PROFILE_FIPS_LIKE)",
            '  string(APPEND _noxtls_hdr "#define NOXTLS_PROFILE_FIPS_LIKE 1\\n")',
            "endif()",
            "",
            '  string(APPEND _noxtls_hdr "\\n#endif /* _NOXTLS_CONFIG_FEATURES_H_ */\\n")',
            '  file(WRITE "${out_file}" "${_noxtls_hdr}")',
            "endfunction()",
            "",
        ]
    )
    return "\n".join(lines)


def collect_all_settings(catalog: ET.Element) -> list[Setting]:
    settings: list[Setting] = []
    categories = catalog.find("categories")
    if categories is None:
        return settings
    for category in categories.findall("category"):
        if category.attrib.get("id", "") in SKIP_CATEGORY_IDS:
            continue
        walk_settings(category, settings)
    return settings


def resolve_generation_timestamp(check_mode: bool) -> str:
    if not check_mode:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    probe_paths = [PORTS[0].kconfig_out, PORTS[0].cmake_out]
    for path in probe_paths:
        if not path.is_file():
            continue
        match = GENERATOR_TS_RE.search(path.read_text(encoding="utf-8"))
        if match is not None:
            return match.group(1)

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if generated files are out of date",
    )
    args = parser.parse_args()

    if not CATALOG_XML.is_file():
        print(f"error: missing {CATALOG_XML}", file=sys.stderr)
        return 1

    catalog = ET.parse(CATALOG_XML).getroot()
    settings = collect_all_settings(catalog)
    ts = resolve_generation_timestamp(args.check)
    kconfig_text = generate_kconfig(catalog, ts)

    esp_config_header_cmake = NOXTLS_ROOT / "ports" / "esp-idf" / "noxtls_esp_idf_config_header.cmake"

    outputs: list[tuple[Path, str]] = []
    for port in PORTS:
        outputs.append((port.kconfig_out, kconfig_text))
        outputs.append((port.cmake_out, generate_cmake(settings, port.flavor, ts)))
    outputs.append((esp_config_header_cmake, generate_esp_config_header_cmake(settings, ts)))

    if args.check:
        ok = True
        for path, expected in outputs:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                print(f"out of date: {path}", file=sys.stderr)
                ok = False
        return 0 if ok else 1

    for path, text in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(NOXTLS_ROOT)}")

    print(f"({len(settings)} settings, {len(PORTS)} ports)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
