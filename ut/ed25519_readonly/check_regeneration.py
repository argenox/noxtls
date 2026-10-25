"""Check real in-house generation and refuse incompatible compile geometry."""
import pathlib
import subprocess
import sys
import tempfile

small_generator, comb_generator, compiler, root, compiler_id, frontend_variant = sys.argv[1:]
root = pathlib.Path(root)
for generator, table in ((small_generator, "noxtls_ed25519_small_readonly.inc"),
                         (comb_generator, "noxtls_ed25519_comb_readonly.inc")):
    produced = subprocess.check_output([generator], timeout=20).replace(b"\r\n", b"\n")
    expected = (root / "noxtls-lib/pkc/ed25519" / table).read_bytes().replace(b"\r\n", b"\n")
    assert produced == expected, "Generated read-only table differs: " + table
msvc_frontend = compiler_id == "MSVC" or frontend_variant == "MSVC"
assert msvc_frontend or compiler_id in ("GNU", "Clang", "AppleClang"), "Unsupported compiler frontend"
header = root / "noxtls-lib/pkc/ed25519/noxtls_ed25519_config.h"
source = ('#include "' + header.as_posix() + '"\n'
          '#if NOXTLS_ED25519_READONLY_SMALL_BASE\n'
          'noxtls_readonly_profile_checked\n'
          '#elif NOXTLS_ED25519_READONLY_COMB\n'
          'noxtls_readonly_comb_profile_checked\n'
          '#else\nnoxtls_lazy_profile_checked\n#endif\n')
valid = ["NOXTLS_ED25519_SMALL_BASE=1", "NOXTLS_ED25519_READONLY_SMALL_BASE=1"]
accepted = [
    ([], b"noxtls_readonly_comb_profile_checked"),
    (["NOXTLS_ED25519_READONLY_COMB=0"], b"noxtls_lazy_profile_checked"),
    (["NOXTLS_ED25519_SMALL_BASE=1"], b"noxtls_lazy_profile_checked"),
    (["NOXTLS_ED25519_DUMP_BASE=1"], b"noxtls_lazy_profile_checked"),
    (valid, b"noxtls_readonly_profile_checked"),
]
cases = [
    ["NOXTLS_ED25519_READONLY_SMALL_BASE=1"],
    valid + ["NOXTLS_ED25519_DUMP_BASE=1"],
    valid + ["NOXTLS_ED25519_SCALAR_WINDOW_BITS=3"],
    valid + ["NOXTLS_ED25519_SLIDE_ODD_COUNT=8"],
    valid + ["NOXTLS_ED25519_SLIDE_MAX_ABS=15"],
    ["NOXTLS_ED25519_READONLY_COMB=1", "NOXTLS_ED25519_SMALL_BASE=1"],
    ["NOXTLS_ED25519_READONLY_COMB=1", "NOXTLS_ED25519_DUMP_BASE=1"],
    ["NOXTLS_ED25519_COMB_TEETH=5"],
    ["NOXTLS_ED25519_COMB_SPACING=4"],
    ["NOXTLS_ED25519_SLIDE_ODD_COUNT=8"],
    ["NOXTLS_ED25519_SLIDE_MAX_ABS=15"],
]
with tempfile.TemporaryDirectory(prefix="noxtls-ed25519-config-") as temporary:
    source_path = pathlib.Path(temporary) / "profile.c"
    source_path.write_text(source, encoding="utf-8")

    def preprocess(definitions):
        if msvc_frontend:
            arguments = ["/nologo", "/EP", "/TC", *("/D" + d for d in definitions)]
        else:
            arguments = ["-E", "-x", "c", *("-D" + d for d in definitions)]
        return subprocess.run([compiler, *arguments, str(source_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    for definitions, marker in accepted:
        result = preprocess(definitions)
        assert result.returncode == 0, "Valid Ed25519 profile was rejected: " + repr(definitions)
        assert marker in result.stdout, "Unexpected Ed25519 table profile: " + repr(definitions)
    for definitions in cases:
        result = preprocess(definitions)
        assert result.returncode != 0, "Unsupported geometry was accepted: " + repr(definitions)
print("In-house small/comb table regeneration and %d compile-configuration checks passed"
      % (len(accepted) + len(cases)))
