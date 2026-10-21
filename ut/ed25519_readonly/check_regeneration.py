"""Check real in-house generation and refuse incompatible compile geometry."""
import pathlib
import subprocess
import sys
import tempfile

generator, compiler, root, compiler_id, frontend_variant = sys.argv[1:]
root = pathlib.Path(root)
produced = subprocess.check_output([generator], timeout=20).replace(b"\r\n", b"\n")
expected = (root / "noxtls-lib/pkc/ed25519/noxtls_ed25519_small_readonly.inc").read_bytes().replace(b"\r\n", b"\n")
assert produced == expected, "Generated read-only table differs"
msvc_frontend = compiler_id == "MSVC" or frontend_variant == "MSVC"
assert msvc_frontend or compiler_id in ("GNU", "Clang", "AppleClang"), "Unsupported compiler frontend"
header = root / "noxtls-lib/pkc/ed25519/noxtls_ed25519_config.h"
source = ('#include "' + header.as_posix() + '"\n'
          '#if NOXTLS_ED25519_READONLY_SMALL_BASE\n'
          'noxtls_readonly_profile_checked\n'
          '#else\nnoxtls_lazy_profile_checked\n#endif\n')
valid = ["NOXTLS_ED25519_SMALL_BASE=1", "NOXTLS_ED25519_READONLY_SMALL_BASE=1"]
cases = [
    ["NOXTLS_ED25519_READONLY_SMALL_BASE=1"],
    valid + ["NOXTLS_ED25519_DUMP_BASE=1"],
    valid + ["NOXTLS_ED25519_SCALAR_WINDOW_BITS=3"],
    valid + ["NOXTLS_ED25519_SLIDE_ODD_COUNT=8"],
    valid + ["NOXTLS_ED25519_SLIDE_MAX_ABS=15"],
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

    for definitions, marker in [([], b"noxtls_lazy_profile_checked"),
                                (valid, b"noxtls_readonly_profile_checked")]:
        result = preprocess(definitions)
        assert result.returncode == 0, "Valid Ed25519 profile was rejected"
        assert marker in result.stdout, "Compiler did not preprocess the configuration header"
    for definitions in cases:
        result = preprocess(definitions)
        assert result.returncode != 0, "Unsupported geometry was accepted"
print("In-house table regeneration and seven compile-configuration checks passed")
