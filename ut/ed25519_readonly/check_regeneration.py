"""Check real in-house generation and refuse incompatible compile geometry."""
import pathlib
import subprocess
import sys

generator, compiler, root = sys.argv[1:]
root = pathlib.Path(root)
produced = subprocess.check_output([generator], timeout=20).replace(b"\r\n", b"\n")
expected = (root / "noxtls-lib/pkc/ed25519/noxtls_ed25519_small_readonly.inc").read_bytes().replace(b"\r\n", b"\n")
assert produced == expected, "Generated read-only table differs"
header = root / "noxtls-lib/pkc/ed25519/noxtls_ed25519_config.h"
source = ('#include "' + header.as_posix() + '"\n').encode()
valid = ["-DNOXTLS_ED25519_SMALL_BASE=1", "-DNOXTLS_ED25519_READONLY_SMALL_BASE=1"]
cases = [
    ["-DNOXTLS_ED25519_READONLY_SMALL_BASE=1"],
    valid + ["-DNOXTLS_ED25519_DUMP_BASE=1"],
    valid + ["-DNOXTLS_ED25519_SCALAR_WINDOW_BITS=3"],
    valid + ["-DNOXTLS_ED25519_SLIDE_ODD_COUNT=8"],
    valid + ["-DNOXTLS_ED25519_SLIDE_MAX_ABS=15"],
]
for definitions in cases:
    result = subprocess.run([compiler, "-E", "-x", "c", *definitions, "-"],
                            input=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert result.returncode != 0, "Unsupported geometry was accepted"
for definitions in [[], valid]:
    subprocess.run([compiler, "-E", "-x", "c", *definitions, "-"], input=source,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=10)
print("In-house table regeneration and seven compile-configuration checks passed")
