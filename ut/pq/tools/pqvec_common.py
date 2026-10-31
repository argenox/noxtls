"""Shared helpers for the PQ known-answer vector generators.

The generators read official NIST data (ACVP-Server JSON files from
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files, or
the NIST PQC submission KAT .rsp files) from a directory given on the
command line and write small C headers under ut/pq/vectors/.  Only a handful
of vectors per parameter set are emitted to keep the repository small; large
expected outputs (keys, signatures) are stored as SHA3-256 digests where the
test can recompute them.

All input files are treated as untrusted data: they are parsed as JSON/text
only, every field is validated (hex, expected lengths) before it is emitted.
"""

import hashlib
import json
import re

HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")

LICENSE_HEADER = """/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* GENERATED FILE - do not edit by hand.
*
*****************************************************************************/
"""


def unhex(s, expected_len=None, what="field"):
    """Decode a hex string, validating characters and (optionally) length."""
    if not isinstance(s, str) or (len(s) % 2) != 0 or not HEX_RE.match(s):
        raise ValueError("bad hex in %s" % what)
    b = bytes.fromhex(s)
    if expected_len is not None and len(b) != expected_len:
        raise ValueError("%s: length %d, expected %d" % (what, len(b), expected_len))
    return b


def sha3_256(data):
    return hashlib.sha3_256(data).digest()


def load_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def c_ident(s):
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s):
        raise ValueError("bad identifier %r" % s)
    return s


def c_bytes(name, data, per_line=16):
    """Emit `static const uint8_t name[] = {...};` (empty arrays get one pad byte)."""
    name = c_ident(name)
    if len(data) == 0:
        return "static const uint8_t %s[1] = { 0x00 }; /* empty */\n" % name
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append("    " + ", ".join("0x%02x" % b for b in chunk) + ",")
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(lines))


def write_header(path, guard, provenance, body):
    guard = c_ident(guard)
    out = [LICENSE_HEADER, "/*\n"]
    for line in provenance:
        out.append(" * %s\n" % line)
    out.append(" */\n\n#ifndef %s\n#define %s\n\n#include <stdint.h>\n\n" % (guard, guard))
    out.append(body)
    out.append("\n#endif /* %s */\n" % guard)
    with open(path, "w", newline="\n") as f:
        f.write("".join(out))
