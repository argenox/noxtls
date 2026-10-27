#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Independent DTLS 1.3 PSK binder vectors for dtls13_single_association_test.c.

Writes binder_vectors.h next to this script. Only the Python standard library (hmac,
hashlib) is used, not NoxTLS. The key schedule is checked against RFC 8448 at start-up.

- An external PSK binder of a first ClientHello (RFC 8446 Section 4.2.11.2):
  early_secret = HKDF-Extract(0, PSK), binder_key = Derive-Secret(early_secret,
  "ext binder", ""), finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32),
  binder = HMAC(finished_key, Transcript-Hash(Truncate(ClientHello))). DTLS 1.3 uses the
  label prefix "dtls13" (RFC 9147 Section 5.9); the "tls13 " value is given for contrast.
- A second ClientHello after a stateless HelloRetryRequest (RFC 9147 Section 5.1): the
  transcript is message_hash(Hash(CH1)) || HelloRetryRequest || Truncate(CH2) (RFC 8446
  Section 4.4.1), with the transcript form of RFC 9147 Section 5.2 (msg_type, length,
  body). The HelloRetryRequest is built here from its definition (RFC 8446 Sections 4.1.3,
  4.1.4: legacy_version, the HelloRetryRequest random, echoed legacy_session_id, suite,
  null compression, supported_versions, cookie).
"""
import hashlib
import hmac
import os

H = hashlib.sha256
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def hkdf_extract(salt, ikm):
    return hmac.new(salt if salt else bytes(32), ikm, H).digest()


def hkdf_expand(prk, info, length):
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), H).digest()
        out += block
        counter += 1
    return out[:length]


def expand_label(prefix, secret, label, context, length):
    full = prefix + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


def derive_secret(prefix, secret, label, messages):
    return expand_label(prefix, secret, label, H(messages).digest(), 32)


def binder(prefix, psk, transcript):
    early = hkdf_extract(b"", psk)
    binder_key = derive_secret(prefix, early, b"ext binder", b"")
    finished_key = expand_label(prefix, binder_key, b"finished", b"", 32)
    return hmac.new(finished_key, H(transcript).digest(), H).digest()


def u16(v):
    return v.to_bytes(2, "big")


def u24(v):
    return v.to_bytes(3, "big")


def ext(t, data):
    return u16(t) + u16(len(data)) + data


def client_hello_body(identity, cookie):
    """DTLS 1.3 ClientHello body without its binders; returns (body_prefix, binders_len_field)."""
    exts = ext(43, b"\x02\xfe\xfc")                                      # supported_versions
    exts += ext(10, u16(2) + u16(0x001D))                                # supported_groups: x25519
    exts += ext(51, u16(36) + u16(0x001D) + u16(32) + bytes(range(0x60, 0x80)))  # key_share
    exts += ext(45, b"\x01\x01")                                         # psk_dhe_ke
    if cookie is not None:
        exts += ext(44, u16(len(cookie)) + cookie)                       # cookie
    identities = u16(len(identity)) + identity + (0).to_bytes(4, "big")
    binders_len = 1 + 32
    psk_ext_len = 2 + len(identities) + 2 + binders_len
    psk_head = u16(41) + u16(psk_ext_len) + u16(len(identities)) + identities
    exts_len = len(exts) + len(psk_head) + 2 + binders_len
    body = b"\xfe\xfd" + bytes(range(0xA0, 0xC0)) + b"\x00" + b"\x00"   # version, random, sid, legacy_cookie
    body += u16(2) + u16(0x1301) + b"\x01\x00"                          # suites, compression
    body += u16(exts_len) + exts + psk_head
    return body, binders_len


def finish_client_hello(prefix, psk, identity, cookie, transcript_prefix):
    """Return the TLS-form ClientHello (4-byte header) with its binder filled in."""
    body, binders_len = client_hello_body(identity, cookie)
    total = len(body) + 2 + binders_len
    truncated = b"\x01" + u24(total) + body
    value = binder(prefix, psk, transcript_prefix + truncated)
    return truncated + u16(binders_len) + b"\x20" + value, value


def hello_retry_request(session_id, suite, cookie):
    exts = ext(43, b"\xfe\xfc") + ext(44, u16(len(cookie)) + cookie)
    body = b"\xfe\xfd" + HRR_RANDOM + bytes([len(session_id)]) + session_id + u16(suite) + b"\x00"
    body += u16(len(exts)) + exts
    return b"\x02" + u24(len(body)) + body


def dtls_datagram(tls_form, record_seq, message_seq):
    body = tls_form[4:]
    hs = tls_form[0:1] + u24(len(body)) + u16(message_seq) + u24(0) + u24(len(body)) + body
    return b"\x16\xfe\xfd" + u16(0) + record_seq.to_bytes(6, "big") + u16(len(hs)) + hs


def c_array(name, data):
    rows = []
    for i in range(0, len(data), 16):
        rows.append("    " + ", ".join("0x%02XU" % b for b in data[i:i + 16]))
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), ",\n".join(rows))


def self_check():
    """RFC 8448 Section 3: Derive-Secret(early_secret, "derived", "") of the simple 1-RTT handshake."""
    early = hkdf_extract(b"", bytes(32))
    assert early.hex() == "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    derived = derive_secret(b"tls13 ", early, b"derived", b"")
    assert derived.hex() == "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"


def main():
    self_check()
    psk = bytes(range(0x10, 0x30))
    identity = b"nmx1-management"
    cookie = bytes([1, 0, 0, 0, 0, 0, 0x10, 0]) + bytes(range(0x20, 0x50))   # 56 bytes

    ch1, binder_dtls = finish_client_hello(b"dtls13", psk, identity, None, b"")
    ch1_tls_binder = binder(b"tls13 ", psk, ch1[:-35])
    ch1_hash = H(ch1).digest()                                       # RFC 9147 5.2 transcript form

    hrr = hello_retry_request(b"", 0x1301, cookie)
    prefix = b"\xfe" + u24(32) + ch1_hash + hrr                      # message_hash || HRR
    ch2, _ = finish_client_hello(b"dtls13", psk, identity, cookie, prefix)
    ch2_tls13, _ = finish_client_hello(b"tls13 ", psk, identity, cookie, prefix)

    out = ["/* Generated by gen_binder_vectors.py (Python hmac/hashlib, not NoxTLS); do not edit. */",
           "#ifndef SA_BINDER_VECTORS_H", "#define SA_BINDER_VECTORS_H", "#include <stdint.h>", ""]
    out.append(c_array("k_vec_psk", psk))
    out.append(c_array("k_vec_identity", identity))
    out.append("/* First ClientHello, TLS 1.3 four-byte header, binder last (its offset is len - 32). */")
    out.append(c_array("k_vec_ch1", ch1))
    out.append(c_array("k_vec_ch1_binder_dtls13", binder_dtls))
    out.append(c_array("k_vec_ch1_binder_tls13", ch1_tls_binder))
    out.append("/* SHA-256 of k_vec_ch1 (RFC 9147 5.2 transcript form). */")
    out.append(c_array("k_vec_ch1_hash", ch1_hash))
    out.append(c_array("k_vec_cookie", cookie))
    out.append("/* The stateless HelloRetryRequest (suite 0x1301, no key_share), TLS 1.3 header. */")
    out.append(c_array("k_vec_hrr", hrr))
    out.append("/* Second ClientHello datagrams (record 1, message_seq 1): binder with \"dtls13\" and \"tls13 \" labels. */")
    out.append(c_array("k_vec_ch2_dtls13", dtls_datagram(ch2, 1, 1)))
    out.append(c_array("k_vec_ch2_tls13", dtls_datagram(ch2_tls13, 1, 1)))
    out.append("#endif /* SA_BINDER_VECTORS_H */")
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "binder_vectors.h")
    with open(path, "w", newline="\n") as handle:
        handle.write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
