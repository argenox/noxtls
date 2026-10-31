#!/usr/bin/env python3
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# File:    openssl_interop.py
# Summary: NoxTLS <-> OpenSSL interoperability over localhost TCP.
#
# Usage: openssl_interop.py --openssl openssl --tlscurl tlscurl --https-server https_server
#                           --pki loopback_pki.c --work-dir DIR --case NAME
#        openssl_interop.py --list
#
# NoxTLS client cases run applications/tlscurl against `openssl s_server -www`;
# NoxTLS server cases run applications/https_server against `openssl s_client`
# with an HTTP request. Certificates come from the loopback test PKI.

import argparse
import os
import re
import socket
import subprocess
import sys
import time


def extract_pki(pki_c, out_dir, openssl):
    src = open(pki_c).read()
    os.makedirs(out_dir, exist_ok=True)
    for m in re.finditer(r'const uint8_t (\w+)\[\] = \{(.*?)\};', src, re.S):
        data = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-F]{2})', m.group(2)))
        open(os.path.join(out_dir, m.group(1) + ".der"), "wb").write(data)

    def conv(kind, name, out):
        subprocess.run([openssl, kind, "-inform", "DER", "-in", os.path.join(out_dir, name + ".der"),
                        "-out", os.path.join(out_dir, out)], check=True, capture_output=True)

    conv("x509", "lb_ec_localhost_cert", "ec_localhost.pem")
    conv("x509", "lb_ec_int_cert", "ec_int.pem")
    conv("x509", "lb_ec_root_cert", "ec_root.pem")
    conv("x509", "lb_rsa_server_cert", "rsa_server.pem")
    conv("x509", "lb_rsa_root_cert", "rsa_root.pem")
    conv("ec", "lb_ec_server_key", "ec_server_key.pem")
    conv("rsa", "lb_rsa_server_key", "rsa_server_key.pem")
    conv("x509", "lb_ec_client_cert", "ec_client.pem")
    conv("ec", "lb_ec_client_key", "ec_client_key.pem")
    conv("x509", "lb_rsa_client_cert", "rsa_client.pem")
    conv("rsa", "lb_rsa_client_key", "rsa_client_key.pem")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port, proc, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class Server:
    def __init__(self, argv, port, cwd):
        self.log = open(os.path.join(cwd, "server_%d.log" % port), "w+")
        self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=self.log,
                                     stderr=subprocess.STDOUT)
        self.port = port
        if not wait_listening(port, self.proc):
            self.stop()
            raise RuntimeError("server did not start: %s\n%s" % (" ".join(argv), self.output()))

    def output(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def run_client(argv, cwd, stdin_data=None, timeout=30):
    r = subprocess.run(argv, cwd=cwd, input=stdin_data, capture_output=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def expect(cond, what, text):
    if not cond:
        raise AssertionError("%s\n----- output -----\n%s" % (what, text))


# ---- NoxTLS client vs openssl s_server ------------------------------------------

def noxtls_client(a, server_args, client_args, want):
    port = free_port()
    srv = Server([a.openssl, "s_server", "-accept", str(port), "-www", "-cert", "ec_localhost.pem",
                  "-key", "ec_server_key.pem", "-cert_chain", "ec_int.pem"] + server_args, port, a.work)
    try:
        rc, out = run_client([a.tlscurl, "https://localhost:%d/" % port, "--ca", "ec_root.pem",
                              "-o", "-", "-v"] + client_args, a.work)
    finally:
        srv.stop()
    expect(rc == 0, "tlscurl exited with %d" % rc, out + srv.output())
    for w in want:
        expect(w in out, "missing %r in s_server -www response" % w, out)


def case_client_tls13(a):
    noxtls_client(a, ["-tls1_3"], ["--tls13"], ["TLSv1.3"])


def case_client_tls13_hrr(a):
    # The NoxTLS client sends its first share for X25519; P-256 only forces a HelloRetryRequest.
    noxtls_client(a, ["-tls1_3", "-groups", "P-256"], ["--tls13"], ["TLSv1.3", "selected_kex_group=0x0017"])


def case_client_tls13_chacha20(a):
    noxtls_client(a, ["-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"], ["--tls13"],
                  ["TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256"])


def case_client_tls13_aes256(a):
    noxtls_client(a, ["-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384"], ["--tls13"],
                  ["TLSv1.3", "TLS_AES_256_GCM_SHA384"])


def case_client_tls12_gcm(a):
    noxtls_client(a, ["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"], ["--tls12"],
                  ["TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256"])


def case_client_tls12_ems_sha384(a):
    # RFC 7627 session_hash from the running SHA-384 transcript (client side).
    noxtls_client(a, ["-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"], ["--tls12"],
                  ["TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384", "Extended master secret: yes"])


def case_client_tls12_chacha20(a):
    noxtls_client(a, ["-tls1_2", "-cipher", "ECDHE-ECDSA-CHACHA20-POLY1305"], ["--tls12"],
                  ["TLSv1.2", "ECDHE-ECDSA-CHACHA20-POLY1305"])


# ---- openssl s_client vs NoxTLS https_server --------------------------------------

def noxtls_server(a, server_args, client_args, want, ca="ec_root.pem", sessions=1):
    port = free_port()
    srv = Server([a.https_server, str(port)] + server_args, port, a.work)
    outputs = []
    try:
        sess = os.path.join(a.work, "sess_%d.pem" % port)
        for i in range(sessions):
            extra = []
            if sessions > 1:
                extra = ["-sess_out", sess] if i == 0 else ["-sess_in", sess]
            rc, out = run_client([a.openssl, "s_client", "-connect", "127.0.0.1:%d" % port,
                                  "-servername", "localhost", "-CAfile", ca, "-verify_return_error",
                                  "-ign_eof"] + client_args + extra, a.work,
                                 stdin_data=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            outputs.append(out)
            expect(rc == 0, "s_client exited with %d (connection %d)" % (rc, i), out + srv.output())
            expect("HTTP/1." in out and " 200 " in out, "no HTTP 200 response (connection %d)" % i, out)
            expect("Verify return code: 0 (ok)" in out, "certificate not verified", out)
    finally:
        srv.stop()
    for w in want:
        expect(w in outputs[-1], "missing %r in s_client output" % w, outputs[-1])


EC_SERVER = ["--cert", "lb_ec_localhost_cert.der", "--key", "lb_ec_server_key.der",
             "--cert-chain", "lb_ec_int_cert.der"]
RSA_SERVER = ["--cert", "lb_rsa_server_cert.der", "--key", "lb_rsa_server_key.der"]


def case_server_tls13(a):
    noxtls_server(a, EC_SERVER, ["-tls1_3"], ["Protocol  : TLSv1.3"])


def case_server_tls13_chacha20(a):
    noxtls_server(a, EC_SERVER, ["-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"],
                  ["Cipher    : TLS_CHACHA20_POLY1305_SHA256"])


def case_server_tls13_p256(a):
    noxtls_server(a, EC_SERVER, ["-tls1_3", "-groups", "P-256"], ["Protocol  : TLSv1.3"])


def case_server_tls13_resumption(a):
    noxtls_server(a, EC_SERVER, ["-tls1_3"], ["Reused, TLSv1.3"], sessions=2)


def case_server_tls12_rsa(a):
    noxtls_server(a, RSA_SERVER, ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"],
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"], ca="rsa_root.pem")


def case_server_tls12_rsa_chacha20(a):
    noxtls_server(a, RSA_SERVER, ["-tls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305"],
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305"], ca="rsa_root.pem")


def case_server_tls13_rsa(a):
    noxtls_server(a, RSA_SERVER, ["-tls1_3"], ["Protocol  : TLSv1.3"], ca="rsa_root.pem")


def case_server_tls12_session_id_resumption(a):
    # The NoxTLS client never offers a session ID, so the server-side session cache is
    # exercised with openssl (tickets disabled).
    noxtls_server(a, RSA_SERVER, ["-tls1_2", "-no_ticket"], ["Reused, TLSv1.2"], ca="rsa_root.pem",
                  sessions=2)


def case_server_tls12_ticket_resumption(a):
    noxtls_server(a, RSA_SERVER, ["-tls1_2"], ["Reused, TLSv1.2"], ca="rsa_root.pem", sessions=2)


# TLS 1.2 client authentication. The NoxTLS server keeps only running transcript hashes and
# lists SHA-256 and SHA-384 schemes in CertificateRequest; -client_sigalgs forces the
# CertificateVerify scheme so its hash differs from the suite PRF hash. The certificate is
# required, so a client that could not sign with a listed scheme fails the handshake.
MTLS = ["--request-client-cert", "--require-client-cert"]
RSA_CLIENT = ["-cert", "rsa_client.pem", "-key", "rsa_client_key.pem"]
EC_CLIENT = ["-cert", "ec_client.pem", "-key", "ec_client_key.pem"]


def case_server_tls12_ems_sha384(a):
    # RFC 7627 session_hash from the running SHA-384 transcript (server side).
    noxtls_server(a, RSA_SERVER, ["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"],
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", "Extended master secret: yes"],
                  ca="rsa_root.pem")


def case_server_tls12_mtls_rsa_pss_sha384(a):
    # SHA-256 PRF, rsa_pss_rsae_sha384 CertificateVerify.
    noxtls_server(a, RSA_SERVER + MTLS,
                  ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-client_sigalgs",
                   "rsa_pss_rsae_sha384"] + RSA_CLIENT,
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"], ca="rsa_root.pem")


def case_server_tls12_mtls_rsa_pkcs1_sha384(a):
    # SHA-256 PRF, rsa_pkcs1_sha384 CertificateVerify.
    noxtls_server(a, RSA_SERVER + MTLS,
                  ["-tls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305", "-client_sigalgs", "RSA+SHA384"] + RSA_CLIENT,
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305"], ca="rsa_root.pem")


def case_server_tls12_mtls_ecdsa_sha256_prf_sha384(a):
    # SHA-384 PRF, ecdsa_secp256r1_sha256 CertificateVerify.
    noxtls_server(a, RSA_SERVER + MTLS,
                  ["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-client_sigalgs", "ECDSA+SHA256"] + EC_CLIENT,
                  ["Protocol  : TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"], ca="rsa_root.pem")


def case_server_tls12_mtls_no_resumption(a):
    # A server that authenticates clients never resumes (an abbreviated handshake has no
    # CertificateVerify): the offered session is declined and the second connection runs a
    # full handshake with a fresh transcript and CertificateVerify again.
    noxtls_server(a, RSA_SERVER + MTLS,
                  ["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-no_ticket"] + RSA_CLIENT,
                  ["New, TLSv1.2"], ca="rsa_root.pem", sessions=2)


# ---- Legacy TLS 1.2 policy (CBC / static-RSA / 3DES suites, SHA-1 signatures) ----------------
# By default NoxTLS refuses them in both roles; a build with
# NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES / NOXTLS_CFG_TLS12_ENABLE_SHA1_SIGNATURES
# (--legacy-suites / --sha1-sigs, passed by CMake) must still interoperate.

def noxtls_client_refused(a, server_args, client_args):
    port = free_port()
    srv = Server([a.openssl, "s_server", "-accept", str(port), "-www", "-cert", "ec_localhost.pem",
                  "-key", "ec_server_key.pem", "-cert_chain", "ec_int.pem"] + server_args, port, a.work)
    try:
        rc, out = run_client([a.tlscurl, "https://localhost:%d/" % port, "--ca", "ec_root.pem",
                              "-o", "-", "-v"] + client_args, a.work)
    finally:
        srv.stop()
    expect(rc != 0, "tlscurl connected although the server allows only legacy algorithms", out + srv.output())
    expect("s_server -www" not in out and "Ciphers supported in s_server" not in out,
           "an s_server -www page was received", out)


def noxtls_server_refused(a, server_args, client_args, ca="rsa_root.pem"):
    port = free_port()
    srv = Server([a.https_server, str(port)] + server_args, port, a.work)
    try:
        rc, out = run_client([a.openssl, "s_client", "-connect", "127.0.0.1:%d" % port,
                              "-servername", "localhost", "-CAfile", ca, "-verify_return_error",
                              "-ign_eof"] + client_args, a.work,
                             stdin_data=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    finally:
        srv.stop()
    expect(rc != 0, "s_client connected although it offered only legacy algorithms", out + srv.output())
    expect(" 200 " not in out, "an HTTP response was received", out)
    expect("handshake failure" in out or "alert" in out, "no TLS alert from the NoxTLS server", out)


CBC_OPENSSL = "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256"


def case_client_tls12_cbc_only_server(a):
    server = ["-tls1_2", "-cipher", CBC_OPENSSL]
    if a.legacy_suites:
        noxtls_client(a, server, ["--tls12"], ["TLSv1.2", "ECDHE-ECDSA-AES128-SHA"])
    else:
        noxtls_client_refused(a, server, ["--tls12"])


def case_client_tls12_sha1_only_server(a):
    # The peer must actually offer SHA-1 so rejection exercises NoxTLS policy.
    server = ["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0", "-sigalgs", "ECDSA+SHA1"]
    if a.sha1_sigs:
        noxtls_client(a, server, ["--tls12"], ["TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256"])
    else:
        noxtls_client_refused(a, server, ["--tls12"])


def case_server_tls12_cbc_only_client(a):
    # The application allowlist names only CBC / static-RSA suites: by default the library
    # still refuses to negotiate them.
    server = RSA_SERVER + ["--cipher-suites", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA"]
    client = ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-SHA:AES128-SHA:AES128-GCM-SHA256:DES-CBC3-SHA"]
    if a.legacy_suites:
        noxtls_server(a, server, client, ["Protocol  : TLSv1.2", "ECDHE-RSA-AES128-SHA"], ca="rsa_root.pem")
    else:
        noxtls_server_refused(a, server, client)


def case_server_tls12_sha1_only_client(a):
    client = ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "-sigalgs", "RSA+SHA1"]
    if a.sha1_sigs:
        noxtls_server(a, RSA_SERVER, client, ["Protocol  : TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"],
                      ca="rsa_root.pem")
    else:
        noxtls_server_refused(a, RSA_SERVER, client)


CASES = {name[5:]: fn for name, fn in globals().items() if name.startswith("case_")}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--openssl")
    p.add_argument("--tlscurl")
    p.add_argument("--https-server", dest="https_server")
    p.add_argument("--pki")
    p.add_argument("--work-dir", dest="work")
    p.add_argument("--case")
    p.add_argument("--list", action="store_true")
    p.add_argument("--legacy-suites", dest="legacy_suites", action="store_true",
                   help="build has NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES=ON")
    p.add_argument("--sha1-sigs", dest="sha1_sigs", action="store_true",
                   help="build has NOXTLS_CFG_TLS12_ENABLE_SHA1_SIGNATURES=ON")
    a = p.parse_args()
    if a.list:
        print("\n".join(sorted(CASES)))
        return 0
    a.work = os.path.abspath(os.path.join(a.work, a.case))
    extract_pki(a.pki, a.work, a.openssl)
    try:
        CASES[a.case](a)
    except Exception as exc:  # noqa: BLE001 - report every failure kind
        print("interop case %s FAILED: %s" % (a.case, exc))
        return 1
    print("interop case %s passed" % a.case)
    return 0


if __name__ == "__main__":
    sys.exit(main())
