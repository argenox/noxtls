# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# Generate certificates/CSRs with the NoxTLS writers and validate them with openssl.
# Inputs: TEST_EXE, OPENSSL, WORK_DIR.
file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}")

function(run)
    execute_process(COMMAND ${ARGN} WORKING_DIRECTORY "${WORK_DIR}"
                    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(FATAL_ERROR "command failed (${rc}): ${ARGN}\n${out}\n${err}")
    endif()
    set(LAST_OUT "${out}" PARENT_SCOPE)
endfunction()

run("${TEST_EXE}" --artifacts "${WORK_DIR}" x509_cert_write_roundtrip)

# EC self-signed: parse and verify its own signature.
run("${OPENSSL}" x509 -inform DER -in gen_ec_selfsigned.der -out gen_ec_selfsigned.pem)
run("${OPENSSL}" x509 -in gen_ec_selfsigned.pem -noout -text)
if(NOT LAST_OUT MATCHES "CN *= *gen.test")
    message(FATAL_ERROR "unexpected subject in generated EC certificate:\n${LAST_OUT}")
endif()
if(NOT LAST_OUT MATCHES "prime256v1")
    message(FATAL_ERROR "generated EC certificate lacks the namedCurve parameter:\n${LAST_OUT}")
endif()
run("${OPENSSL}" verify -check_ss_sig -partial_chain -CAfile gen_ec_selfsigned.pem gen_ec_selfsigned.pem)

# Ed25519 self-signed with extensions.
run("${OPENSSL}" x509 -inform DER -in gen_ed25519_ext.der -noout -text)
if(NOT LAST_OUT MATCHES "DNS:gen.test" OR NOT LAST_OUT MATCHES "CA:TRUE")
    message(FATAL_ERROR "generated Ed25519 certificate extensions not as requested:\n${LAST_OUT}")
endif()

# EC certificate from the *_with_extensions_ex generator: the RFC 5480 namedCurve must be
# present so other implementations can load the public key and verify the signature.
run("${OPENSSL}" x509 -inform DER -in gen_ec_ext.der -out gen_ec_ext.pem)
run("${OPENSSL}" x509 -in gen_ec_ext.pem -noout -text)
if(NOT LAST_OUT MATCHES "prime256v1" OR NOT LAST_OUT MATCHES "DNS:gen.test")
    message(FATAL_ERROR "gen_ec_ext.der lacks the namedCurve parameter or its SAN:\n${LAST_OUT}")
endif()
run("${OPENSSL}" x509 -in gen_ec_ext.pem -noout -pubkey)
run("${OPENSSL}" verify -check_ss_sig -partial_chain -CAfile gen_ec_ext.pem gen_ec_ext.pem)

# Writer corpus (byte-identical to the previous implementation): every output must load.
run("${TEST_EXE}" --artifacts "${WORK_DIR}" x509_cert_write_corpus)
foreach(der wc_plain_ed25519 wc_ex_ec wc_ext_ed25519 wc_ext_ex_ed25519 wc_noext_ed25519)
    run("${OPENSSL}" x509 -inform DER -in ${der}.der -noout -text)
endforeach()
# wc_ex_ec carries a randomized ECDSA signature (only its TBS part is byte-compared): verify it.
run("${OPENSSL}" x509 -inform DER -in wc_ex_ec.der -out wc_ex_ec.pem)
run("${OPENSSL}" verify -check_ss_sig -partial_chain -CAfile wc_ex_ec.pem wc_ex_ec.pem)
run("${OPENSSL}" req -inform DER -in wc_csr_ec.der -noout -verify)
run("${OPENSSL}" req -inform DER -in wc_csr_ed25519.der -noout -verify)
run("${OPENSSL}" req -in wc_csr_ec.pem -noout -verify)

# PKCS#10 request: structure and self-signature.
run("${OPENSSL}" req -inform DER -in gen_ec.csr.der -noout -verify -text)
message(STATUS "openssl cross-check passed")
