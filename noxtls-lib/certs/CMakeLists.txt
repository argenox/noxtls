# Certificates library
option(NOXTLS_SILENCE_ASN1_PRINTF "Disable asn1.c debug printf (recommended for libFuzzer / CI noise)" OFF)

add_library(noxtls_certificates STATIC
    asn1.c
    certificates.c
    oids.c
)

if(NOXTLS_SILENCE_ASN1_PRINTF)
    target_compile_definitions(noxtls_certificates PRIVATE NOXTLS_NO_ASN1_PRINTF=1)
endif()

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_certificates PRIVATE /wd5045)
endif()

target_include_directories(noxtls_certificates PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/certs
)

target_link_libraries(noxtls_certificates
    noxtls_utility
)

# Certificate (X.509) library - implements X.509 certificate parsing (DER and PEM)
option(NOXTLS_HAVE_TIME "Have time support; if OFF, skip cert validity time checks (embedded/no RTC)" ON)
if(DEFINED NOXTLS_CFG_HAVE_CERT_WRITE)
    set(NOXTLS_HAVE_CERT_WRITE ${NOXTLS_CFG_HAVE_CERT_WRITE})
else()
    option(NOXTLS_HAVE_CERT_WRITE "Enable certificate writing and generation (write DER/PEM, generate self-signed)" OFF)
endif()

set(NOXTLS_CERT_SOURCES noxtls_x509.c)
if(NOXTLS_HAVE_CERT_WRITE)
    list(APPEND NOXTLS_CERT_SOURCES noxtls_x509_write.c)
endif()

add_library(noxtls_cert STATIC
    ${NOXTLS_CERT_SOURCES}
)

if(NOT NOXTLS_HAVE_TIME)
    target_compile_definitions(noxtls_cert PRIVATE NOXTLS_HAVE_TIME=0)
endif()
if(NOXTLS_HAVE_CERT_WRITE)
    target_compile_definitions(noxtls_cert PRIVATE NOXTLS_HAVE_CERT_WRITE=1)
endif()

if(MSVC)
    target_compile_options(noxtls_cert PRIVATE /wd5045)
endif()

if(NOT DEFINED NOXTLS_PROJECT_ROOT)
    get_filename_component(NOXTLS_PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
endif()
target_include_directories(noxtls_cert PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/certs
    ${NOXTLS_PROJECT_ROOT}/utility
    ${NOXTLS_LIB_ROOT}/pkc
    ${NOXTLS_LIB_ROOT}/pkc/rsa
    ${NOXTLS_LIB_ROOT}/pkc/ecc
    ${NOXTLS_LIB_ROOT}/mdigest
    ${NOXTLS_LIB_ROOT}/encryption
    ${NOXTLS_LIB_ROOT}/common
)

target_link_libraries(noxtls_cert
    noxtls_certificates
    noxtls_utility
    noxtls_pkc
    noxtls_hash
    noxtls_encryption
    noxtls_common
)
