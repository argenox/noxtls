# ATECC608B/C secure element provider sources consumed by other NoxTLS libraries
# (the entropy port is compiled into noxtls_drbg, like the nRF54 port).
set(NOXTLS_ATECC608_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(NOXTLS_ATECC608_PORT_DRBG_SOURCES ${NOXTLS_ATECC608_DIR}/noxtls_atecc608_port_drbg.c)
