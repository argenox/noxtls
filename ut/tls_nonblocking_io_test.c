#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_memory.h"
#include "noxtls_tls_common.h"

typedef struct test_io_s {
    uint8_t written[64];
    uint32_t written_len;
    const uint8_t *input;
    uint32_t input_len;
    uint32_t input_offset;
    uint32_t max_chunk;
    uint8_t block_next;
} test_io_t;

static int32_t test_send(void *user_data, const uint8_t *data, uint32_t len)
{
    test_io_t *io = (test_io_t *)user_data;
    uint32_t count;
    if(io->block_next != 0U) {
        io->block_next = 0U;
        return TLS_IO_WOULD_BLOCK;
    }
    count = len < io->max_chunk ? len : io->max_chunk;
    if(io->written_len + count > sizeof(io->written)) return -1;
    memcpy(io->written + io->written_len, data, count);
    io->written_len += count;
    io->block_next = 1U;
    return (int32_t)count;
}

static int32_t test_recv(void *user_data, uint8_t *data, uint32_t len)
{
    test_io_t *io = (test_io_t *)user_data;
    uint32_t available;
    uint32_t count;
    if(io->block_next != 0U) {
        io->block_next = 0U;
        return TLS_IO_WOULD_BLOCK;
    }
    available = io->input_len - io->input_offset;
    if(available == 0U) return TLS_IO_WOULD_BLOCK;
    count = len < io->max_chunk ? len : io->max_chunk;
    if(count > available) count = available;
    memcpy(data, io->input + io->input_offset, count);
    io->input_offset += count;
    io->block_next = 1U;
    return (int32_t)count;
}

static int test_partial_write(void)
{
    static const uint8_t expected[] = {
        TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x04,
        'n', 'o', 'x', '!'
    };
    tls_context_t ctx;
    test_io_t io;
    noxtls_return_t rc;
    uint32_t attempts = 0U;

    memset(&io, 0, sizeof(io));
    io.max_chunk = 3U;
    if(noxtls_tls_context_init(&ctx, TLS_ROLE_CLIENT, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS) return 1;
    noxtls_tls_set_io_callbacks(&ctx, test_send, test_recv, &io);
    noxtls_tls_set_io_mode(&ctx, TLS_IO_MODE_NON_BLOCKING);

    rc = noxtls_tls_send_record(&ctx, TLS_RECORD_APPLICATION_DATA,
                                expected + 5U, 4U);
    if(rc != NOXTLS_RETURN_SUCCESS || !noxtls_tls_has_pending_output(&ctx)) return 2;
    do {
        rc = noxtls_tls_flush(&ctx);
        attempts++;
    } while(rc == NOXTLS_RETURN_WANT_WRITE && attempts < 16U);
    if(rc != NOXTLS_RETURN_SUCCESS || io.written_len != sizeof(expected) ||
       memcmp(io.written, expected, sizeof(expected)) != 0) return 3;
    noxtls_tls_context_free(&ctx);
    return 0;
}

static int test_fragmented_read(void)
{
    static const uint8_t input[] = {
        TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x05,
        'M', 'o', 'd', 'b', 'N'
    };
    tls_context_t ctx;
    tls_record_t record;
    test_io_t io;
    noxtls_return_t rc;
    uint32_t attempts = 0U;

    memset(&io, 0, sizeof(io));
    io.input = input;
    io.input_len = sizeof(input);
    io.max_chunk = 2U;
    if(noxtls_tls_context_init(&ctx, TLS_ROLE_SERVER, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS) return 1;
    noxtls_tls_set_io_callbacks(&ctx, test_send, test_recv, &io);
    noxtls_tls_set_io_mode(&ctx, TLS_IO_MODE_NON_BLOCKING);

    do {
        rc = noxtls_tls_recv_record(&ctx, &record);
        attempts++;
    } while(rc == NOXTLS_RETURN_WANT_READ && attempts < 16U);
    if(rc != NOXTLS_RETURN_SUCCESS || record.length != 5U ||
       record.data == NULL || memcmp(record.data, "ModbN", 5U) != 0) return 2;
    noxtls_free(record.data);
    noxtls_tls_context_free(&ctx);
    return 0;
}

static int test_fragmented_client_hello_detection(void)
{
    static const uint8_t input[] = {
        TLS_RECORD_HANDSHAKE, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00,
        TLS_RECORD_HANDSHAKE, 0x03, 0x01, 0x00, 0x2B,
        0x00, 0x29, 0x03, 0x03,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x00, 0x00, 0x02, 0x00, 0x2F, 0x01, 0x00
    };
    tls_context_t ctx;
    test_io_t io;
    noxtls_return_t rc;
    uint16_t version = 0U;
    uint8_t *hello = NULL;
    uint32_t hello_length = 0U;
    uint32_t attempts = 0U;

    memset(&io, 0, sizeof(io));
    io.input = input;
    io.input_len = sizeof(input);
    io.max_chunk = 3U;
    if(noxtls_tls_context_init(&ctx, TLS_ROLE_SERVER, TLS_VERSION_1_2) !=
       NOXTLS_RETURN_SUCCESS) return 1;
    noxtls_tls_set_io_callbacks(&ctx, test_send, test_recv, &io);
    noxtls_tls_set_io_mode(&ctx, TLS_IO_MODE_NON_BLOCKING);
    do {
        rc = noxtls_tls_detect_version(&ctx, &version, &hello, &hello_length);
        attempts++;
    } while(rc == NOXTLS_RETURN_WANT_READ && attempts < 64U);
    if(rc != NOXTLS_RETURN_SUCCESS || version != TLS_VERSION_1_2 ||
       hello == NULL || hello_length != 45U) return 2;
    noxtls_free(hello);
    noxtls_tls_context_free(&ctx);
    return 0;
}

int main(void)
{
    int rc = test_partial_write();
    if(rc != 0) {
        fprintf(stderr, "partial-write test failed: %d\n", rc);
        return rc;
    }
    rc = test_fragmented_read();
    if(rc != 0) {
        fprintf(stderr, "fragmented-read test failed: %d\n", rc);
        return 10 + rc;
    }
    rc = test_fragmented_client_hello_detection();
    if(rc != 0) {
        fprintf(stderr, "fragmented ClientHello test failed: %d\n", rc);
        return 20 + rc;
    }
    return 0;
}
