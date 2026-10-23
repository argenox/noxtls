/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* This file is part of the NoxTLS Library.
*
* File:    main.c
* Summary: X.509 Certificate Utility Application
*
*/

/**
 * @file main.c
 * @brief X.509 certificate parsing and verification utility.
 * @defgroup noxtls_app_cert Cert utility
 * @details
 * Operations: read, write, info, convert, verify, keyinfo, keymatch, keywrite, debug, keydebug.
 * Parameters: operation name then options. Options: -i &lt;file&gt; input, -o &lt;file&gt; output,
 * -I der|pem input format, -O der|pem output format, -f der|pem output format,
 * -d debug, -v version/verbose, -h help.
 * @example
 * cert read -i cert.der
 * cert info -i cert.pem
 * cert convert -i cert.der -I der -o cert.pem -O pem
 * cert verify -i cert.der
 * cert keyinfo -i key.pem
 * cert keymatch -i cert.pem -k key.pem
 * cert keywrite -i key.der -o key_out.pem -f pem
 * cert -h
 */

/* MUST be the FIRST #include: app-local noxtls_config.h (project policy)
 * MSVC searches the directory of the including header first for "..."
 * style includes; if a library header pulls in "noxtls_config.h" before
 * this app does, the top-level config wins. Hoisting our local one
 * here ensures _NOXTLS_CONFIG_H_ is set from THIS file. */
#include "noxtls_config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "noxtls-lib/common/getopt_compat.h"
#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls_common.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/certs/certificates.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#if NOXTLS_FEATURE_ED25519
#include "noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "noxtls-lib/pkc/ed448/noxtls_ed448.h"
#endif
#include "utility/base64.h"
#include "noxtls_ct.h"

/* noxtls_getopt() is POSIX getopt(int, char * const[], const char *) on
 * non-Windows hosts and the uint8_t-based shim from getopt_win.h on Windows.
 * The handlers keep argv as uint8_t text (like the NoxTLS API), so adapt the
 * pointer type at the getopt boundary only. */
#ifdef _WIN32
#define APP_GETOPT_ARGV(v) ((uint8_t * const *)(v))
#else
#define APP_GETOPT_ARGV(v) ((char * const *)(v))
#endif

/* ============================================================================
 * Application-private static workspace (per project policy)
 * ============================================================================
 *
 * Every application owns a large statically-allocated workspace buffer; all
 * dynamic allocations made by this translation unit are served out of it via
 * a simple bump arena. The buffer's size lives in this app's noxtls_config.h
 * (NOXTLS_APP_STATIC_BUFFER_SIZE) so it can be tuned independently per app.
 *
 * free() is a no-op; the whole arena is released en-masse via
 * app_workspace_reset() (e.g. between commands) which also wipes any
 * transient secret material that may have been allocated.
 */
static uint8_t  g_app_workspace[NOXTLS_APP_STATIC_BUFFER_SIZE];
static size_t   g_app_workspace_off = 0U;
#define APP_WORKSPACE_ALIGN ((size_t)16U)
    
/**
 * @brief Allocate workspace
 *
 * @param[in] n The size to allocate
 * @return The pointer to the allocated workspace
 */
static void *app_workspace_alloc(size_t n)
{
    size_t off = (g_app_workspace_off + (APP_WORKSPACE_ALIGN - 1U)) &
                 ~(APP_WORKSPACE_ALIGN - 1U);
    if(n == 0U || off > sizeof(g_app_workspace) ||
       n > sizeof(g_app_workspace) - off) {
        return NULL;
    }
    g_app_workspace_off = off + n;
    return &g_app_workspace[off];
}

/**
 * @brief Free the workspace
 *
 * @param[in] p The pointer to the workspace to free
 * @return void
 */
static void app_workspace_free(void *p) 
{ 
    (void)p; 
}

/**
 * @brief Reset the workspace
 *
 * @return void
 */
static void app_workspace_reset(void)
{
    if(g_app_workspace_off > 0U) {
        memset(g_app_workspace, 0, g_app_workspace_off);
    }
    g_app_workspace_off = 0U;
}

/* Redirect malloc()/free() in this translation unit to the static workspace.
 * Library and standard headers have already been pulled in above; they
 * declared malloc/free as plain functions and are unaffected. App code below
 * uses these macros transparently. */
#undef malloc
#undef free
#define malloc(n) app_workspace_alloc(n)
#define free(p)   app_workspace_free(p)

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 0

typedef enum {
    CERT_OP_READ,
    CERT_OP_WRITE,
    CERT_OP_INFO,
    CERT_OP_CONVERT,
    CERT_OP_VERIFY,
    CERT_OP_KEY_INFO,
    CERT_OP_KEY_MATCH,
    CERT_OP_KEY_WRITE,
    CERT_OP_DEBUG,
    CERT_OP_KEY_DEBUG,
} cert_operation_t;

typedef enum {
    CERT_FORMAT_AUTO = 0,
    CERT_FORMAT_DER,
    CERT_FORMAT_PEM,
} cert_format_t;

uint8_t debug_lvl = 0;

/**
 * @brief Open the file
 *
 * @param[in] filename The filename to open the file from
 * @param[in] mode The mode to open the file from
 * @return The file pointer
 */
static FILE *noxtls_fopen(const uint8_t *filename, const uint8_t *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}

/**
 * @brief Parse the format
 *
 * @param[in] format The format to parse
 * @param[out] parsed The parsed format
 * @return The return code
 */
static int parse_format(const uint8_t *format, cert_format_t *parsed)
{
    if(parsed == NULL) {
        return -1;
    }
    if(format == NULL || noxtls_u8_strcmp(format, "auto") == 0) {
        *parsed = CERT_FORMAT_AUTO;
        return 0;
    }
    if(noxtls_u8_strcmp(format, "der") == 0 || noxtls_u8_strcmp(format, "DER") == 0) {
        *parsed = CERT_FORMAT_DER;
        return 0;
    }
    if(noxtls_u8_strcmp(format, "pem") == 0 || noxtls_u8_strcmp(format, "PEM") == 0) {
        *parsed = CERT_FORMAT_PEM;
        return 0;
    }
    return -1;
}

/**
 * @brief Read the file and allocate the data
 *
 * @param[in] filename The filename to read the file from
 * @param[out] data The data to read the file into
 * @param[out] len The length of the data to read the file into
 * @return The return code
 */
static noxtls_return_t read_file_alloc(const uint8_t *filename, uint8_t **data, uint32_t *len)
{
    FILE *fp = NULL;
    long file_size = 0;
    uint8_t *buffer = NULL;

    if(filename == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    file_size = ftell(fp);
    if(file_size < 0 || file_size > (long)UINT32_MAX) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    if(fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    buffer = (uint8_t *)malloc((size_t)file_size == 0U ? 1U : (size_t)file_size);
    if(buffer == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    if(file_size > 0) {
        size_t read_count = fread(buffer, 1, (size_t)file_size, fp);
        if(read_count != (size_t)file_size) {
            free(buffer);
            fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
    }

    fclose(fp);
    *data = buffer;
    *len = (uint32_t)file_size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Load the certificate with format
 *
 * @param[in] cert The certificate to load
 * @param[in] input_file The input file to load the certificate from
 * @param[in] input_format The format of the input file
 * @return The return code
 */
static noxtls_return_t load_certificate_with_format(
    x509_certificate_t *cert,
    const uint8_t *input_file,
    cert_format_t input_format)
{
    uint8_t *data = NULL;
    uint32_t len = 0;
    noxtls_return_t rc;

    if(input_format == CERT_FORMAT_AUTO) {
        return noxtls_x509_certificate_load_file(cert, input_file);
    }

    rc = read_file_alloc(input_file, &data, &len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(input_format == CERT_FORMAT_DER) {
        rc = noxtls_x509_certificate_parse_der(cert, data, len);
    } else {
        rc = noxtls_x509_certificate_parse_pem(cert, data, len);
    }

    free(data);
    return rc;
}

/**
 * @brief Load the private key with format
 *
 * @param[in] key The private key to load
 * @param[in] input_file The input file to load the private key from
 * @param[in] input_format The format of the input file
 * @return The return code
 */
static noxtls_return_t load_private_key_with_format(
    x509_private_key_t *key,
    const uint8_t *input_file,
    cert_format_t input_format)
{
    uint8_t *data = NULL;
    uint32_t len = 0;
    noxtls_return_t rc;

    if(input_format == CERT_FORMAT_AUTO) {
        return noxtls_x509_private_key_load_file(key, input_file);
    }

    rc = read_file_alloc(input_file, &data, &len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(input_format == CERT_FORMAT_DER) {
        rc = noxtls_x509_private_key_parse_der(key, data, len);
    } else {
        rc = noxtls_x509_private_key_parse_pem(key, data, len);
    }

    free(data);
    return rc;
}

/**
 * @brief Print the return reason
 *
 * @param[in] rc The return code
 * @param[in] bad_data_label The label of the bad data
 * @return void
 */
static void print_return_reason(noxtls_return_t rc, const uint8_t *bad_data_label)
{
    switch(rc) {
        case NOXTLS_RETURN_SUCCESS:
            printf("  Reason: Success\n");
            break;
        case NOXTLS_RETURN_NULL:
            printf("  Reason: NULL parameter\n");
            break;
        case NOXTLS_RETURN_FAILED:
            printf("  Reason: File not found, invalid format, or parsing error\n");
            break;
        case NOXTLS_RETURN_INVALID_PARAM:
            printf("  Reason: Invalid parameter\n");
            break;
        case NOXTLS_RETURN_INVALID_BLOCK_SIZE:
            printf("  Reason: Invalid block size\n");
            break;
        case NOXTLS_RETURN_INVALID_ALGORITHM:
            printf("  Reason: Invalid algorithm\n");
            break;
        case NOXTLS_RETURN_BAD_DATA:
            printf("  Reason: %s\n", bad_data_label);
            break;
        case NOXTLS_RETURN_TIMEOUT:
            printf("  Reason: Operation timed out\n");
            break;
        case NOXTLS_RETURN_NOT_SUPPORTED:
            printf("  Reason: Not supported\n");
            break;
        case NOXTLS_RETURN_NOT_INITIALIZED:
            printf("  Reason: Not initialized\n");
            break;
        case NOXTLS_RETURN_NOT_ENOUGH_MEMORY:
            printf("  Reason: Not enough memory\n");
            break;
        case NOXTLS_RETURN_NOT_ENOUGH_ENTROPY:
            printf("  Reason: Not enough entropy\n");
            break;
        default:
            printf("  Reason: Unknown error (code: %d)\n", rc);
            break;
    }
}

/**
 * @brief Print the hexadecimal data
 *
 * @param[in] data The data to print
 * @param[in] len The length of the data to print
 * @return void
 */
void print_hex(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * @brief Print the usage information
 *
 * @param[in] name The name of the application
 * @return void
 */
void print_usage(const uint8_t *name)
{
    printf("usage: %s [operation] <parameters>\n", name);
    printf("\nSupported Operations:\n\n");
    printf("  read       - Read and display certificate information\n");
    printf("  write      - Write certificate to file\n");
    printf("  info       - Display detailed certificate information\n");
    printf("  convert    - Convert certificate between DER and PEM formats\n");
    printf("  verify     - Verify certificate validity\n");
    printf("  keyinfo    - Read and display private key information\n");
    printf("  keymatch   - Check whether a private key matches a certificate\n");
    printf("  keywrite   - Write private key to file (convert format)\n");
    printf("  debug      - Print detailed debug information about certificate\n");
    printf("  keydebug   - Print detailed debug information about private key\n");
    
    printf("\nCommandline Switches:\n\n");
    printf("  -i <file>      Input file (certificate or private key)\n");
    printf("  -k <file>      Private key input for keymatch\n");
    printf("  -o <file>      Output file\n");
    printf("  -I <format>    Input format: der, pem, or auto (default: auto)\n");
    printf("  -O <format>    Output format: der or pem\n");
    printf("  -f <format>    Output format alias for -O: der or pem\n");
    printf("  -d             Enable debug mode\n");
    printf("  -v             Version Information\n");
    printf("  -h             Help\n");
    
    printf("\nExamples:\n\n");
    printf("  %s read -i cert.der\n", name);
    printf("  %s read -i cert.pem\n", name);
    printf("  %s info -i cert.der\n", name);
    printf("  %s convert -i cert.der -I der -o cert.pem -O pem\n", name);
    printf("  %s convert -i cert.pem -I pem -o cert.der -O der\n", name);
    printf("  %s verify -i cert.der\n", name);
    printf("  %s keyinfo -i key.pem\n", name);
    printf("  %s keymatch -i cert.pem -k private.key\n", name);
    printf("  %s keywrite -i key.der -o key_out.pem -f pem\n", name);
    printf("  %s debug -i cert.der\n", name);
    printf("  %s debug -i cert.der -v (verbose with raw data)\n", name);
    printf("  %s keydebug -i key.pem\n", name);
    printf("  %s keydebug -i key.pem -v (verbose with raw data)\n", name);
    printf("  %s write -i cert.der -I der -o cert_out.pem -O pem\n", name);
    
    printf("\n");
}

/**
 * @brief Print the version information
 *
 * @return void
 */
void print_version(void)
{
    printf("Certificate Utility v%d.%d.%d\n", APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}

/**
 * @brief Print the certificate information
 *
 * @param[in] cert The certificate to print the information from
 * @return void
 */
void print_certificate_info(const x509_certificate_t *cert)
{
    
    if(cert == NULL || !cert->parsed) {
        printf("Certificate not parsed or invalid\n");
        return;
    }
    
    printf("\n=== Certificate Information ===\n\n");
    
    printf("Version: %d\n", cert->version);
    
    printf("Serial Number: ");
    print_hex(cert->serial_number, cert->serial_number_len);
    
    printf("Issuer: %s\n", cert->issuer_dn);
    printf("Subject: %s\n", cert->subject_dn);
    
    printf("Not Before: ");
    if(cert->not_before[0] != 0) {
        /* Find actual length by looking for null terminator or end of buffer */
        uint32_t time_len = 0;
        while(time_len < 15 && cert->not_before[time_len] != 0) {
            time_len++;
        }
        /* Use the actual length found, not the full buffer size */
        uint8_t time_str[64];
        if(noxtls_x509_parse_time(cert->not_before, time_len, time_str, sizeof(time_str)) == NOXTLS_RETURN_SUCCESS) {
            printf("%s\n", time_str);
        } else {
            /* Fallback: print raw time */
            printf("%.*s\n", (int)time_len, cert->not_before);
        }
    } else {
        printf("(not available)\n");
    }
    
    printf("Not After: ");
    if(cert->not_after[0] != 0) {
        /* Find actual length by looking for null terminator or end of buffer */
        uint32_t time_len = 0;
        while(time_len < 15 && cert->not_after[time_len] != 0) {
            time_len++;
        }
        /* Use the actual length found, not the full buffer size */
        uint8_t time_str[64];
        if(noxtls_x509_parse_time(cert->not_after, time_len, time_str, sizeof(time_str)) == NOXTLS_RETURN_SUCCESS) {
            printf("%s\n", time_str);
        } else {
            /* Fallback: print raw time */
            printf("%.*s\n", (int)time_len, cert->not_after);
        }
    } else {
        printf("(not available)\n");
    }
    
    if(cert->rsa_modulus) {
        printf("Public Key Algorithm: RSA\n");
        printf("RSA Modulus Length: %u bytes\n", cert->rsa_modulus_len);
        printf("RSA Modulus: ");
        print_hex(cert->rsa_modulus, cert->rsa_modulus_len);
        printf("RSA Exponent Length: %u bytes\n", cert->rsa_exponent_len);
        printf("RSA Exponent: ");
        print_hex(cert->rsa_exponent, cert->rsa_exponent_len);
    } else if(cert->ecc_public_key) {
        printf("Public Key Algorithm: ECC\n");
        printf("ECC Public Key Length: %u bytes\n", cert->ecc_public_key_len);
        printf("ECC Public Key: ");
        print_hex(cert->ecc_public_key, cert->ecc_public_key_len);
    } else if(cert->has_ed25519) {
        printf("Public Key Algorithm: Ed25519 (id-Ed25519)\n");
        printf("Ed25519 Public Key (32 bytes): ");
        print_hex(cert->ed25519_public_key, 32);
    } else if(cert->has_ed448) {
        printf("Public Key Algorithm: Ed448 (id-Ed448)\n");
        printf("Ed448 Public Key (57 bytes): ");
        print_hex(cert->ed448_public_key, 57);
    }
    
    printf("Signature Length: %u bytes\n", cert->signature_len);
    printf("Signature: ");
    if(cert->signature) {
        print_hex(cert->signature, cert->signature_len);
    } else {
        printf("(not available)\n");
    }
    
    printf("\n");
}

/**
 * @brief Print the private key information
 *
 * @param[in] key The private key to print the information from
 * @return void
 */
void print_private_key_info(const x509_private_key_t *key)
{
    if(key == NULL || !key->parsed) {
        printf("Private key not parsed or invalid\n");
        return;
    }
    
    printf("\n=== Private Key Information ===\n\n");
    
    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        printf("Key Type: RSA\n");
        printf("Format: %s\n", 
               key->format == X509_PRIVATE_KEY_FORMAT_PKCS1 ? "PKCS#1" :
               key->format == X509_PRIVATE_KEY_FORMAT_PKCS8 ? "PKCS#8" : "Unknown");
        
        if(key->rsa_modulus) {
            printf("RSA Modulus Length: %u bytes\n", key->rsa_modulus_len);
            printf("RSA Modulus: ");
            print_hex(key->rsa_modulus, key->rsa_modulus_len);
        }
        
        if(key->rsa_public_exponent) {
            printf("RSA Public Exponent Length: %u bytes\n", key->rsa_public_exponent_len);
            printf("RSA Public Exponent: ");
            print_hex(key->rsa_public_exponent, key->rsa_public_exponent_len);
        }
        
        if(key->rsa_private_exponent) {
            printf("RSA Private Exponent Length: %u bytes\n", key->rsa_private_exponent_len);
            printf("RSA Private Exponent: ");
            print_hex(key->rsa_private_exponent, key->rsa_private_exponent_len);
        }
        
        if(key->rsa_prime1) {
            printf("RSA Prime 1 (p) Length: %u bytes\n", key->rsa_prime1_len);
            printf("RSA Prime 1 (p): ");
            print_hex(key->rsa_prime1, key->rsa_prime1_len);
        }
        
        if(key->rsa_prime2) {
            printf("RSA Prime 2 (q) Length: %u bytes\n", key->rsa_prime2_len);
            printf("RSA Prime 2 (q): ");
            print_hex(key->rsa_prime2, key->rsa_prime2_len);
        }
    } else if(key->key_type == X509_PRIVATE_KEY_ECC) {
        printf("Key Type: ECC\n");
        printf("Format: %s\n",
               key->format == X509_PRIVATE_KEY_FORMAT_SEC1 ? "SEC1" :
               key->format == X509_PRIVATE_KEY_FORMAT_PKCS8 ? "PKCS#8" : "Unknown");
        
        if(key->ecc_private_key) {
            printf("ECC Private Key Length: %u bytes\n", key->ecc_private_key_len);
            printf("ECC Private Key: ");
            print_hex(key->ecc_private_key, key->ecc_private_key_len);
        }
        
        if(key->ecc_public_key) {
            printf("ECC Public Key Length: %u bytes\n", key->ecc_public_key_len);
            printf("ECC Public Key: ");
            print_hex(key->ecc_public_key, key->ecc_public_key_len);
        }
    }
    
    if(key->encrypted) {
        printf("Status: Encrypted (decryption not supported)\n");
    } else {
        printf("Status: Unencrypted\n");
    }
    
    printf("\n");
}

/**
 * @brief Read the certificate handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t read_certificate_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL) {
        printf("Error: Input file required (-i)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_certificate_init(&cert);
    
    rc = noxtls_x509_certificate_load_file(&cert, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load certificate from %s\n", input_file);
        print_return_reason(rc, "Invalid certificate data");
        noxtls_x509_certificate_free(&cert);
        return rc;
    }
    
    print_certificate_info(&cert);
    
    noxtls_x509_certificate_free(&cert);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Write the certificate handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t write_certificate_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    const uint8_t *output_file = NULL;
    cert_format_t input_format = CERT_FORMAT_AUTO;
    cert_format_t output_format = CERT_FORMAT_PEM;
    x509_certificate_t cert;
    FILE *fp;
    uint8_t *output_data = NULL;
    uint32_t output_len = 0;
    noxtls_return_t rc;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:o:f:I:O:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'f':
            case 'O':
                if(parse_format(optarg, &output_format) != 0 || output_format == CERT_FORMAT_AUTO) {
                    printf("Error: Invalid output format. Use 'der' or 'pem'\n");
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                break;
            case 'I':
                if(parse_format(optarg, &input_format) != 0) {
                    printf("Error: Invalid input format. Use 'der', 'pem', or 'auto'\n");
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL || output_file == NULL) {
        printf("Error: Both input (-i) and output (-o) files required\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_certificate_init(&cert);
    
    rc = load_certificate_with_format(&cert, input_file, input_format);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load certificate from %s\n", input_file);
        print_return_reason(rc, "Invalid certificate data");
        noxtls_x509_certificate_free(&cert);
        return rc;
    }
    
    if(output_format == CERT_FORMAT_PEM) {
        /* Write as PEM */
        output_len = cert.raw_data_len * 2;  /* PEM is larger than DER */
        output_data = (uint8_t*)malloc(output_len);
        if(output_data == NULL) {
            noxtls_x509_certificate_free(&cert);
            return NOXTLS_RETURN_FAILED;
        }
        
        rc = noxtls_certificate_der_to_pem(cert.raw_data, cert.raw_data_len, output_data, &output_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(output_data);
            noxtls_x509_certificate_free(&cert);
            return rc;
        }
    } else if(output_format == CERT_FORMAT_DER) {
        /* Write as DER */
        output_data = cert.raw_data;
        output_len = cert.raw_data_len;
    }
    
    fp = noxtls_fopen(output_file, "wb");
    if(fp == NULL) {
        if(output_format == CERT_FORMAT_PEM) {
            free(output_data);
        }
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(fwrite(output_data, 1, output_len, fp) != output_len) {
        fclose(fp);
        if(output_format == CERT_FORMAT_PEM) {
            free(output_data);
        }
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_FAILED;
    }
    
    fclose(fp);
    
    if(output_format == CERT_FORMAT_PEM) {
        free(output_data);
    }
    
    printf("Certificate written to %s (%u bytes)\n", output_file, output_len);
    
    noxtls_x509_certificate_free(&cert);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Print the certificate information handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t info_certificate_handler(int argc, uint8_t **argv)
{
    return read_certificate_handler(argc, argv);
}

/**
 * @brief Convert the certificate handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t convert_certificate_handler(int argc, uint8_t **argv)
{
    return write_certificate_handler(argc, argv);
}

/**
 * @brief Verify the certificate handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t verify_certificate_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL) {
        printf("Error: Input file required (-i)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_certificate_init(&cert);
    
    rc = noxtls_x509_certificate_load_file(&cert, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load certificate from %s\n", input_file);
        print_return_reason(rc, "Invalid certificate data");
        noxtls_x509_certificate_free(&cert);
        return rc;
    }
    
    printf("\n=== Certificate Verification ===\n\n");
    
    rc = noxtls_x509_certificate_check_validity(&cert);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        printf("Certificate validity: PASSED\n");
    } else {
        printf("Certificate validity: FAILED\n");
    }
    
    printf("Certificate parsed: %s\n", cert.parsed ? "YES" : "NO");
    printf("Certificate version: %d\n", cert.version);
    
    noxtls_x509_certificate_free(&cert);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Print the private key information handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t keyinfo_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    x509_private_key_t key;
    noxtls_return_t rc;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL) {
        printf("Error: Input file required (-i)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_private_key_init(&key);
    
    rc = noxtls_x509_private_key_load_file(&key, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load private key from %s\n", input_file);
        print_return_reason(rc, "Invalid private key data");
        noxtls_x509_private_key_free(&key);
        return rc;
    }
    
    print_private_key_info(&key);
    
    noxtls_x509_private_key_free(&key);
    
    return NOXTLS_RETURN_SUCCESS;
}

static void keymatch_trim_integer(const uint8_t **value, uint32_t *value_len)
{
    if((value == NULL) || (value_len == NULL) || (*value == NULL)) {
        return;
    }
    while((*value_len > 1U) && ((*value)[0] == 0U)) {
        *value = &(*value)[1];
        (*value_len)--;
    }
}

static int keymatch_integer_equal(const uint8_t *left, uint32_t left_len,
                                  const uint8_t *right, uint32_t right_len)
{
    keymatch_trim_integer(&left, &left_len);
    keymatch_trim_integer(&right, &right_len);
    if((left == NULL) || (right == NULL) || (left_len == 0U) || (right_len == 0U)) {
        return 0;
    }
    return (left_len == right_len) &&
           (noxtls_ct_memcmp(left, right, (size_t)left_len) == 0);
}

static const uint8_t s_keymatch_challenge[] = "NoxTLS certificate/private-key match check v1";

static noxtls_return_t keymatch_rsa_signature(const x509_certificate_t *cert,
                                               const x509_private_key_t *key,
                                               int *matches)
{
    const uint8_t *modulus = cert->rsa_modulus;
    const uint8_t *exponent = cert->rsa_exponent;
    uint32_t modulus_len = cert->rsa_modulus_len;
    uint32_t exponent_len = cert->rsa_exponent_len;
    rsa_key_size_t rsa_size;
    rsa_key_t private_rsa;
    rsa_key_t certificate_rsa;
    uint8_t signature[RSA_MAX_KEY_SIZE / 8U];
    uint32_t signature_len = sizeof(signature);
    noxtls_return_t rc;
    int private_rsa_ready = 0;
    int certificate_rsa_ready = 0;

    if((cert->rsa_modulus == NULL) || (cert->rsa_exponent == NULL) ||
       (key->rsa_modulus == NULL) || (key->rsa_public_exponent == NULL)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(!keymatch_integer_equal(cert->rsa_modulus, cert->rsa_modulus_len,
                               key->rsa_modulus, key->rsa_modulus_len) ||
       !keymatch_integer_equal(cert->rsa_exponent, cert->rsa_exponent_len,
                               key->rsa_public_exponent, key->rsa_public_exponent_len)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    keymatch_trim_integer(&modulus, &modulus_len);
    keymatch_trim_integer(&exponent, &exponent_len);
    if((modulus_len == 128U)) {
        rsa_size = RSA_1024_BIT;
    } else if(modulus_len == 256U) {
        rsa_size = RSA_2048_BIT;
    } else if(modulus_len == 384U) {
        rsa_size = RSA_3072_BIT;
    } else if(modulus_len == 512U) {
        rsa_size = RSA_4096_BIT;
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    rc = noxtls_x509_private_key_to_rsa_key(key, &private_rsa);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    private_rsa_ready = 1;
    rc = noxtls_rsa_key_init(&certificate_rsa, rsa_size);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        certificate_rsa_ready = 1;
        if((modulus_len > certificate_rsa.key_bytes) ||
           (exponent_len > certificate_rsa.key_bytes)) {
            rc = NOXTLS_RETURN_BAD_DATA;
        } else {
            memcpy(&certificate_rsa.n[certificate_rsa.key_bytes - modulus_len], modulus, modulus_len);
            memcpy(&certificate_rsa.e[certificate_rsa.key_bytes - exponent_len], exponent, exponent_len);
            rc = noxtls_rsa_sign(&private_rsa, s_keymatch_challenge,
                                 (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                 signature, &signature_len, NOXTLS_HASH_SHA_256);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_rsa_verify(&certificate_rsa, s_keymatch_challenge,
                                       (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                       signature, signature_len, NOXTLS_HASH_SHA_256);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    *matches = 1;
                } else if((rc == NOXTLS_RETURN_FAILED) || (rc == NOXTLS_RETURN_BAD_DATA)) {
                    *matches = 0;
                    rc = NOXTLS_RETURN_SUCCESS;
                }
            }
        }
    }

    noxtls_secure_zero(signature, sizeof(signature));
    if(certificate_rsa_ready != 0) {
        (void)noxtls_rsa_key_free(&certificate_rsa);
    }
    if(private_rsa_ready != 0) {
        (void)noxtls_rsa_key_free(&private_rsa);
    }
    return rc;
}

#if NOXTLS_FEATURE_ML_DSA || NOXTLS_FEATURE_SLH_DSA || NOXTLS_FEATURE_FALCON
static noxtls_return_t keymatch_pqc_signature(const x509_certificate_t *cert,
                                               const x509_private_key_t *key,
                                               int *matches)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t signature_max = 0U;
    uint32_t signature_len = 0U;
    uint8_t *signature = NULL;

    if((cert == NULL) || (key == NULL) || (matches == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(key->key_type == X509_PRIVATE_KEY_ML_DSA) {
#if NOXTLS_FEATURE_ML_DSA
        if((cert->has_mldsa == 0U) || (cert->mldsa_param != (noxtls_mldsa_param_t)key->pqc_param)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        signature_max = noxtls_mldsa_signature_len((noxtls_mldsa_param_t)key->pqc_param);
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(key->key_type == X509_PRIVATE_KEY_SLH_DSA) {
#if NOXTLS_FEATURE_SLH_DSA
        if((cert->has_slhdsa == 0U) || (cert->slhdsa_param != (noxtls_slhdsa_param_t)key->pqc_param)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        signature_max = noxtls_slhdsa_signature_len((noxtls_slhdsa_param_t)key->pqc_param);
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else if(key->key_type == X509_PRIVATE_KEY_FALCON) {
#if NOXTLS_FEATURE_FALCON
        if((cert->has_falcon == 0U) || (cert->falcon_param != (noxtls_falcon_param_t)key->pqc_param)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        signature_max = noxtls_falcon_signature_len((noxtls_falcon_param_t)key->pqc_param);
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if((signature_max == 0U) || (key->raw_data == NULL) || (key->raw_data_len == 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    signature = (uint8_t *)malloc((size_t)signature_max);
    if(signature == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_x509_private_key_sign_data(key->raw_data, key->raw_data_len,
                                           s_keymatch_challenge, (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                           NOXTLS_HASH_SHA_256, signature, signature_max,
                                           &signature_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(key->key_type == X509_PRIVATE_KEY_ML_DSA) {
#if NOXTLS_FEATURE_ML_DSA
            rc = noxtls_mldsa_verify((noxtls_mldsa_param_t)key->pqc_param,
                                     cert->mldsa_public_key, s_keymatch_challenge,
                                     (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                     signature, signature_len);
#else
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else if(key->key_type == X509_PRIVATE_KEY_SLH_DSA) {
#if NOXTLS_FEATURE_SLH_DSA
            rc = noxtls_slhdsa_verify((noxtls_slhdsa_param_t)key->pqc_param,
                                      cert->slhdsa_public_key, s_keymatch_challenge,
                                      (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                      signature, signature_len);
#else
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        } else {
#if NOXTLS_FEATURE_FALCON
            rc = noxtls_falcon_verify((noxtls_falcon_param_t)key->pqc_param,
                                      cert->falcon_public_key, s_keymatch_challenge,
                                      (uint32_t)(sizeof(s_keymatch_challenge) - 1U),
                                      signature, signature_len);
#else
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *matches = 1;
        } else if((rc == NOXTLS_RETURN_FAILED) || (rc == NOXTLS_RETURN_BAD_DATA)) {
            /* A validly parsed but unrelated certificate key fails verification. */
            *matches = 0;
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }

    noxtls_secure_zero(signature, (size_t)signature_max);
    free(signature);
    return rc;
}
#endif

static noxtls_return_t certificate_matches_private_key(const x509_certificate_t *cert,
                                                        const x509_private_key_t *key,
                                                        int *matches)
{
    if((cert == NULL) || (key == NULL) || (matches == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *matches = 0;

    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        return keymatch_rsa_signature(cert, key, matches);
    }

    if(key->key_type == X509_PRIVATE_KEY_ECC) {
        noxtls_return_t rc;
        void *cert_key = NULL;
        uint32_t cert_key_type = 0U;
        ecc_key_t private_key_ec;
        ecc_key_t derived_key;
        ecc_key_t *cert_key_ec;

        if((cert->ecc_public_key == NULL) || (cert->ecc_public_key_len == 0U)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        rc = noxtls_x509_certificate_get_public_key(cert, &cert_key, &cert_key_type);
        if((rc != NOXTLS_RETURN_SUCCESS) || (cert_key == NULL) || (cert_key_type != 2U)) {
            if(cert_key != NULL) {
                cert_key_ec = (ecc_key_t *)cert_key;
                (void)noxtls_ecc_key_free(cert_key_ec);
                (void)noxtls_free(cert_key_ec);
            }
            return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_BAD_DATA : rc;
        }
        cert_key_ec = (ecc_key_t *)cert_key;

        rc = noxtls_x509_private_key_to_ecc_key(key, &private_key_ec);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_ecc_key_free(cert_key_ec);
            (void)noxtls_free(cert_key_ec);
            return rc;
        }

        if(private_key_ec.curve_kind == cert_key_ec->curve_kind) {
            if((private_key_ec.Q.size == cert_key_ec->Q.size) && (private_key_ec.Q.size > 0U)) {
                *matches = (noxtls_ct_memcmp(private_key_ec.Q.x, cert_key_ec->Q.x,
                                              (size_t)private_key_ec.Q.size) == 0) &&
                           (noxtls_ct_memcmp(private_key_ec.Q.y, cert_key_ec->Q.y,
                                             (size_t)private_key_ec.Q.size) == 0);
            } else {
                memset(&derived_key, 0, sizeof(derived_key));
                rc = noxtls_ecc_key_import_private(&derived_key, private_key_ec.curve_kind,
                                                    key->ecc_private_key,
                                                    key->ecc_private_key_len);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    *matches = (derived_key.Q.size == cert_key_ec->Q.size) &&
                               (noxtls_ct_memcmp(derived_key.Q.x, cert_key_ec->Q.x,
                                                 (size_t)derived_key.Q.size) == 0) &&
                               (noxtls_ct_memcmp(derived_key.Q.y, cert_key_ec->Q.y,
                                                 (size_t)derived_key.Q.size) == 0);
                }
                (void)noxtls_ecc_key_free(&derived_key);
            }
        }

        (void)noxtls_ecc_key_free(&private_key_ec);
        (void)noxtls_ecc_key_free(cert_key_ec);
        (void)noxtls_free(cert_key_ec);
        return rc;
    }

    if(key->key_type == X509_PRIVATE_KEY_ED25519) {
#if NOXTLS_FEATURE_ED25519
        const uint8_t *seed;
        uint32_t seed_len = 0U;
        uint8_t derived_public[NOXTLS_ED25519_PUBLIC_KEY_SIZE];
        noxtls_return_t rc;
        if(cert->has_ed25519 == 0U) {
            return NOXTLS_RETURN_SUCCESS;
        }
        seed = noxtls_x509_private_key_get_eddsa_seed(key, &seed_len);
        if((seed == NULL) || (seed_len != NOXTLS_ED25519_PRIVATE_KEY_SIZE)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        rc = noxtls_ed25519_public_key(seed, derived_public);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *matches = noxtls_ct_memcmp(derived_public, cert->ed25519_public_key,
                                        sizeof(derived_public)) == 0;
        }
        noxtls_secure_zero(derived_public, sizeof(derived_public));
        return rc;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    if(key->key_type == X509_PRIVATE_KEY_ED448) {
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        const uint8_t *seed;
        uint32_t seed_len = 0U;
        uint8_t derived_public[NOXTLS_ED448_PUBLIC_KEY_SIZE];
        noxtls_return_t rc;
        if(cert->has_ed448 == 0U) {
            return NOXTLS_RETURN_SUCCESS;
        }
        seed = noxtls_x509_private_key_get_eddsa_seed(key, &seed_len);
        if((seed == NULL) || (seed_len != NOXTLS_ED448_PRIVATE_KEY_SIZE)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        rc = noxtls_ed448_public_key(seed, derived_public);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            *matches = noxtls_ct_memcmp(derived_public, cert->ed448_public_key,
                                        sizeof(derived_public)) == 0;
        }
        noxtls_secure_zero(derived_public, sizeof(derived_public));
        return rc;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

#if NOXTLS_FEATURE_ML_DSA || NOXTLS_FEATURE_SLH_DSA || NOXTLS_FEATURE_FALCON
    if((key->key_type == X509_PRIVATE_KEY_ML_DSA) ||
       (key->key_type == X509_PRIVATE_KEY_SLH_DSA) ||
       (key->key_type == X509_PRIVATE_KEY_FALCON)) {
        return keymatch_pqc_signature(cert, key, matches);
    }
#endif

    return NOXTLS_RETURN_NOT_SUPPORTED;
}

static noxtls_return_t keymatch_handler(int argc, uint8_t **argv)
{
    const uint8_t *cert_file = NULL;
    const uint8_t *key_file = NULL;
    x509_certificate_t cert;
    x509_private_key_t key;
    noxtls_return_t rc;
    int matches = 0;
    int c;

    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:k:")) != -1) {
        switch(c) {
            case 'i':
                cert_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    if((cert_file == NULL) || (key_file == NULL)) {
        printf("Error: certificate (-i) and private key (-k) are required\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    (void)noxtls_x509_certificate_init(&cert);
    (void)noxtls_x509_private_key_init(&key);
    rc = noxtls_x509_certificate_load_file(&cert, cert_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Cannot load certificate from %s\n", cert_file);
        print_return_reason(rc, "Invalid certificate data");
        (void)noxtls_x509_certificate_free(&cert);
        (void)noxtls_x509_private_key_free(&key);
        return rc;
    }
    rc = noxtls_x509_private_key_load_file(&key, key_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Cannot load private key from %s\n", key_file);
        print_return_reason(rc, "Invalid private key data");
        (void)noxtls_x509_certificate_free(&cert);
        (void)noxtls_x509_private_key_free(&key);
        return rc;
    }

    rc = certificate_matches_private_key(&cert, &key, &matches);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(matches != 0) {
            printf("Private key matches the certificate public key.\n");
        } else {
            printf("Private key does not match the certificate public key.\n");
            rc = NOXTLS_RETURN_FAILED;
        }
    } else {
        printf("Error: NoxTLS could not compare this private key and certificate\n");
        print_return_reason(rc, "Key match operation failed");
    }

    (void)noxtls_x509_certificate_free(&cert);
    (void)noxtls_x509_private_key_free(&key);
    return rc;
}

/**
 * @brief Write the private key handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t keywrite_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    const uint8_t *output_file = NULL;
    cert_format_t input_format = CERT_FORMAT_AUTO;
    cert_format_t output_format = CERT_FORMAT_PEM;
    x509_private_key_t key;
    FILE *fp;
    uint8_t *output_data = NULL;
    uint32_t output_len = 0;
    noxtls_return_t rc;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:o:f:I:O:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'f':
            case 'O':
                if(parse_format(optarg, &output_format) != 0 || output_format == CERT_FORMAT_AUTO) {
                    printf("Error: Invalid output format. Use 'der' or 'pem'\n");
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                break;
            case 'I':
                if(parse_format(optarg, &input_format) != 0) {
                    printf("Error: Invalid input format. Use 'der', 'pem', or 'auto'\n");
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL || output_file == NULL) {
        printf("Error: Both input (-i) and output (-o) files required\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_private_key_init(&key);
    
    rc = load_private_key_with_format(&key, input_file, input_format);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load private key from %s\n", input_file);
        print_return_reason(rc, "Invalid private key data");
        noxtls_x509_private_key_free(&key);
        return rc;
    }
    
    if(output_format == CERT_FORMAT_PEM) {
        /* Write as PEM */
        if(key.raw_data == NULL) {
            printf("Error: No raw data available for conversion\n");
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        
        output_len = key.raw_data_len * 2;  /* PEM is larger than DER */
        output_data = (uint8_t*)malloc(output_len);
        if(output_data == NULL) {
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        
        /* Determine PEM header based on key type and format */
        const uint8_t *begin_marker;
        const uint8_t *end_marker;
        
        if(key.key_type == X509_PRIVATE_KEY_RSA) {
            if(key.format == X509_PRIVATE_KEY_FORMAT_PKCS1) {
                begin_marker = "-----BEGIN RSA PRIVATE KEY-----\n";
                end_marker = "-----END RSA PRIVATE KEY-----\n";
            } else {
                begin_marker = "-----BEGIN PRIVATE KEY-----\n";
                end_marker = "-----END PRIVATE KEY-----\n";
            }
        } else if(key.key_type == X509_PRIVATE_KEY_ECC) {
            if(key.format == X509_PRIVATE_KEY_FORMAT_SEC1) {
                begin_marker = "-----BEGIN EC PRIVATE KEY-----\n";
                end_marker = "-----END EC PRIVATE KEY-----\n";
            } else {
                begin_marker = "-----BEGIN PRIVATE KEY-----\n";
                end_marker = "-----END PRIVATE KEY-----\n";
            }
        } else {
            begin_marker = "-----BEGIN PRIVATE KEY-----\n";
            end_marker = "-----END PRIVATE KEY-----\n";
        }
        
        /* Build PEM */
        size_t offset = 0;
        size_t buffer_size = output_len;
        size_t begin_len = noxtls_u8_strlen(begin_marker);
        size_t end_len = noxtls_u8_strlen(end_marker);
        if(begin_len > buffer_size) {
            free(output_data);
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(output_data + offset, begin_marker, begin_len);
        offset += begin_len;
        
        /* Base64 encode the DER data */
        int b64_len = noxtls_base64_encode(key.raw_data, key.raw_data_len, (uint8_t *)(output_data + offset));
        if(b64_len < 0 || (size_t)b64_len > buffer_size - offset) {
            free(output_data);
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        offset += (size_t)b64_len;
        
        /* Add newline and end marker */
        if(offset + 1 + end_len > buffer_size) {
            free(output_data);
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        output_data[offset++] = '\n';
        memcpy(output_data + offset, end_marker, end_len);
        offset += end_len;
        if(offset > UINT32_MAX) {
            free(output_data);
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        output_len = (uint32_t)offset;
        
    } else if(output_format == CERT_FORMAT_DER) {
        /* Write as DER */
        if(key.raw_data == NULL) {
            printf("Error: No raw data available\n");
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        output_data = key.raw_data;
        output_len = key.raw_data_len;
    }
    
    fp = noxtls_fopen(output_file, "wb");
    if(fp == NULL) {
        if(output_format == CERT_FORMAT_PEM) {
            free(output_data);
        }
        noxtls_x509_private_key_free(&key);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(fwrite(output_data, 1, output_len, fp) != output_len) {
        fclose(fp);
        if(output_format == CERT_FORMAT_PEM) {
            free(output_data);
        }
        noxtls_x509_private_key_free(&key);
        return NOXTLS_RETURN_FAILED;
    }
    
    fclose(fp);
    
    if(output_format == CERT_FORMAT_PEM) {
        free(output_data);
    }
    
    printf("Private key written to %s (%u bytes)\n", output_file, output_len);
    
    noxtls_x509_private_key_free(&key);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Debug the certificate handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t debug_certificate_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    uint8_t verbose = 0;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:vd")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL) {
        printf("Error: Input file required (-i)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_certificate_init(&cert);
    
    rc = noxtls_x509_certificate_load_file(&cert, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load certificate from %s\n", input_file);
        print_return_reason(rc, "Invalid certificate data");
        noxtls_x509_certificate_free(&cert);
        return rc;
    }
    
    rc = noxtls_x509_certificate_debug_print(&cert, verbose);
    
    noxtls_x509_certificate_free(&cert);
    
    return rc;
}

/**
 * @brief Debug the key handler
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
noxtls_return_t debug_key_handler(int argc, uint8_t **argv)
{
    const uint8_t *input_file = NULL;
    x509_private_key_t key;
    noxtls_return_t rc;
    uint8_t verbose = 0;
    int c;
    
    while((c = noxtls_getopt(argc, APP_GETOPT_ARGV(argv), "i:vd")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'd':
                debug_lvl = 1;
                break;
            default:
                return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    
    if(input_file == NULL) {
        printf("Error: Input file required (-i)\n");
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    noxtls_x509_private_key_init(&key);
    
    rc = noxtls_x509_private_key_load_file(&key, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load private key from %s\n", input_file);
        print_return_reason(rc, "Invalid private key data");
        noxtls_x509_private_key_free(&key);
        return rc;
    }
    
    rc = noxtls_x509_private_key_debug_print(&key, verbose);
    
    noxtls_x509_private_key_free(&key);
    
    return rc;
}

/**
 * @brief Main function
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return The exit status
 */
int main(int argc, char **argv)
{
    cert_operation_t op = CERT_OP_READ;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t **op_argv = NULL;
    
    if(argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    
    /* Parse operation */
    if(noxtls_u8_strcmp(argv[1], "read") == 0) {
        op = CERT_OP_READ;
    } else if(noxtls_u8_strcmp(argv[1], "write") == 0) {
        op = CERT_OP_WRITE;
    } else if(noxtls_u8_strcmp(argv[1], "info") == 0) {
        op = CERT_OP_INFO;
    } else if(noxtls_u8_strcmp(argv[1], "convert") == 0) {
        op = CERT_OP_CONVERT;
    } else if(noxtls_u8_strcmp(argv[1], "verify") == 0) {
        op = CERT_OP_VERIFY;
    } else if(noxtls_u8_strcmp(argv[1], "keyinfo") == 0) {
        op = CERT_OP_KEY_INFO;
    } else if(noxtls_u8_strcmp(argv[1], "keymatch") == 0) {
        op = CERT_OP_KEY_MATCH;
    } else if(noxtls_u8_strcmp(argv[1], "keywrite") == 0) {
        op = CERT_OP_KEY_WRITE;
    } else if(noxtls_u8_strcmp(argv[1], "debug") == 0) {
        op = CERT_OP_DEBUG;
    } else if(noxtls_u8_strcmp(argv[1], "keydebug") == 0) {
        op = CERT_OP_KEY_DEBUG;
    } else if(noxtls_u8_strcmp(argv[1], "-v") == 0 || noxtls_u8_strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    } else if(noxtls_u8_strcmp(argv[1], "-h") == 0 || noxtls_u8_strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        printf("Error: Unknown operation '%s'\n", argv[1]);
        print_usage(argv[0]);
        return -1;
    }
    
    /* Adjust argc/argv for noxtls_getopt. The C runtime passes char strings;
     * the handlers work on uint8_t text like the NoxTLS API, so view argv as
     * uint8_t once here (char and unsigned char share representation). */
    argc--;
    op_argv = (uint8_t **)&argv[1];
    
    /* Execute operation */
    switch(op) {
        case CERT_OP_READ:
            rc = read_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_WRITE:
            rc = write_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_INFO:
            rc = info_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_CONVERT:
            rc = convert_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_VERIFY:
            rc = verify_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_KEY_INFO:
            rc = keyinfo_handler(argc, op_argv);
            break;
        case CERT_OP_KEY_MATCH:
            rc = keymatch_handler(argc, op_argv);
            break;
        case CERT_OP_KEY_WRITE:
            rc = keywrite_handler(argc, op_argv);
            break;
        case CERT_OP_DEBUG:
            rc = debug_certificate_handler(argc, op_argv);
            break;
        case CERT_OP_KEY_DEBUG:
            rc = debug_key_handler(argc, op_argv);
            break;
        default:
            printf("Error: Unknown operation\n");
            return -1;
    }
    
    app_workspace_reset();
    return (rc != NOXTLS_RETURN_SUCCESS) ? -1 : 0;
}
