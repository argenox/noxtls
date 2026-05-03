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
* File:    main.c
* Summary: X.509 Certificate Utility Application
*
*/

/**
 * @file main.c
 * @brief X.509 certificate parsing and verification utility.
 * @defgroup noxtls_app_cert Cert utility
 * @details
 * Operations: read, write, info, convert, verify, keyinfo, keywrite, debug, keydebug.
 * Parameters: operation name then options. Options: -i &lt;file&gt; input, -o &lt;file&gt; output,
 * -f der|pem format, -d debug, -v version/verbose, -h help.
 * @example
 * cert read -i cert.der
 * cert info -i cert.pem
 * cert convert -i cert.der -o cert.pem -f pem
 * cert verify -i cert.der
 * cert keyinfo -i key.pem
 * cert keywrite -i key.der -o key_out.pem -f pem
 * cert -h
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls_common.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/certs/certificates.h"
#include "utility/base64.h"

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
    CERT_OP_KEY_WRITE,
    CERT_OP_DEBUG,
    CERT_OP_KEY_DEBUG,
} cert_operation_t;

uint8_t debug_lvl = 0;

static FILE *noxtls_fopen(const char *filename, const char *mode)
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

static void print_return_reason(noxtls_return_t rc, const char *bad_data_label)
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

void print_hex(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_usage(const char *name)
{
    printf("usage: %s [operation] <parameters>\n", name);
    printf("\nSupported Operations:\n\n");
    printf("  read       - Read and display certificate information\n");
    printf("  write      - Write certificate to file\n");
    printf("  info       - Display detailed certificate information\n");
    printf("  convert    - Convert certificate between DER and PEM formats\n");
    printf("  verify     - Verify certificate validity\n");
    printf("  keyinfo    - Read and display private key information\n");
    printf("  keywrite   - Write private key to file (convert format)\n");
    printf("  debug      - Print detailed debug information about certificate\n");
    printf("  keydebug   - Print detailed debug information about private key\n");
    
    printf("\nCommandline Switches:\n\n");
    printf("  -i <file>      Input file (certificate or private key)\n");
    printf("  -o <file>      Output file\n");
    printf("  -f <format>     Format: der or pem (default: auto-detect)\n");
    printf("  -d             Enable debug mode\n");
    printf("  -v             Version Information\n");
    printf("  -h             Help\n");
    
    printf("\nExamples:\n\n");
    printf("  %s read -i cert.der\n", name);
    printf("  %s read -i cert.pem\n", name);
    printf("  %s info -i cert.der\n", name);
    printf("  %s convert -i cert.der -o cert.pem -f pem\n", name);
    printf("  %s verify -i cert.der\n", name);
    printf("  %s keyinfo -i key.pem\n", name);
    printf("  %s keywrite -i key.der -o key_out.pem -f pem\n", name);
    printf("  %s debug -i cert.der\n", name);
    printf("  %s debug -i cert.der -v (verbose with raw data)\n", name);
    printf("  %s keydebug -i key.pem\n", name);
    printf("  %s keydebug -i key.pem -v (verbose with raw data)\n", name);
    printf("  %s write -i cert.der -o cert_out.pem -f pem\n", name);
    
    printf("\n");
}

void print_version(void)
{
    printf("Certificate Utility v%d.%d.%d\n", APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}

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
        char time_str[64];
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
        char time_str[64];
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

noxtls_return_t read_certificate_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    int c;
    
    while((c = getopt(argc, argv, "i:d")) != -1) {
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

noxtls_return_t write_certificate_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    const char *output_file = NULL;
    const char *format_str = NULL;
    x509_certificate_t cert;
    FILE *fp;
    uint8_t *output_data = NULL;
    uint32_t output_len = 0;
    noxtls_return_t rc;
    int c;
    
    while((c = getopt(argc, argv, "i:o:f:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'f':
                format_str = optarg;
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
    
    rc = noxtls_x509_certificate_load_file(&cert, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load certificate from %s\n", input_file);
        print_return_reason(rc, "Invalid certificate data");
        noxtls_x509_certificate_free(&cert);
        return rc;
    }
    
    if(format_str == NULL || strcmp(format_str, "pem") == 0) {
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
    } else if(strcmp(format_str, "der") == 0) {
        /* Write as DER */
        output_data = cert.raw_data;
        output_len = cert.raw_data_len;
    } else {
        printf("Error: Invalid format. Use 'der' or 'pem'\n");
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    fp = noxtls_fopen(output_file, "wb");
    if(fp == NULL) {
        if(format_str == NULL || strcmp(format_str, "pem") == 0) {
            free(output_data);
        }
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(fwrite(output_data, 1, output_len, fp) != output_len) {
        fclose(fp);
        if(format_str == NULL || strcmp(format_str, "pem") == 0) {
            free(output_data);
        }
        noxtls_x509_certificate_free(&cert);
        return NOXTLS_RETURN_FAILED;
    }
    
    fclose(fp);
    
    if(format_str == NULL || strcmp(format_str, "pem") == 0) {
        free(output_data);
    }
    
    printf("Certificate written to %s (%u bytes)\n", output_file, output_len);
    
    noxtls_x509_certificate_free(&cert);
    
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t info_certificate_handler(int argc, char **argv)
{
    return read_certificate_handler(argc, argv);
}

noxtls_return_t convert_certificate_handler(int argc, char **argv)
{
    return write_certificate_handler(argc, argv);
}

noxtls_return_t verify_certificate_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    int c;
    
    while((c = getopt(argc, argv, "i:d")) != -1) {
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

noxtls_return_t keyinfo_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    x509_private_key_t key;
    noxtls_return_t rc;
    int c;
    
    while((c = getopt(argc, argv, "i:d")) != -1) {
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

noxtls_return_t keywrite_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    const char *output_file = NULL;
    const char *format_str = NULL;
    x509_private_key_t key;
    FILE *fp;
    uint8_t *output_data = NULL;
    uint32_t output_len = 0;
    noxtls_return_t rc;
    int c;
    
    while((c = getopt(argc, argv, "i:o:f:d")) != -1) {
        switch(c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'f':
                format_str = optarg;
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
    
    rc = noxtls_x509_private_key_load_file(&key, input_file);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to load private key from %s\n", input_file);
        print_return_reason(rc, "Invalid private key data");
        noxtls_x509_private_key_free(&key);
        return rc;
    }
    
    if(format_str == NULL || strcmp(format_str, "pem") == 0) {
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
        const char *begin_marker;
        const char *end_marker;
        
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
        size_t begin_len = strlen(begin_marker);
        size_t end_len = strlen(end_marker);
        if(begin_len > buffer_size) {
            free(output_data);
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(output_data + offset, begin_marker, begin_len);
        offset += begin_len;
        
        /* Base64 encode the DER data */
        int b64_len = noxtls_base64_encode(key.raw_data, key.raw_data_len, (char*)(output_data + offset));
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
        
    } else if(strcmp(format_str, "der") == 0) {
        /* Write as DER */
        if(key.raw_data == NULL) {
            printf("Error: No raw data available\n");
            noxtls_x509_private_key_free(&key);
            return NOXTLS_RETURN_FAILED;
        }
        output_data = key.raw_data;
        output_len = key.raw_data_len;
    } else {
        printf("Error: Invalid format. Use 'der' or 'pem'\n");
        noxtls_x509_private_key_free(&key);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    fp = noxtls_fopen(output_file, "wb");
    if(fp == NULL) {
        if(format_str == NULL || strcmp(format_str, "pem") == 0) {
            free(output_data);
        }
        noxtls_x509_private_key_free(&key);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(fwrite(output_data, 1, output_len, fp) != output_len) {
        fclose(fp);
        if(format_str == NULL || strcmp(format_str, "pem") == 0) {
            free(output_data);
        }
        noxtls_x509_private_key_free(&key);
        return NOXTLS_RETURN_FAILED;
    }
    
    fclose(fp);
    
    if(format_str == NULL || strcmp(format_str, "pem") == 0) {
        free(output_data);
    }
    
    printf("Private key written to %s (%u bytes)\n", output_file, output_len);
    
    noxtls_x509_private_key_free(&key);
    
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t debug_certificate_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    x509_certificate_t cert;
    noxtls_return_t rc;
    uint8_t verbose = 0;
    int c;
    
    while((c = getopt(argc, argv, "i:vd")) != -1) {
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

noxtls_return_t debug_key_handler(int argc, char **argv)
{
    const char *input_file = NULL;
    x509_private_key_t key;
    noxtls_return_t rc;
    uint8_t verbose = 0;
    int c;
    
    while((c = getopt(argc, argv, "i:vd")) != -1) {
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

int main(int argc, char **argv)
{
    cert_operation_t op = CERT_OP_READ;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    
    /* Parse operation */
    if(strcmp(argv[1], "read") == 0) {
        op = CERT_OP_READ;
    } else if(strcmp(argv[1], "write") == 0) {
        op = CERT_OP_WRITE;
    } else if(strcmp(argv[1], "info") == 0) {
        op = CERT_OP_INFO;
    } else if(strcmp(argv[1], "convert") == 0) {
        op = CERT_OP_CONVERT;
    } else if(strcmp(argv[1], "verify") == 0) {
        op = CERT_OP_VERIFY;
    } else if(strcmp(argv[1], "keyinfo") == 0) {
        op = CERT_OP_KEY_INFO;
    } else if(strcmp(argv[1], "keywrite") == 0) {
        op = CERT_OP_KEY_WRITE;
    } else if(strcmp(argv[1], "debug") == 0) {
        op = CERT_OP_DEBUG;
    } else if(strcmp(argv[1], "keydebug") == 0) {
        op = CERT_OP_KEY_DEBUG;
    } else if(strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    } else if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        printf("Error: Unknown operation '%s'\n", argv[1]);
        print_usage(argv[0]);
        return -1;
    }
    
    /* Adjust argc/argv for getopt */
    argc--;
    argv++;
    
    /* Execute operation */
    switch(op) {
        case CERT_OP_READ:
            rc = read_certificate_handler(argc, argv);
            break;
        case CERT_OP_WRITE:
            rc = write_certificate_handler(argc, argv);
            break;
        case CERT_OP_INFO:
            rc = info_certificate_handler(argc, argv);
            break;
        case CERT_OP_CONVERT:
            rc = convert_certificate_handler(argc, argv);
            break;
        case CERT_OP_VERIFY:
            rc = verify_certificate_handler(argc, argv);
            break;
        case CERT_OP_KEY_INFO:
            rc = keyinfo_handler(argc, argv);
            break;
        case CERT_OP_KEY_WRITE:
            rc = keywrite_handler(argc, argv);
            break;
        case CERT_OP_DEBUG:
            rc = debug_certificate_handler(argc, argv);
            break;
        case CERT_OP_KEY_DEBUG:
            rc = debug_key_handler(argc, argv);
            break;
        default:
            printf("Error: Unknown operation\n");
            return -1;
    }
    
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return -1;
    }
    
    return 0;
}

