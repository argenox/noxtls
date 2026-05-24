/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    oids.c
* Summary: OIDs
*
*****************************************************************************/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "noxtls_common.h"
#include "oids.h"

/** @brief PKCS#1 OIDs */
const oid_item_t pkcs_1_oids[] = {

    {1, "rsaEncryption",             NULL},
    {2, "md2WithRSAEncryption",      NULL},
    {3, "md4withRSAEncryption",      NULL},
    {4, "md5WithRSAEncryption",      NULL},
    {5, "sha1-with-rsa-signature",   NULL},
    {6, "rsaOAEPEncryptionSET",      NULL},
    {7, "id-RSAES",                  NULL},
    {8, "id-mgf1",                   NULL},
    {9, "id-pSpecified",             NULL},
    {10, "rsassa-pss",               NULL},
    {11, "sha256WithRSAEncryption",  NULL},
    {12, "sha384WithRSAEncryption",  NULL},
    {13, "sha512WithRSAEncryption",  NULL},
    {14, "sha224WithRSAEncryption",  NULL},
    {0, NULL, NULL}
};

/** @brief PKCS#9 OIDs */
const oid_item_t pkcs_9_oids[] = {

    {0, "modules",                       NULL},
    {1, "emailAddress",                  NULL},
    {2, "unstructuredName",              NULL},
    {3, "contentType",                   NULL},
    {4, "messageDigest",                 NULL},
    {5, "signing-time",                  NULL},
    {6, "countersignature",              NULL},
    {7, "challengePassword",             NULL},
    {8, "unstructuredAddress",           NULL},
    {9, "extendedCertificateAttributes", NULL},
    {10, "10",                           NULL},
    {11, "11",                           NULL},
    {12, "12",                           NULL},
    {13, "signingDescription",           NULL},
    {14, "extensionRequest",             NULL},
    {15, "smimeCapabilities",            NULL},
    {16, "smime",                        NULL},
    {17, "pgpKeyID",                     NULL},
    {20, "friendlyName",                 NULL},
    {21, "localKeyID",                   NULL},
    {22, "certTypes",                    NULL},
    {23, "crlTypes",                     NULL},
    {24, "pkcs-9-oc",                    NULL},
    {25, "pkcs-9-at",                    NULL},
    {26, "pkcs-9-sx",                    NULL},
    {27, "pkcs-9-mr",                    NULL},
    {52, "id-aa-CMSAlgorithmProtection", NULL},
    {0, NULL,                            NULL},
};

/** @brief PKCS#1 and PKCS#9 OIDs */
const oid_item_t pkcs_id_oids[] = {
    {1, "PKCS1", pkcs_1_oids},
    {9, "PKCS9", pkcs_9_oids},
    {0, NULL, NULL}
};


/** @brief PKCS OIDs */
const oid_item_t pkcs_oids[] = {
    {1, "PKCS", pkcs_id_oids},
    {0, NULL, NULL}
};

/** @brief RSA OIDs */
const oid_item_t rsadsi_oids[] = {
    {113549, "RSA", pkcs_oids},
    {0, NULL, NULL}
};


/** @brief Country OIDs */
const oid_item_t country_oids[] = {

    {840, "United States", rsadsi_oids},
    {0, NULL, NULL}
};


/** @brief Member OIDs */
const oid_item_t member_oids[] = {

    {2, "member-body", country_oids},
    {0, NULL, NULL}
};

/** @brief Attribute Type OIDs */
const oid_item_t attrtype_oids[] = {

    {1,  "aliasedEntryName", NULL},
    {2,  "knowledgeInformation", NULL},
    {3,  "commonName", NULL},
    {4,  "surname", NULL},
    {5,  "serialNumber", NULL},
    {6,  "countryName", NULL},
    {7,  "localityName", NULL},
    {8,  "stateOrProvinceName", NULL},
    {9,  "streetAddress", NULL},
    {10, "organizationName", NULL},
    {11, "organizationUnitName", NULL},
    {12, "title", NULL},
    {13, "description", NULL},
    {14, "searchGuide", NULL},
    {15, "businessCategory", NULL},
    {16, "postalAddress", NULL},
    {17, "postalCode", NULL},
    {18, "postOfficeBox", NULL},
    {19, "physicalDeliveryOfficeName", NULL},
    {20, "telephoneNumber", NULL},
    {21, "telexNumber", NULL},
    {22, "teletexTerminalIdentifier", NULL},
    {23, "facsimileTelephoneNumber", NULL},
    {24, "x121Address", NULL},
    {25, "internationalISDNNumber", NULL},
    {26, "registeredAddress", NULL},
    {27, "destinationIndicator", NULL},
    {28, "preferredDeliveryMethod", NULL},
    {29, "presentationAddress", NULL},
    {30, "supportedApplicationContext", NULL},
    {31, "member", NULL},
    {32, "owner", NULL},
    {33, "roleOccupant", NULL},
    {34, "seeAlso", NULL},
    {35, "userPassword", NULL},
    {36, "userCertificate", NULL},
    {37, "cACertificate", NULL},
    {38, "authorityRevocationList", NULL},
    {39, "certificateRevocationList", NULL},
    {40, "crossCertificatePair", NULL},
    {41, "name", NULL},
    {42, "givenName", NULL},
    {43, "initials", NULL},
    {44, "generationQualifier", NULL},
    {45, "uniqueIdentifier", NULL},
    {46, "dnQualifier", NULL},
    {47, "enhancedSearchGuide", NULL},
    {48, "protocolInformation", NULL},
    {49, "distinguishedName", NULL},
    {50, "uniqueMember", NULL},
    {51, "houseIdentifier", NULL},
    {52, "supportedAlgorithms", NULL},
    {53, "deltaRevocationList", NULL},
    {54, "dmdName", NULL},
    {55, "clearance", NULL},
    {56, "defaultDirQop", NULL},
    {57, "attributeIntegrityInfo", NULL},
    {58, "attributeCertificate", NULL},
    {59, "attributeCertificateRevocationList", NULL},
    {60, "confKeyInfo", NULL},
    {61, "aACertificate", NULL},
    {62, "attributeDescriptorCertificate", NULL},
    {63, "attributeAuthorityRevocationList", NULL},
    {64, "family", NULL},
    {65, "pseudonym", NULL},
    {66, "communicationsService", NULL},
    {67, "communicationsNetwork", NULL},
    {68, "certificationPracticeStmt", NULL},
    {69, "certificatePolicy", NULL},
    {70, "pkiPath", NULL},
    {71, "privPolicy", NULL},
    {72, "role", NULL},
    {73, "delegationPath", NULL},
    {74, "protPrivPolicy", NULL},
    {0, NULL, NULL}
};

/** @brief DS OIDs */
const oid_item_t ds_oids[] = {

    {4, "attribType", attrtype_oids},
    {0, NULL, NULL}
};

/** @brief Joint OIDs */
const oid_item_t joint_oids[] = {

    {5, "ds", ds_oids},
    {0, NULL, NULL}
};

/** @brief Base OIDs */
const oid_item_t base_oids[3] = {

    {1, "ISO", member_oids},
    {2, "joint", joint_oids},
    {0, NULL, NULL}
};

