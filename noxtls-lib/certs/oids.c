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

#include "noxtls_common.h"
#include "oids.h"
#include "noxtls_misra_refs.h"

/* Dir 1.1 / Rule 7.4: OID labels as explicit uint8_t text (no string literals). */
static const uint8_t oid_name_10_0[] = { (uint8_t)'1', (uint8_t)'0', 0 };
static const uint8_t oid_name_11_1[] = { (uint8_t)'1', (uint8_t)'1', 0 };
static const uint8_t oid_name_12_2[] = { (uint8_t)'1', (uint8_t)'2', 0 };
static const uint8_t oid_name_ISO_3[] = { (uint8_t)'I', (uint8_t)'S', (uint8_t)'O', 0 };
static const uint8_t oid_name_PKCS_4[] = { (uint8_t)'P', (uint8_t)'K', (uint8_t)'C', (uint8_t)'S', 0 };
static const uint8_t oid_name_PKCS1_5[] = { (uint8_t)'P', (uint8_t)'K', (uint8_t)'C', (uint8_t)'S', (uint8_t)'1', 0 };
static const uint8_t oid_name_PKCS9_6[] = { (uint8_t)'P', (uint8_t)'K', (uint8_t)'C', (uint8_t)'S', (uint8_t)'9', 0 };
static const uint8_t oid_name_RSA_7[] = { (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', 0 };
static const uint8_t oid_name_United_States_8[] = { (uint8_t)'U', (uint8_t)'n', (uint8_t)'i', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)' ', (uint8_t)'S', (uint8_t)'t', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_aACertificate_9[] = { (uint8_t)'a', (uint8_t)'A', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 };
static const uint8_t oid_name_aliasedEntryName_10[] = { (uint8_t)'a', (uint8_t)'l', (uint8_t)'i', (uint8_t)'a', (uint8_t)'s', (uint8_t)'e', (uint8_t)'d', (uint8_t)'E', (uint8_t)'n', (uint8_t)'t', (uint8_t)'r', (uint8_t)'y', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_attribType_11[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'T', (uint8_t)'y', (uint8_t)'p', (uint8_t)'e', 0 };
static const uint8_t oid_name_attributeAuthorityRevocationList_12[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'A', (uint8_t)'u', (uint8_t)'t', (uint8_t)'h', (uint8_t)'o', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'y', (uint8_t)'R', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'L', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_attributeCertificate_13[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 };
static const uint8_t oid_name_attributeCertificateRevocationList_14[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'R', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'L', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_attributeDescriptorCertificate_15[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'D', (uint8_t)'e', (uint8_t)'s', (uint8_t)'c', (uint8_t)'r', (uint8_t)'i', (uint8_t)'p', (uint8_t)'t', (uint8_t)'o', (uint8_t)'r', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 };
static const uint8_t oid_name_attributeIntegrityInfo_16[] = { (uint8_t)'a', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'I', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'g', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'y', (uint8_t)'I', (uint8_t)'n', (uint8_t)'f', (uint8_t)'o', 0 };
static const uint8_t oid_name_authorityRevocationList_17[] = { (uint8_t)'a', (uint8_t)'u', (uint8_t)'t', (uint8_t)'h', (uint8_t)'o', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'y', (uint8_t)'R', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'L', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_businessCategory_18[] = { (uint8_t)'b', (uint8_t)'u', (uint8_t)'s', (uint8_t)'i', (uint8_t)'n', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', (uint8_t)'C', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'g', (uint8_t)'o', (uint8_t)'r', (uint8_t)'y', 0 };
static const uint8_t oid_name_cACertificate_19[] = { (uint8_t)'c', (uint8_t)'A', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 };
static const uint8_t oid_name_certTypes_20[] = { (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'T', (uint8_t)'y', (uint8_t)'p', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_certificatePolicy_21[] = { (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'P', (uint8_t)'o', (uint8_t)'l', (uint8_t)'i', (uint8_t)'c', (uint8_t)'y', 0 };
static const uint8_t oid_name_certificateRevocationList_22[] = { (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'R', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'L', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_certificationPracticeStmt_23[] = { (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'P', (uint8_t)'r', (uint8_t)'a', (uint8_t)'c', (uint8_t)'t', (uint8_t)'i', (uint8_t)'c', (uint8_t)'e', (uint8_t)'S', (uint8_t)'t', (uint8_t)'m', (uint8_t)'t', 0 };
static const uint8_t oid_name_challengePassword_24[] = { (uint8_t)'c', (uint8_t)'h', (uint8_t)'a', (uint8_t)'l', (uint8_t)'l', (uint8_t)'e', (uint8_t)'n', (uint8_t)'g', (uint8_t)'e', (uint8_t)'P', (uint8_t)'a', (uint8_t)'s', (uint8_t)'s', (uint8_t)'w', (uint8_t)'o', (uint8_t)'r', (uint8_t)'d', 0 };
static const uint8_t oid_name_clearance_25[] = { (uint8_t)'c', (uint8_t)'l', (uint8_t)'e', (uint8_t)'a', (uint8_t)'r', (uint8_t)'a', (uint8_t)'n', (uint8_t)'c', (uint8_t)'e', 0 };
static const uint8_t oid_name_commonName_26[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'m', (uint8_t)'m', (uint8_t)'o', (uint8_t)'n', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_communicationsNetwork_27[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'m', (uint8_t)'m', (uint8_t)'u', (uint8_t)'n', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'s', (uint8_t)'N', (uint8_t)'e', (uint8_t)'t', (uint8_t)'w', (uint8_t)'o', (uint8_t)'r', (uint8_t)'k', 0 };
static const uint8_t oid_name_communicationsService_28[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'m', (uint8_t)'m', (uint8_t)'u', (uint8_t)'n', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'s', (uint8_t)'S', (uint8_t)'e', (uint8_t)'r', (uint8_t)'v', (uint8_t)'i', (uint8_t)'c', (uint8_t)'e', 0 };
static const uint8_t oid_name_confKeyInfo_29[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'n', (uint8_t)'f', (uint8_t)'K', (uint8_t)'e', (uint8_t)'y', (uint8_t)'I', (uint8_t)'n', (uint8_t)'f', (uint8_t)'o', 0 };
static const uint8_t oid_name_contentType_30[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'T', (uint8_t)'y', (uint8_t)'p', (uint8_t)'e', 0 };
static const uint8_t oid_name_countersignature_31[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'u', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'r', (uint8_t)'s', (uint8_t)'i', (uint8_t)'g', (uint8_t)'n', (uint8_t)'a', (uint8_t)'t', (uint8_t)'u', (uint8_t)'r', (uint8_t)'e', 0 };
static const uint8_t oid_name_countryName_32[] = { (uint8_t)'c', (uint8_t)'o', (uint8_t)'u', (uint8_t)'n', (uint8_t)'t', (uint8_t)'r', (uint8_t)'y', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_crlTypes_33[] = { (uint8_t)'c', (uint8_t)'r', (uint8_t)'l', (uint8_t)'T', (uint8_t)'y', (uint8_t)'p', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_crossCertificatePair_34[] = { (uint8_t)'c', (uint8_t)'r', (uint8_t)'o', (uint8_t)'s', (uint8_t)'s', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'P', (uint8_t)'a', (uint8_t)'i', (uint8_t)'r', 0 };
static const uint8_t oid_name_defaultDirQop_35[] = { (uint8_t)'d', (uint8_t)'e', (uint8_t)'f', (uint8_t)'a', (uint8_t)'u', (uint8_t)'l', (uint8_t)'t', (uint8_t)'D', (uint8_t)'i', (uint8_t)'r', (uint8_t)'Q', (uint8_t)'o', (uint8_t)'p', 0 };
static const uint8_t oid_name_delegationPath_36[] = { (uint8_t)'d', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'g', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'P', (uint8_t)'a', (uint8_t)'t', (uint8_t)'h', 0 };
static const uint8_t oid_name_deltaRevocationList_37[] = { (uint8_t)'d', (uint8_t)'e', (uint8_t)'l', (uint8_t)'t', (uint8_t)'a', (uint8_t)'R', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'L', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_description_38[] = { (uint8_t)'d', (uint8_t)'e', (uint8_t)'s', (uint8_t)'c', (uint8_t)'r', (uint8_t)'i', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_destinationIndicator_39[] = { (uint8_t)'d', (uint8_t)'e', (uint8_t)'s', (uint8_t)'t', (uint8_t)'i', (uint8_t)'n', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'I', (uint8_t)'n', (uint8_t)'d', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'o', (uint8_t)'r', 0 };
static const uint8_t oid_name_distinguishedName_40[] = { (uint8_t)'d', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', (uint8_t)'i', (uint8_t)'n', (uint8_t)'g', (uint8_t)'u', (uint8_t)'i', (uint8_t)'s', (uint8_t)'h', (uint8_t)'e', (uint8_t)'d', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_dmdName_41[] = { (uint8_t)'d', (uint8_t)'m', (uint8_t)'d', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_dnQualifier_42[] = { (uint8_t)'d', (uint8_t)'n', (uint8_t)'Q', (uint8_t)'u', (uint8_t)'a', (uint8_t)'l', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_ds_43[] = { (uint8_t)'d', (uint8_t)'s', 0 };
static const uint8_t oid_name_emailAddress_44[] = { (uint8_t)'e', (uint8_t)'m', (uint8_t)'a', (uint8_t)'i', (uint8_t)'l', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_enhancedSearchGuide_45[] = { (uint8_t)'e', (uint8_t)'n', (uint8_t)'h', (uint8_t)'a', (uint8_t)'n', (uint8_t)'c', (uint8_t)'e', (uint8_t)'d', (uint8_t)'S', (uint8_t)'e', (uint8_t)'a', (uint8_t)'r', (uint8_t)'c', (uint8_t)'h', (uint8_t)'G', (uint8_t)'u', (uint8_t)'i', (uint8_t)'d', (uint8_t)'e', 0 };
static const uint8_t oid_name_extendedCertificateAttributes_46[] = { (uint8_t)'e', (uint8_t)'x', (uint8_t)'t', (uint8_t)'e', (uint8_t)'n', (uint8_t)'d', (uint8_t)'e', (uint8_t)'d', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'A', (uint8_t)'t', (uint8_t)'t', (uint8_t)'r', (uint8_t)'i', (uint8_t)'b', (uint8_t)'u', (uint8_t)'t', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_extensionRequest_47[] = { (uint8_t)'e', (uint8_t)'x', (uint8_t)'t', (uint8_t)'e', (uint8_t)'n', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'R', (uint8_t)'e', (uint8_t)'q', (uint8_t)'u', (uint8_t)'e', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_facsimileTelephoneNumber_48[] = { (uint8_t)'f', (uint8_t)'a', (uint8_t)'c', (uint8_t)'s', (uint8_t)'i', (uint8_t)'m', (uint8_t)'i', (uint8_t)'l', (uint8_t)'e', (uint8_t)'T', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'p', (uint8_t)'h', (uint8_t)'o', (uint8_t)'n', (uint8_t)'e', (uint8_t)'N', (uint8_t)'u', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_family_49[] = { (uint8_t)'f', (uint8_t)'a', (uint8_t)'m', (uint8_t)'i', (uint8_t)'l', (uint8_t)'y', 0 };
static const uint8_t oid_name_friendlyName_50[] = { (uint8_t)'f', (uint8_t)'r', (uint8_t)'i', (uint8_t)'e', (uint8_t)'n', (uint8_t)'d', (uint8_t)'l', (uint8_t)'y', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_generationQualifier_51[] = { (uint8_t)'g', (uint8_t)'e', (uint8_t)'n', (uint8_t)'e', (uint8_t)'r', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'Q', (uint8_t)'u', (uint8_t)'a', (uint8_t)'l', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_givenName_52[] = { (uint8_t)'g', (uint8_t)'i', (uint8_t)'v', (uint8_t)'e', (uint8_t)'n', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_houseIdentifier_53[] = { (uint8_t)'h', (uint8_t)'o', (uint8_t)'u', (uint8_t)'s', (uint8_t)'e', (uint8_t)'I', (uint8_t)'d', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_id_RSAES_54[] = { (uint8_t)'i', (uint8_t)'d', (uint8_t)'-', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'S', 0 };
static const uint8_t oid_name_id_aa_CMSAlgorithmProtection_55[] = { (uint8_t)'i', (uint8_t)'d', (uint8_t)'-', (uint8_t)'a', (uint8_t)'a', (uint8_t)'-', (uint8_t)'C', (uint8_t)'M', (uint8_t)'S', (uint8_t)'A', (uint8_t)'l', (uint8_t)'g', (uint8_t)'o', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'m', (uint8_t)'P', (uint8_t)'r', (uint8_t)'o', (uint8_t)'t', (uint8_t)'e', (uint8_t)'c', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_id_mgf1_56[] = { (uint8_t)'i', (uint8_t)'d', (uint8_t)'-', (uint8_t)'m', (uint8_t)'g', (uint8_t)'f', (uint8_t)'1', 0 };
static const uint8_t oid_name_id_pSpecified_57[] = { (uint8_t)'i', (uint8_t)'d', (uint8_t)'-', (uint8_t)'p', (uint8_t)'S', (uint8_t)'p', (uint8_t)'e', (uint8_t)'c', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'d', 0 };
static const uint8_t oid_name_initials_58[] = { (uint8_t)'i', (uint8_t)'n', (uint8_t)'i', (uint8_t)'t', (uint8_t)'i', (uint8_t)'a', (uint8_t)'l', (uint8_t)'s', 0 };
static const uint8_t oid_name_internationalISDNNumber_59[] = { (uint8_t)'i', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'r', (uint8_t)'n', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'a', (uint8_t)'l', (uint8_t)'I', (uint8_t)'S', (uint8_t)'D', (uint8_t)'N', (uint8_t)'N', (uint8_t)'u', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_joint_60[] = { (uint8_t)'j', (uint8_t)'o', (uint8_t)'i', (uint8_t)'n', (uint8_t)'t', 0 };
static const uint8_t oid_name_knowledgeInformation_61[] = { (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'l', (uint8_t)'e', (uint8_t)'d', (uint8_t)'g', (uint8_t)'e', (uint8_t)'I', (uint8_t)'n', (uint8_t)'f', (uint8_t)'o', (uint8_t)'r', (uint8_t)'m', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_localKeyID_62[] = { (uint8_t)'l', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'l', (uint8_t)'K', (uint8_t)'e', (uint8_t)'y', (uint8_t)'I', (uint8_t)'D', 0 };
static const uint8_t oid_name_localityName_63[] = { (uint8_t)'l', (uint8_t)'o', (uint8_t)'c', (uint8_t)'a', (uint8_t)'l', (uint8_t)'i', (uint8_t)'t', (uint8_t)'y', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_md2WithRSAEncryption_64[] = { (uint8_t)'m', (uint8_t)'d', (uint8_t)'2', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_md4withRSAEncryption_65[] = { (uint8_t)'m', (uint8_t)'d', (uint8_t)'4', (uint8_t)'w', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_md5WithRSAEncryption_66[] = { (uint8_t)'m', (uint8_t)'d', (uint8_t)'5', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_member_67[] = { (uint8_t)'m', (uint8_t)'e', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_member_body_68[] = { (uint8_t)'m', (uint8_t)'e', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', (uint8_t)'-', (uint8_t)'b', (uint8_t)'o', (uint8_t)'d', (uint8_t)'y', 0 };
static const uint8_t oid_name_messageDigest_69[] = { (uint8_t)'m', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', (uint8_t)'a', (uint8_t)'g', (uint8_t)'e', (uint8_t)'D', (uint8_t)'i', (uint8_t)'g', (uint8_t)'e', (uint8_t)'s', (uint8_t)'t', 0 };
static const uint8_t oid_name_modules_70[] = { (uint8_t)'m', (uint8_t)'o', (uint8_t)'d', (uint8_t)'u', (uint8_t)'l', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_name_71[] = { (uint8_t)'n', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_organizationName_72[] = { (uint8_t)'o', (uint8_t)'r', (uint8_t)'g', (uint8_t)'a', (uint8_t)'n', (uint8_t)'i', (uint8_t)'z', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_organizationUnitName_73[] = { (uint8_t)'o', (uint8_t)'r', (uint8_t)'g', (uint8_t)'a', (uint8_t)'n', (uint8_t)'i', (uint8_t)'z', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'U', (uint8_t)'n', (uint8_t)'i', (uint8_t)'t', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_owner_74[] = { (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_pgpKeyID_75[] = { (uint8_t)'p', (uint8_t)'g', (uint8_t)'p', (uint8_t)'K', (uint8_t)'e', (uint8_t)'y', (uint8_t)'I', (uint8_t)'D', 0 };
static const uint8_t oid_name_physicalDeliveryOfficeName_76[] = { (uint8_t)'p', (uint8_t)'h', (uint8_t)'y', (uint8_t)'s', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'l', (uint8_t)'D', (uint8_t)'e', (uint8_t)'l', (uint8_t)'i', (uint8_t)'v', (uint8_t)'e', (uint8_t)'r', (uint8_t)'y', (uint8_t)'O', (uint8_t)'f', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'e', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_pkcs_9_at_77[] = { (uint8_t)'p', (uint8_t)'k', (uint8_t)'c', (uint8_t)'s', (uint8_t)'-', (uint8_t)'9', (uint8_t)'-', (uint8_t)'a', (uint8_t)'t', 0 };
static const uint8_t oid_name_pkcs_9_mr_78[] = { (uint8_t)'p', (uint8_t)'k', (uint8_t)'c', (uint8_t)'s', (uint8_t)'-', (uint8_t)'9', (uint8_t)'-', (uint8_t)'m', (uint8_t)'r', 0 };
static const uint8_t oid_name_pkcs_9_oc_79[] = { (uint8_t)'p', (uint8_t)'k', (uint8_t)'c', (uint8_t)'s', (uint8_t)'-', (uint8_t)'9', (uint8_t)'-', (uint8_t)'o', (uint8_t)'c', 0 };
static const uint8_t oid_name_pkcs_9_sx_80[] = { (uint8_t)'p', (uint8_t)'k', (uint8_t)'c', (uint8_t)'s', (uint8_t)'-', (uint8_t)'9', (uint8_t)'-', (uint8_t)'s', (uint8_t)'x', 0 };
static const uint8_t oid_name_pkiPath_81[] = { (uint8_t)'p', (uint8_t)'k', (uint8_t)'i', (uint8_t)'P', (uint8_t)'a', (uint8_t)'t', (uint8_t)'h', 0 };
static const uint8_t oid_name_postOfficeBox_82[] = { (uint8_t)'p', (uint8_t)'o', (uint8_t)'s', (uint8_t)'t', (uint8_t)'O', (uint8_t)'f', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'e', (uint8_t)'B', (uint8_t)'o', (uint8_t)'x', 0 };
static const uint8_t oid_name_postalAddress_83[] = { (uint8_t)'p', (uint8_t)'o', (uint8_t)'s', (uint8_t)'t', (uint8_t)'a', (uint8_t)'l', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_postalCode_84[] = { (uint8_t)'p', (uint8_t)'o', (uint8_t)'s', (uint8_t)'t', (uint8_t)'a', (uint8_t)'l', (uint8_t)'C', (uint8_t)'o', (uint8_t)'d', (uint8_t)'e', 0 };
static const uint8_t oid_name_preferredDeliveryMethod_85[] = { (uint8_t)'p', (uint8_t)'r', (uint8_t)'e', (uint8_t)'f', (uint8_t)'e', (uint8_t)'r', (uint8_t)'r', (uint8_t)'e', (uint8_t)'d', (uint8_t)'D', (uint8_t)'e', (uint8_t)'l', (uint8_t)'i', (uint8_t)'v', (uint8_t)'e', (uint8_t)'r', (uint8_t)'y', (uint8_t)'M', (uint8_t)'e', (uint8_t)'t', (uint8_t)'h', (uint8_t)'o', (uint8_t)'d', 0 };
static const uint8_t oid_name_presentationAddress_86[] = { (uint8_t)'p', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_privPolicy_87[] = { (uint8_t)'p', (uint8_t)'r', (uint8_t)'i', (uint8_t)'v', (uint8_t)'P', (uint8_t)'o', (uint8_t)'l', (uint8_t)'i', (uint8_t)'c', (uint8_t)'y', 0 };
static const uint8_t oid_name_protPrivPolicy_88[] = { (uint8_t)'p', (uint8_t)'r', (uint8_t)'o', (uint8_t)'t', (uint8_t)'P', (uint8_t)'r', (uint8_t)'i', (uint8_t)'v', (uint8_t)'P', (uint8_t)'o', (uint8_t)'l', (uint8_t)'i', (uint8_t)'c', (uint8_t)'y', 0 };
static const uint8_t oid_name_protocolInformation_89[] = { (uint8_t)'p', (uint8_t)'r', (uint8_t)'o', (uint8_t)'t', (uint8_t)'o', (uint8_t)'c', (uint8_t)'o', (uint8_t)'l', (uint8_t)'I', (uint8_t)'n', (uint8_t)'f', (uint8_t)'o', (uint8_t)'r', (uint8_t)'m', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_pseudonym_90[] = { (uint8_t)'p', (uint8_t)'s', (uint8_t)'e', (uint8_t)'u', (uint8_t)'d', (uint8_t)'o', (uint8_t)'n', (uint8_t)'y', (uint8_t)'m', 0 };
static const uint8_t oid_name_registeredAddress_91[] = { (uint8_t)'r', (uint8_t)'e', (uint8_t)'g', (uint8_t)'i', (uint8_t)'s', (uint8_t)'t', (uint8_t)'e', (uint8_t)'r', (uint8_t)'e', (uint8_t)'d', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_role_92[] = { (uint8_t)'r', (uint8_t)'o', (uint8_t)'l', (uint8_t)'e', 0 };
static const uint8_t oid_name_roleOccupant_93[] = { (uint8_t)'r', (uint8_t)'o', (uint8_t)'l', (uint8_t)'e', (uint8_t)'O', (uint8_t)'c', (uint8_t)'c', (uint8_t)'u', (uint8_t)'p', (uint8_t)'a', (uint8_t)'n', (uint8_t)'t', 0 };
static const uint8_t oid_name_rsaEncryption_94[] = { (uint8_t)'r', (uint8_t)'s', (uint8_t)'a', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_rsaOAEPEncryptionSET_95[] = { (uint8_t)'r', (uint8_t)'s', (uint8_t)'a', (uint8_t)'O', (uint8_t)'A', (uint8_t)'E', (uint8_t)'P', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'S', (uint8_t)'E', (uint8_t)'T', 0 };
static const uint8_t oid_name_rsassa_pss_96[] = { (uint8_t)'r', (uint8_t)'s', (uint8_t)'a', (uint8_t)'s', (uint8_t)'s', (uint8_t)'a', (uint8_t)'-', (uint8_t)'p', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_searchGuide_97[] = { (uint8_t)'s', (uint8_t)'e', (uint8_t)'a', (uint8_t)'r', (uint8_t)'c', (uint8_t)'h', (uint8_t)'G', (uint8_t)'u', (uint8_t)'i', (uint8_t)'d', (uint8_t)'e', 0 };
static const uint8_t oid_name_seeAlso_98[] = { (uint8_t)'s', (uint8_t)'e', (uint8_t)'e', (uint8_t)'A', (uint8_t)'l', (uint8_t)'s', (uint8_t)'o', 0 };
static const uint8_t oid_name_serialNumber_99[] = { (uint8_t)'s', (uint8_t)'e', (uint8_t)'r', (uint8_t)'i', (uint8_t)'a', (uint8_t)'l', (uint8_t)'N', (uint8_t)'u', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_sha1_with_rsa_signature_100[] = { (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'1', (uint8_t)'-', (uint8_t)'w', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'-', (uint8_t)'r', (uint8_t)'s', (uint8_t)'a', (uint8_t)'-', (uint8_t)'s', (uint8_t)'i', (uint8_t)'g', (uint8_t)'n', (uint8_t)'a', (uint8_t)'t', (uint8_t)'u', (uint8_t)'r', (uint8_t)'e', 0 };
static const uint8_t oid_name_sha224WithRSAEncryption_101[] = { (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'2', (uint8_t)'2', (uint8_t)'4', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_sha256WithRSAEncryption_102[] = { (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'2', (uint8_t)'5', (uint8_t)'6', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_sha384WithRSAEncryption_103[] = { (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'3', (uint8_t)'8', (uint8_t)'4', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_sha512WithRSAEncryption_104[] = { (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'5', (uint8_t)'1', (uint8_t)'2', (uint8_t)'W', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'R', (uint8_t)'S', (uint8_t)'A', (uint8_t)'E', (uint8_t)'n', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_signing_time_105[] = { (uint8_t)'s', (uint8_t)'i', (uint8_t)'g', (uint8_t)'n', (uint8_t)'i', (uint8_t)'n', (uint8_t)'g', (uint8_t)'-', (uint8_t)'t', (uint8_t)'i', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_signingDescription_106[] = { (uint8_t)'s', (uint8_t)'i', (uint8_t)'g', (uint8_t)'n', (uint8_t)'i', (uint8_t)'n', (uint8_t)'g', (uint8_t)'D', (uint8_t)'e', (uint8_t)'s', (uint8_t)'c', (uint8_t)'r', (uint8_t)'i', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 };
static const uint8_t oid_name_smime_107[] = { (uint8_t)'s', (uint8_t)'m', (uint8_t)'i', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_smimeCapabilities_108[] = { (uint8_t)'s', (uint8_t)'m', (uint8_t)'i', (uint8_t)'m', (uint8_t)'e', (uint8_t)'C', (uint8_t)'a', (uint8_t)'p', (uint8_t)'a', (uint8_t)'b', (uint8_t)'i', (uint8_t)'l', (uint8_t)'i', (uint8_t)'t', (uint8_t)'i', (uint8_t)'e', (uint8_t)'s', 0 };
static const uint8_t oid_name_stateOrProvinceName_109[] = { (uint8_t)'s', (uint8_t)'t', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'O', (uint8_t)'r', (uint8_t)'P', (uint8_t)'r', (uint8_t)'o', (uint8_t)'v', (uint8_t)'i', (uint8_t)'n', (uint8_t)'c', (uint8_t)'e', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_streetAddress_110[] = { (uint8_t)'s', (uint8_t)'t', (uint8_t)'r', (uint8_t)'e', (uint8_t)'e', (uint8_t)'t', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_supportedAlgorithms_111[] = { (uint8_t)'s', (uint8_t)'u', (uint8_t)'p', (uint8_t)'p', (uint8_t)'o', (uint8_t)'r', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)'A', (uint8_t)'l', (uint8_t)'g', (uint8_t)'o', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'h', (uint8_t)'m', (uint8_t)'s', 0 };
static const uint8_t oid_name_supportedApplicationContext_112[] = { (uint8_t)'s', (uint8_t)'u', (uint8_t)'p', (uint8_t)'p', (uint8_t)'o', (uint8_t)'r', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)'A', (uint8_t)'p', (uint8_t)'p', (uint8_t)'l', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'C', (uint8_t)'o', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'x', (uint8_t)'t', 0 };
static const uint8_t oid_name_surname_113[] = { (uint8_t)'s', (uint8_t)'u', (uint8_t)'r', (uint8_t)'n', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_telephoneNumber_114[] = { (uint8_t)'t', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'p', (uint8_t)'h', (uint8_t)'o', (uint8_t)'n', (uint8_t)'e', (uint8_t)'N', (uint8_t)'u', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_teletexTerminalIdentifier_115[] = { (uint8_t)'t', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'t', (uint8_t)'e', (uint8_t)'x', (uint8_t)'T', (uint8_t)'e', (uint8_t)'r', (uint8_t)'m', (uint8_t)'i', (uint8_t)'n', (uint8_t)'a', (uint8_t)'l', (uint8_t)'I', (uint8_t)'d', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_telexNumber_116[] = { (uint8_t)'t', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'x', (uint8_t)'N', (uint8_t)'u', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_title_117[] = { (uint8_t)'t', (uint8_t)'i', (uint8_t)'t', (uint8_t)'l', (uint8_t)'e', 0 };
static const uint8_t oid_name_uniqueIdentifier_118[] = { (uint8_t)'u', (uint8_t)'n', (uint8_t)'i', (uint8_t)'q', (uint8_t)'u', (uint8_t)'e', (uint8_t)'I', (uint8_t)'d', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_uniqueMember_119[] = { (uint8_t)'u', (uint8_t)'n', (uint8_t)'i', (uint8_t)'q', (uint8_t)'u', (uint8_t)'e', (uint8_t)'M', (uint8_t)'e', (uint8_t)'m', (uint8_t)'b', (uint8_t)'e', (uint8_t)'r', 0 };
static const uint8_t oid_name_unstructuredAddress_120[] = { (uint8_t)'u', (uint8_t)'n', (uint8_t)'s', (uint8_t)'t', (uint8_t)'r', (uint8_t)'u', (uint8_t)'c', (uint8_t)'t', (uint8_t)'u', (uint8_t)'r', (uint8_t)'e', (uint8_t)'d', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };
static const uint8_t oid_name_unstructuredName_121[] = { (uint8_t)'u', (uint8_t)'n', (uint8_t)'s', (uint8_t)'t', (uint8_t)'r', (uint8_t)'u', (uint8_t)'c', (uint8_t)'t', (uint8_t)'u', (uint8_t)'r', (uint8_t)'e', (uint8_t)'d', (uint8_t)'N', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 };
static const uint8_t oid_name_userCertificate_122[] = { (uint8_t)'u', (uint8_t)'s', (uint8_t)'e', (uint8_t)'r', (uint8_t)'C', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 };
static const uint8_t oid_name_userPassword_123[] = { (uint8_t)'u', (uint8_t)'s', (uint8_t)'e', (uint8_t)'r', (uint8_t)'P', (uint8_t)'a', (uint8_t)'s', (uint8_t)'s', (uint8_t)'w', (uint8_t)'o', (uint8_t)'r', (uint8_t)'d', 0 };
static const uint8_t oid_name_x121Address_124[] = { (uint8_t)'x', (uint8_t)'1', (uint8_t)'2', (uint8_t)'1', (uint8_t)'A', (uint8_t)'d', (uint8_t)'d', (uint8_t)'r', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', 0 };


/** @brief PKCS#1 OIDs */
static const oid_item_t pkcs_1_oids[] = {

    {1, oid_name_rsaEncryption_94,             NULL},
    {2, oid_name_md2WithRSAEncryption_64,      NULL},
    {3, oid_name_md4withRSAEncryption_65,      NULL},
    {4, oid_name_md5WithRSAEncryption_66,      NULL},
    {5, oid_name_sha1_with_rsa_signature_100,   NULL},
    {6, oid_name_rsaOAEPEncryptionSET_95,      NULL},
    {7, oid_name_id_RSAES_54,                  NULL},
    {8, oid_name_id_mgf1_56,                   NULL},
    {9, oid_name_id_pSpecified_57,             NULL},
    {10, oid_name_rsassa_pss_96,               NULL},
    {11, oid_name_sha256WithRSAEncryption_102,  NULL},
    {12, oid_name_sha384WithRSAEncryption_103,  NULL},
    {13, oid_name_sha512WithRSAEncryption_104,  NULL},
    {14, oid_name_sha224WithRSAEncryption_101,  NULL},
    {0, NULL, NULL}
};

/** @brief PKCS#9 OIDs */
static const oid_item_t pkcs_9_oids[] = {

    {0, oid_name_modules_70,                       NULL},
    {1, oid_name_emailAddress_44,                  NULL},
    {2, oid_name_unstructuredName_121,              NULL},
    {3, oid_name_contentType_30,                   NULL},
    {4, oid_name_messageDigest_69,                 NULL},
    {5, oid_name_signing_time_105,                  NULL},
    {6, oid_name_countersignature_31,              NULL},
    {7, oid_name_challengePassword_24,             NULL},
    {8, oid_name_unstructuredAddress_120,           NULL},
    {9, oid_name_extendedCertificateAttributes_46, NULL},
    {10, oid_name_10_0,                           NULL},
    {11, oid_name_11_1,                           NULL},
    {12, oid_name_12_2,                           NULL},
    {13, oid_name_signingDescription_106,           NULL},
    {14, oid_name_extensionRequest_47,             NULL},
    {15, oid_name_smimeCapabilities_108,            NULL},
    {16, oid_name_smime_107,                        NULL},
    {17, oid_name_pgpKeyID_75,                     NULL},
    {20, oid_name_friendlyName_50,                 NULL},
    {21, oid_name_localKeyID_62,                   NULL},
    {22, oid_name_certTypes_20,                    NULL},
    {23, oid_name_crlTypes_33,                     NULL},
    {24, oid_name_pkcs_9_oc_79,                    NULL},
    {25, oid_name_pkcs_9_at_77,                    NULL},
    {26, oid_name_pkcs_9_sx_80,                    NULL},
    {27, oid_name_pkcs_9_mr_78,                    NULL},
    {52, oid_name_id_aa_CMSAlgorithmProtection_55, NULL},
    {0, NULL,                            NULL},
};

/** @brief PKCS#1 and PKCS#9 OIDs */
static const oid_item_t pkcs_id_oids[] = {
    {1, oid_name_PKCS1_5, pkcs_1_oids},
    {9, oid_name_PKCS9_6, pkcs_9_oids},
    {0, NULL, NULL}
};

/** @brief PKCS OIDs */
static const oid_item_t pkcs_oids[] = {
    {1, oid_name_PKCS_4, pkcs_id_oids},
    {0, NULL, NULL}
};

/** @brief RSA OIDs */
static const oid_item_t rsadsi_oids[] = {
    {113549, oid_name_RSA_7, pkcs_oids},
    {0, NULL, NULL}
};

/** @brief Country OIDs */
static const oid_item_t country_oids[] = {

    {840, oid_name_United_States_8, rsadsi_oids},
    {0, NULL, NULL}
};

/** @brief Member OIDs */
static const oid_item_t member_oids[] = {

    {2, oid_name_member_body_68, country_oids},
    {0, NULL, NULL}
};

/** @brief Attribute Type OIDs */
static const oid_item_t attrtype_oids[] = {

    {1,  oid_name_aliasedEntryName_10, NULL},
    {2,  oid_name_knowledgeInformation_61, NULL},
    {3,  oid_name_commonName_26, NULL},
    {4,  oid_name_surname_113, NULL},
    {5,  oid_name_serialNumber_99, NULL},
    {6,  oid_name_countryName_32, NULL},
    {7,  oid_name_localityName_63, NULL},
    {8,  oid_name_stateOrProvinceName_109, NULL},
    {9,  oid_name_streetAddress_110, NULL},
    {10, oid_name_organizationName_72, NULL},
    {11, oid_name_organizationUnitName_73, NULL},
    {12, oid_name_title_117, NULL},
    {13, oid_name_description_38, NULL},
    {14, oid_name_searchGuide_97, NULL},
    {15, oid_name_businessCategory_18, NULL},
    {16, oid_name_postalAddress_83, NULL},
    {17, oid_name_postalCode_84, NULL},
    {18, oid_name_postOfficeBox_82, NULL},
    {19, oid_name_physicalDeliveryOfficeName_76, NULL},
    {20, oid_name_telephoneNumber_114, NULL},
    {21, oid_name_telexNumber_116, NULL},
    {22, oid_name_teletexTerminalIdentifier_115, NULL},
    {23, oid_name_facsimileTelephoneNumber_48, NULL},
    {24, oid_name_x121Address_124, NULL},
    {25, oid_name_internationalISDNNumber_59, NULL},
    {26, oid_name_registeredAddress_91, NULL},
    {27, oid_name_destinationIndicator_39, NULL},
    {28, oid_name_preferredDeliveryMethod_85, NULL},
    {29, oid_name_presentationAddress_86, NULL},
    {30, oid_name_supportedApplicationContext_112, NULL},
    {31, oid_name_member_67, NULL},
    {32, oid_name_owner_74, NULL},
    {33, oid_name_roleOccupant_93, NULL},
    {34, oid_name_seeAlso_98, NULL},
    {35, oid_name_userPassword_123, NULL},
    {36, oid_name_userCertificate_122, NULL},
    {37, oid_name_cACertificate_19, NULL},
    {38, oid_name_authorityRevocationList_17, NULL},
    {39, oid_name_certificateRevocationList_22, NULL},
    {40, oid_name_crossCertificatePair_34, NULL},
    {41, oid_name_name_71, NULL},
    {42, oid_name_givenName_52, NULL},
    {43, oid_name_initials_58, NULL},
    {44, oid_name_generationQualifier_51, NULL},
    {45, oid_name_uniqueIdentifier_118, NULL},
    {46, oid_name_dnQualifier_42, NULL},
    {47, oid_name_enhancedSearchGuide_45, NULL},
    {48, oid_name_protocolInformation_89, NULL},
    {49, oid_name_distinguishedName_40, NULL},
    {50, oid_name_uniqueMember_119, NULL},
    {51, oid_name_houseIdentifier_53, NULL},
    {52, oid_name_supportedAlgorithms_111, NULL},
    {53, oid_name_deltaRevocationList_37, NULL},
    {54, oid_name_dmdName_41, NULL},
    {55, oid_name_clearance_25, NULL},
    {56, oid_name_defaultDirQop_35, NULL},
    {57, oid_name_attributeIntegrityInfo_16, NULL},
    {58, oid_name_attributeCertificate_13, NULL},
    {59, oid_name_attributeCertificateRevocationList_14, NULL},
    {60, oid_name_confKeyInfo_29, NULL},
    {61, oid_name_aACertificate_9, NULL},
    {62, oid_name_attributeDescriptorCertificate_15, NULL},
    {63, oid_name_attributeAuthorityRevocationList_12, NULL},
    {64, oid_name_family_49, NULL},
    {65, oid_name_pseudonym_90, NULL},
    {66, oid_name_communicationsService_28, NULL},
    {67, oid_name_communicationsNetwork_27, NULL},
    {68, oid_name_certificationPracticeStmt_23, NULL},
    {69, oid_name_certificatePolicy_21, NULL},
    {70, oid_name_pkiPath_81, NULL},
    {71, oid_name_privPolicy_87, NULL},
    {72, oid_name_role_92, NULL},
    {73, oid_name_delegationPath_36, NULL},
    {74, oid_name_protPrivPolicy_88, NULL},
    {0, NULL, NULL}
};

/** @brief DS OIDs */
static const oid_item_t ds_oids[] = {

    {4, oid_name_attribType_11, attrtype_oids},
    {0, NULL, NULL}
};

/** @brief Joint OIDs */
static const oid_item_t joint_oids[] = {

    {5, oid_name_ds_43, ds_oids},
    {0, NULL, NULL}
};

/** @brief Base OIDs */
const oid_item_t base_oids[3] = {

    {1, oid_name_ISO_3, member_oids},
    {2, oid_name_joint_60, joint_oids},
    {0, NULL, NULL}
};


/* Same-TU reference so Rule 8.9 does not force block-scope for public OID table. */
__attribute__((used)) static void noxtls_oids_misra_keep(void)
{
    NOXTLS_MISRA_REF_OBJ(base_oids);
}
