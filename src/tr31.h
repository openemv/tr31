/**
 * @file tr31.h
 * @brief High level TR-31 library interface
 *
 * Copyright 2020-2023, 2025 Leon Lynch
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef LIBTR31_H
#define LIBTR31_H

#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

/// Key block format versions
enum tr31_version_t {
	TR31_VERSION_A = 'A', ///< Key block format version A as defined in ANSI X9.143:2021 and TR-31:2005; uses TDES Key Variant Binding Method
	TR31_VERSION_B = 'B', ///< Key block format version B as defined in ANSI X9.143:2021 and TR-31:2010; uses TDES Key Derivation Binding Method
	TR31_VERSION_C = 'C', ///< Key block format version C as defined in ANSI X9.143:2021 and TR-31:2010; uses TDES Key Variant Binding Method
	TR31_VERSION_D = 'D', ///< Key block format version D as defined in ANSI X9.143:2021 and ISO 20038:2017; uses AES Key Derivation Binding Method
	TR31_VERSION_E = 'E', ///< Key block format version E as defined in ISO 20038:2017; uses AES Key Derivation Binding Method
};

/**
 * @name Key usage values
 * @remark See ANSI X9.143:2021, 6.3.1, table 2
 * @anchor key-usage-values
 */
/// @{
#define TR31_KEY_USAGE_BDK              (0x4230) ///< Key Usage B0: Base Derivation Key (BDK)
#define TR31_KEY_USAGE_DUKPT_IK         (0x4231) ///< Key Usage B1: Initial DUKPT Key (IK/IPEK)
#define TR31_KEY_USAGE_BKV              (0x4232) ///< Key Usage B2: Base Key Variant Key (deprecated)
#define TR31_KEY_USAGE_KDK              (0x4233) ///< Key Usage B3: Key Derivation Key (Non ANSI X9.24)
#define TR31_KEY_USAGE_CVK              (0x4330) ///< Key Usage C0: Card Verification Key (CVK)
#define TR31_KEY_USAGE_DATA             (0x4430) ///< Key Usage D0: Symmetric Key for Data Encryption
#define TR31_KEY_USAGE_ASYMMETRIC_DATA  (0x4431) ///< Key Usage D1: Asymmetric Key for Data Encryption
#define TR31_KEY_USAGE_DATA_DEC_TABLE   (0x4432) ///< Key Usage D2: Data Encryption Key for Decimalization Table
#define TR31_KEY_USAGE_DATA_SENSITIVE   (0x4433) ///< Key Usage D3: Data Encryption Key for Sensitive Data
#define TR31_KEY_USAGE_EMV_MKAC         (0x4530) ///< Key Usage E0: EMV/Chip Issuer Master Key: Application Cryptograms (MKAC)
#define TR31_KEY_USAGE_EMV_MKSMC        (0x4531) ///< Key Usage E1: EMV/Chip Issuer Master Key: Secure Messaging for Confidentiality (MKSMC)
#define TR31_KEY_USAGE_EMV_MKSMI        (0x4532) ///< Key Usage E2: EMV/Chip Issuer Master Key: Secure Messaging for Integrity (MKSMI)
#define TR31_KEY_USAGE_EMV_MKDAC        (0x4533) ///< Key Usage E3: EMV/Chip Issuer Master Key: Data Authentication Code (MKDAC)
#define TR31_KEY_USAGE_EMV_MKDN         (0x4534) ///< Key Usage E4: EMV/Chip Issuer Master Key: Dynamic Numbers (MKDN)
#define TR31_KEY_USAGE_EMV_CP           (0x4535) ///< Key Usage E5: EMV/Chip Issuer Master Key: Card Personalization (CP)
#define TR31_KEY_USAGE_EMV_OTHER        (0x4536) ///< Key Usage E6: EMV/Chip Issuer Master Key: Other
#define TR31_KEY_USAGE_EMV_AKP_PIN      (0x4537) ///< Key Usage E7: EMV/Chip Asymmetric Key Pair for PIN Encryption
#define TR31_KEY_USAGE_IV               (0x4930) ///< Key Usage I0: Initialization Vector (IV)
#define TR31_KEY_USAGE_KEK              (0x4B30) ///< Key Usage K0: Key Encryption or Wrapping Key (KEK)
#define TR31_KEY_USAGE_TR31_KBPK        (0x4B31) ///< Key Usage K1: ANSI X9.143 / TR-31 Key Block Protection Key (KBPK)
#define TR31_KEY_USAGE_TR34_APK_KRD     (0x4B32) ///< Key Usage K2: ANSI X9.139 / TR-34 Asymmetric Key Pair for Key Receiving Device
#define TR31_KEY_USAGE_APK              (0x4B33) ///< Key Usage K3: Asymmetric Key Pair for Key Wrapping or Key Agreement
#define TR31_KEY_USAGE_ISO20038_KBPK    (0x4B34) ///< Key Usage K4: ISO 20038 Key Block Protection Key (KBPK)
#define TR31_KEY_USAGE_ISO16609_MAC_1   (0x4D30) ///< Key Usage M0: ISO 16609 MAC algorithm 1 (using TDES)
#define TR31_KEY_USAGE_ISO9797_1_MAC_1  (0x4D31) ///< Key Usage M1: ISO 9797-1 MAC Algorithm 1 (CBC-MAC)
#define TR31_KEY_USAGE_ISO9797_1_MAC_2  (0x4D32) ///< Key Usage M2: ISO 9797-1 MAC Algorithm 2
#define TR31_KEY_USAGE_ISO9797_1_MAC_3  (0x4D33) ///< Key Usage M3: ISO 9797-1 MAC Algorithm 3 (Retail MAC)
#define TR31_KEY_USAGE_ISO9797_1_MAC_4  (0x4D34) ///< Key Usage M4: ISO 9797-1 MAC Algorithm 4
#define TR31_KEY_USAGE_ISO9797_1_MAC_5  (0x4D35) ///< Key Usage M5: ISO 9797-1:1999 MAC Algorithm 5 (legacy)
#define TR31_KEY_USAGE_ISO9797_1_CMAC   (0x4D36) ///< Key Usage M6: ISO 9797-1:2011 MAC Algorithm 5 (CMAC)
#define TR31_KEY_USAGE_HMAC             (0x4D37) ///< Key Usage M7: HMAC Key
#define TR31_KEY_USAGE_ISO9797_1_MAC_6  (0x4D38) ///< Key Usage M8: ISO 9797-1 MAC Algorithm 6
#define TR31_KEY_USAGE_PEK              (0x5030) ///< Key Usage P0: PIN Encryption Key
#define TR31_KEY_USAGE_PGK              (0x5031) ///< Key Usage P1: PIN Generation Key
#define TR31_KEY_USAGE_AKP_SIG          (0x5330) ///< Key Usage S0: Asymmetric Key Pair for Digital Signature
#define TR31_KEY_USAGE_AKP_CA           (0x5331) ///< Key Usage S1: Asymmetric Key Pair for CA use
#define TR31_KEY_USAGE_AKP_OTHER        (0x5332) ///< Key Usage S2: Asymmetric Key Pair for non-X9.24 use
#define TR31_KEY_USAGE_PVK              (0x5630) ///< Key Usage V0: PIN Verification Key (Other)
#define TR31_KEY_USAGE_PVK_IBM3624      (0x5631) ///< Key Usage V1: PIN Verification Key (IBM 3624)
#define TR31_KEY_USAGE_PVK_VISA_PVV     (0x5632) ///< Key Usage V2: PIN Verification Key (VISA PVV)
#define TR31_KEY_USAGE_PVK_X9_132_ALG_1 (0x5633) ///< Key Usage V3: PIN Verification Key (ANSI X9.132 algorithm 1)
#define TR31_KEY_USAGE_PVK_X9_132_ALG_2 (0x5634) ///< Key Usage V4: PIN Verification Key (ANSI X9.132 algorithm 2)
#define TR31_KEY_USAGE_PVK_X9_132_ALG_3 (0x5635) ///< Key Usage V5: PIN Verification Key (ANSI X9.132 algorithm 3)
/// @}

/**
 * @name Key algorithm values
 * @remark See ANSI X9.143:2021, 6.3.2, table 3
 * @remark See ISO 20038:2017, Annex A.2.4, table A.4
 * @anchor key-algorithm-values
 */
/// @{
#define TR31_KEY_ALGORITHM_AES          ('A') ///< Key Algorithm A: AES
#define TR31_KEY_ALGORITHM_DES          ('D') ///< Key Algorithm D: DES
#define TR31_KEY_ALGORITHM_EC           ('E') ///< Key Algorithm E: Elliptic Curve
#define TR31_KEY_ALGORITHM_HMAC         ('H') ///< Key Algorithm H for ANSI X9.143: HMAC
#define TR31_KEY_ALGORITHM_HMAC_SHA1    ('H') ///< Key Algorithm H for ISO 20038: HMAC-SHA1
#define TR31_KEY_ALGORITHM_HMAC_SHA2    ('I') ///< Key Algorithm I for ISO 20038: HMAC-SHA2
#define TR31_KEY_ALGORITHM_HMAC_SHA3    ('J') ///< Key Algorithm J for ISO 20038: HMAC-SHA3
#define TR31_KEY_ALGORITHM_RSA          ('R') ///< Key Algorithm R: RSA
#define TR31_KEY_ALGORITHM_DSA          ('S') ///< Key Algorithm S: DSA
#define TR31_KEY_ALGORITHM_TDES         ('T') ///< Key Algorithm T: Triple DES
/// @}

/**
 * @name Key mode of use values
 * @remark See ANSI X9.143:2021, 6.3.3, table 4
 * @anchor key-mode-of-use-values
 */
/// @{
#define TR31_KEY_MODE_OF_USE_ENC_DEC    ('B') ///< Key Mode of Use B: Encrypt/Wrap and Decrypt/Unwrap
#define TR31_KEY_MODE_OF_USE_MAC        ('C') ///< Key Mode of Use C: MAC Generate and Verify
#define TR31_KEY_MODE_OF_USE_DEC        ('D') ///< Key Mode of Use D: Decrypt/Unwrap Only
#define TR31_KEY_MODE_OF_USE_ENC        ('E') ///< Key Mode of Use E: Encrypt/Wrap Only
#define TR31_KEY_MODE_OF_USE_MAC_GEN    ('G') ///< Key Mode of Use G: MAC Generate Only
#define TR31_KEY_MODE_OF_USE_ANY        ('N') ///< Key Mode of Use N: No special restrictions or not applicable (other than restrictions implied by the Key Usage)
#define TR31_KEY_MODE_OF_USE_SIG        ('S') ///< Key Mode of Use S: Signature Only
#define TR31_KEY_MODE_OF_USE_MAC_VERIFY ('V') ///< Key Mode of Use V: MAC Verify Only
#define TR31_KEY_MODE_OF_USE_DERIVE     ('X') ///< Key Mode of Use X: Key Derivation
#define TR31_KEY_MODE_OF_USE_VARIANT    ('Y') ///< Key Mode of Use Y: Create Key Variants
/// @}

/**
 * Key version field interpretation
 * @remark See ANSI X9.143:2021, 6.3.4, table 5
 */
enum tr31_key_version_t {
	TR31_KEY_VERSION_IS_UNUSED = 0, ///< Key version field unused
	TR31_KEY_VERSION_IS_COMPONENT, ///< key version field is component number
	TR31_KEY_VERSION_IS_VALID, ///< Key version field is valid
};

/**
 * @name Key exportability values
 * @remark See ANSI X9.143:2021, 6.3.5, table 6
 * @anchor key-exportability-values
 */
/// @{
#define TR31_KEY_EXPORT_TRUSTED         ('E') ///< Exportability E: Exportable in a trusted key block in accordance with ANSI X9.24
#define TR31_KEY_EXPORT_NONE            ('N') ///< Exportability N: Not exportable
#define TR31_KEY_EXPORT_SENSITIVE       ('S') ///< Exportability S: Sensitive; exportable in forms not in accordance with ANSI X9.24; eg ANSI X9.17
/// @}

/**
 * @name Key context values
 * @remark See ANSI X9.143:2021, 6.2, table 1
 * @anchor key-context-values
 */
/// @{
#define TR31_KEY_CONTEXT_NONE           ('0') ///< Key context: Determined by wrapping key
#define TR31_KEY_CONTEXT_STORAGE        ('1') ///< Key context: Storage context only
#define TR31_KEY_CONTEXT_EXCHANGE       ('2') ///< Key context: Key exchange context only
/// @}

/**
 * @name Optional block IDs
 * @remark See ANSI X9.143:2021, 6.3.6, table 7
 * @anchor optional-block-id-values
 */
/// @{
#define TR31_OPT_BLOCK_AL               (0x414C) ///< Optional Block AL: Asymmetric Key Life (AKL) attribute
#define TR31_OPT_BLOCK_BI               (0x4249) ///< Optional Block BI: Base Derivation Key Identifier (BDK) for DUKPT (see ANSI X9.24-3:2017, 4.7)
#define TR31_OPT_BLOCK_CT               (0x4354) ///< Optional Block CT: Public Key Certificate
#define TR31_OPT_BLOCK_DA               (0x4441) ///< Optional Block DA: Derivation(s) Allowed for Derivation Keys
#define TR31_OPT_BLOCK_FL               (0x464C) ///< Optional Block FL: Flags
#define TR31_OPT_BLOCK_HM               (0x484D) ///< Optional Block HM: Hash algorithm for HMAC
#define TR31_OPT_BLOCK_IK               (0x494B) ///< Optional Block IK: Initial Key Identifier (IKID) for Initial AES DUKPT Key (see ANSI X9.24-3:2017, 4.17)
#define TR31_OPT_BLOCK_KC               (0x4B43) ///< Optional Block KC: Key Check Value (KCV) of wrapped key (see ANSI X9.24-1:2017, Annex A)
#define TR31_OPT_BLOCK_KP               (0x4B50) ///< Optional Block KP: Key Check Value (KCV) of KBPK (see ANSI X9.24-1:2017, Annex A)
#define TR31_OPT_BLOCK_KS               (0x4B53) ///< Optional Block KS: Initial Key Serial Number (KSN) as used in TDEA DUKPT (see ANSI X9.24-3:2017, C.2.3)
#define TR31_OPT_BLOCK_KV               (0x4B56) ///< Optional Block KV: Key Block Values (deprecated)
#define TR31_OPT_BLOCK_LB               (0x4C42) ///< Optional Block LB: Variable-length user defined label
#define TR31_OPT_BLOCK_PB               (0x5042) ///< Optional Block PB: Padding Block
#define TR31_OPT_BLOCK_PK               (0x504B) ///< Optional Block PK: Protection Key Check Value (KCV) of export KBPK
#define TR31_OPT_BLOCK_TC               (0x5443) ///< Optional Block TC: Time of Creation (in ISO 8601 UTC format)
#define TR31_OPT_BLOCK_TS               (0x5453) ///< Optional Block TS: Time Stamp (in ISO 8601 UTC format)
#define TR31_OPT_BLOCK_WP               (0x5750) ///< Optional Block WP: Wrapping Pedigree
/// @}

/**
 * @name Asymmetric Key Life (AKL) optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.1, table 8
 * @anchor optional-block-al-values
 */
/// @{
#define TR31_OPT_BLOCK_AL_VERSION_1     (0x01) ///< Asymmetric Key Life version: 1
#define TR31_OPT_BLOCK_AL_AKL_EPHEMERAL (0x00) ///< Asymmetric Key Life: Ephemeral
#define TR31_OPT_BLOCK_AL_AKL_STATIC    (0x01) ///< Asymmetric Key Life: Static/Permanent
/// @}

/**
 * @name Base Derivation Key Identifier (BDK ID) for DUKPT optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.2, table 9
 * @anchor optional-block-bi-values
 */
/// @{
#define TR31_OPT_BLOCK_BI_TDES_DUKPT    (0x00) ///< TDES DUKPT Key Set ID (KSI)
#define TR31_OPT_BLOCK_BI_AES_DUKPT     (0x01) ///< AES DUKPT Base Derivation Key ID (BDK ID)
/// @}

/**
 * @name Certificate Format for Public Key Certificate optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.3, table 10/11
 * @anchor optional-block-ct-values
 */
/// @{
#define TR31_OPT_BLOCK_CT_X509          (0x00) ///< Certificate Format: X.509
#define TR31_OPT_BLOCK_CT_EMV           (0x01) ///< Certificate Format: EMV
#define TR31_OPT_BLOCK_CT_CERT_CHAIN    (0x02) ///< Certificate Format: Certificate Chain
/// @}

/**
 * @name Derivation(s) Allowed optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.4, table 12
 * @anchor optional-block-da-values
 */
/// @{
#define TR31_OPT_BLOCK_DA_VERSION_1     (0x01) ///< Derivation(s) Allowed version: 1
/// @}

/**
 * @name HMAC optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.5, table 13
 * @anchor optional-block-hm-values
 */
/// @{
#define TR31_OPT_BLOCK_HM_SHA1          (0x10) ///< HMAC Hash Algorithm 10: SHA-1
#define TR31_OPT_BLOCK_HM_SHA224        (0x20) ///< HMAC Hash Algorithm 20: SHA-224
#define TR31_OPT_BLOCK_HM_SHA256        (0x21) ///< HMAC Hash Algorithm 21: SHA-256
#define TR31_OPT_BLOCK_HM_SHA384        (0x22) ///< HMAC Hash Algorithm 22: SHA-384
#define TR31_OPT_BLOCK_HM_SHA512        (0x23) ///< HMAC Hash Algorithm 23: SHA-512
#define TR31_OPT_BLOCK_HM_SHA512_224    (0x24) ///< HMAC Hash Algorithm 24: SHA-512/224
#define TR31_OPT_BLOCK_HM_SHA512_256    (0x25) ///< HMAC Hash Algorithm 25: SHA-512/256
#define TR31_OPT_BLOCK_HM_SHA3_224      (0x30) ///< HMAC Hash Algorithm 30: SHA3-224
#define TR31_OPT_BLOCK_HM_SHA3_256      (0x31) ///< HMAC Hash Algorithm 31: SHA3-256
#define TR31_OPT_BLOCK_HM_SHA3_384      (0x32) ///< HMAC Hash Algorithm 32: SHA3-384
#define TR31_OPT_BLOCK_HM_SHA3_512      (0x33) ///< HMAC Hash Algorithm 33: SHA3-512
#define TR31_OPT_BLOCK_HM_SHAKE128      (0x40) ///< HMAC Hash Algorithm 40: SHAKE128
#define TR31_OPT_BLOCK_HM_SHAKE256      (0x41) ///< HMAC Hash Algorithm 41: SHAKE256
/// @}

/**
 * @name Key Check Value (KCV) optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.7, table 15
 * @anchor optional-block-kcv-values
 */
/// @{
#define TR31_OPT_BLOCK_KCV_LEGACY       (0x00) ///< KCV algorithm: Legacy KCV algorithm
#define TR31_OPT_BLOCK_KCV_CMAC         (0x01) ///< KCV algorithm: CMAC based KCV
/// @}

/**
 * @name Wrapping Pedigree (WP) optional block values
 * @remark See ANSI X9.143:2021, 6.3.6.15, table 23
 * @anchor optional-block-wp-values
 */
/// @{
#define TR31_OPT_BLOCK_WP_VERSION_0     (0x00) ///< Wrapping Pedigree (WP) version: 0
#define TR31_OPT_BLOCK_WP_EQ_GT         (0)    ///< Wrapping Pedigree: Equal or greater effective strength
#define TR31_OPT_BLOCK_WP_LT            (1)    ///< Wrapping Pedigree: Lesser effective strength
#define TR31_OPT_BLOCK_WP_ASYMMETRIC    (2)    ///< Asymmetric key at risk of quantum computing
#define TR31_OPT_BLOCK_WP_ASYMMETRIC_LT (3)    ///< Asymmetric key at risk of quantum computing and symmetric key of lesser effective strength
/// @}

/**
 * @name Key block import flags
 * @anchor import-flags
 */
/// @{
#define TR31_IMPORT_NO_STRICT_VALIDATION        (0x01) ///< Disable strict ANSI X9.143 / ISO 20038 validation during import. This is useful for importing non-standard key blocks.
/// @}

/**
 * @name Key block export flags
 * @anchor export-flags
 */
/// @{
#define TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION   (0x01) ///< Disable ANSI X9.143 key length obfuscation during key block export
#define TR31_EXPORT_ZERO_OPT_BLOCK_PB           (0x02) ///< Fill optional block PB using zeros instead of random characters during key block export.
/// @}

/**
 * @name Key block attribute and optional block values defined by IBM
 */
/// @{
#define TR31_KEY_USAGE_IBM                      (0x3130) ///< Key Usage 10: IBM proprietary key usage
#define TR31_KEY_MODE_OF_USE_IBM                ('1')    ///< Key Mode of Use 1: IBM proprietary mode for keys
#define TR31_OPT_BLOCK_10_IBM                   (0x3130) ///< Optional Block 10: IBM proprietary optional block
#define TR31_OPT_BLOCK_10_IBM_MAGIC             "IBMC"   ///< IBM proprietary optional block magic value
#define TR31_OPT_BLOCK_10_IBM_TLV_CCA_CV        (0x01)   ///< IBM proprietary optional block: Common Cryptographic Architecture (CCA) Control Vector (CV)
#define TR31_OPT_BLOCK_10_IBM_TLV_X9_SWKB       (0x02)   ///< IBM proprietary optional block: Internal X9-SWKB controls
/// @}

/// Key object
struct tr31_key_t {
	unsigned int usage; ///< Key usage. See @ref key-usage-values "key usage values".
	unsigned int algorithm; ///< Key algorithm. See @ref key-algorithm-values "key algorithm values".
	unsigned int mode_of_use; ///< Key mode of use. See @ref key-mode-of-use-values "key mode of use values".

	// key version field information
	enum tr31_key_version_t key_version; ///< Key version field interpretation
	char key_version_str[3]; ///< Key version string. Null terminated. Invalid if unused.

	unsigned int exportability; ///< Key exportability. See @ref key-exportability-values "key exportability values".
	unsigned int key_context; ///< Key context. See @ref key-context-values "key exportability values".

	size_t length; ///< Key data length in bytes
	void* data; ///< Key data

	uint8_t kcv_algorithm; ///< KCV algorithm (@ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC)
	size_t kcv_len; ///< Key Check Value (KCV) length in bytes
	uint8_t kcv[5]; ///< Key Check Value (KCV)
};

/// Optional block context object
struct tr31_opt_ctx_t {
	unsigned int id; ///< Optional block identifier. See @ref optional-block-id-values "optional block IDs".
	size_t data_length; ///< Optional block data length in bytes
	void* data; ///< Optional block data
};

/**
 * Decoded optional block Asymmetric Key Life (AKL) data
 * @see @ref optional-block-al-values "Asymmetric Key Life (AKL) optional block values"
 */
struct tr31_opt_blk_akl_data_t {
	uint8_t version; ///< Asymmetric Key Life (AKL) version
	/// Asymmetric Key Life (AKL) version 1
	struct v1_t {
		uint8_t akl; ///< Asymmetric Key Life (AKL)
	} v1; ///< Asymmetric Key Life (AKL) version 1. Valid if @ref tr31_opt_blk_akl_data_t.version is @ref TR31_OPT_BLOCK_AL_VERSION_1
};

/**
 * Decoded optional block Base Derivation Key Identifier (BDK ID) data
 * @see @ref optional-block-bi-values "Base Derivation Key Identifier (BDK ID) for DUKPT optional block values"
 */
struct tr31_opt_blk_bdkid_data_t {
	uint8_t key_type; ///< DUKPT key type. Either @ref TR31_OPT_BLOCK_BI_TDES_DUKPT or @ref TR31_OPT_BLOCK_BI_AES_DUKPT.
	size_t bdkid_len; ///< Length of @ref tr31_opt_blk_bdkid_data_t.bdkid in bytes. Must be 5 bytes for TDES DUKPT or 4 bytes for AES DUKPT (according to ANSI X9.143:2021, 6.3.6.2, table 9)
	uint8_t bdkid[5]; ///< Key Set ID (KSI) or Base Derivation Key ID (BDK ID)
};

/// Decoded Derivation Allowed (DA) attributes
struct tr31_opt_blk_da_attr_t {
	unsigned int key_usage; ///< Derivation Allowed: key usage
	unsigned int algorithm; ///< Derivation Allowed: key algorithm
	unsigned int mode_of_use; ///< Derivation Allowed: mode of use
	unsigned int exportability; ///< Derivation Allowed: exportability
};

/**
 * Decoded Derivation(s) Allowed (DA) data
 * @see @ref optional-block-da-values "Derivation(s) Allowed optional block values"
 */
struct tr31_opt_blk_da_data_t {
	unsigned int version; ///< Derivation(s) Allowed (DA) version
	struct tr31_opt_blk_da_attr_t attr[]; ///< Derivation Allowed (DA) array
};

/**
 * Decoded optional block Key Check Value (KCV) data
 * @see @ref optional-block-kcv-values "Key Check Value (KCV) optional block values"
 */
struct tr31_opt_blk_kcv_data_t {
	uint8_t kcv_algorithm; ///< KCV algorithm output. Either @ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC.
	size_t kcv_len; ///< Length of @ref tr31_opt_blk_kcv_data_t.kcv in bytes. Must be at most 3 bytes for legacy KCV or at most 5 bytes for CMAC KCV (according to ANSI X9.24-1)
	uint8_t kcv[5]; ///< Key Check Value (KCV)
};

/**
 * Decoded optional block Wrapping Pedigree (WP) data
 * @see @ref optional-block-wp-values "Wrapping Pedigree (WP) optional block values"
 */
struct tr31_opt_blk_wp_data_t {
	uint8_t version; ///< Wrapping Pedigree (WP) format version
	/// Wrapping Pedigree (WP) version 0
	struct v0_t {
		uint8_t wrapping_pedigree; ///< Wrapping Pedigree value
	} v0; ///< Wrapping Pedigree (WP) version 0. Valid if @ref tr31_opt_blk_wp_data_t.version is @ref TR31_OPT_BLOCK_WP_VERSION_0
};

/**
 * @brief Key block context object.
 *
 * This object is typically populated by @ref tr31_import().
 *
 * To manually populate this object for @ref tr31_export(), do:
 * - Use @ref tr31_init() to initialise the object and set the #version field (and optionally the #key field)
 * - Use @ref tr31_key_init() or @ref tr31_key_copy() to set #key field (if not set in the previous step)
 * - Use @ref tr31_opt_block_add() and similar specialised functions to add optional blocks (if required)
 *
 * @note Use @ref tr31_release() to release internal resources when done.
 */
struct tr31_ctx_t {
	enum tr31_version_t version; ///< Key block format version
	size_t length; ///< Key block length in bytes (only populated by @ref tr31_import(), not @ref tr31_export())

	struct tr31_key_t key; ///< Key object

	size_t opt_blocks_count; ///< Number of optional blocks
	struct tr31_opt_ctx_t* opt_blocks; ///< Optional block context objects
};

/// TR-31 library errors
enum tr31_error_t {
	TR31_ERROR_INVALID_LENGTH = 1, ///< Invalid key block length
	TR31_ERROR_INVALID_CHARACTER, ///< Invalid (non-printable) character
	TR31_ERROR_UNSUPPORTED_VERSION, ///< Unsupported key block format version
	TR31_ERROR_INVALID_LENGTH_FIELD, ///< Invalid key block length field
	TR31_ERROR_UNSUPPORTED_KEY_USAGE, ///< Unsupported key usage
	TR31_ERROR_UNSUPPORTED_ALGORITHM, ///< Unsupported key algorithm
	TR31_ERROR_UNSUPPORTED_MODE_OF_USE, ///< Unsupported key mode of use
	TR31_ERROR_INVALID_KEY_VERSION_FIELD, ///< Invalid key version field
	TR31_ERROR_UNSUPPORTED_EXPORTABILITY, ///< Unsupported key exportability
	TR31_ERROR_UNSUPPORTED_KEY_CONTEXT, ///< Unsupported key context
	TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD, ///< Invalid number of optional blocks field
	TR31_ERROR_DUPLICATE_OPTIONAL_BLOCK_ID, ///< Duplicate optional block identifier
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_LENGTH, ///< Invalid optional block length
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA, ///< Invalid optional block data
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_PADDING, ///< Invalid optional block padding
	TR31_ERROR_INVALID_PAYLOAD_FIELD, ///< Invalid payload data field
	TR31_ERROR_INVALID_AUTHENTICATOR_FIELD, ///< Invalid authenticator data field
	TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM, ///< Unsupported key block protection key algorithm
	TR31_ERROR_UNSUPPORTED_KBPK_LENGTH, ///< Unsupported key block protection key length
	TR31_ERROR_INVALID_KEY_LENGTH, ///< Invalid key length; possibly incorrect key block protection key
	TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED, ///< Key block verification failed; possibly incorrect key block protection key
	TR31_ERROR_KCV_NOT_AVAILABLE, ///< Key Check Value (KCV) of either the wrapped key or Key Block Protection Key (KBPK) not available
};

/**
 * Retrieve TR-31 library version string
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_lib_version_string(void);

/**
 * Populate key object
 *
 * @note This function will populate a new key object.
 *       Use @ref tr31_key_release() to release internal resources when done.
 *
 * @param usage Key usage. See @ref key-usage-values "key usage values".
 * @param algorithm Key algorithm. See @ref key-algorithm-values "key algorithm values".
 * @param mode_of_use Key mode of use. See @ref key-mode-of-use-values "key mode of use values".
 * @param key_version Key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @param exportability Key exportability. See @ref key-exportability-values "key exportability values".
 * @param key_context Key context. See @ref key-context-values "key exportability values".
 * @param data Key data. If NULL, use @ref tr31_key_set_data() to populate key data later.
 * @param length Length of key data in bytes
 * @param key Key object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_init(
	unsigned int usage,
	unsigned int algorithm,
	unsigned int mode_of_use,
	const char* key_version,
	unsigned int exportability,
	unsigned int key_context,
	const void* data,
	size_t length,
	struct tr31_key_t* key
);

/**
 * Release key object resources
 * @param key Key object
 */
void tr31_key_release(struct tr31_key_t* key);

/**
 * Copy key object
 *
 * @note This function will populate a new key object.
 *       Use @ref tr31_key_release() to release internal resources when done.
 *
 * @param src Source key object from which to copy
 * @param key Copied key object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_copy(
	const struct tr31_key_t* src,
	struct tr31_key_t* key
);

/**
 * Populate key data in key object. This function will also populate the KCV in
 * the key object when possible.
 *
 * @note This function requires a populated key object
 *       (after @ref tr31_key_init(), @ref tr31_key_copy() or @ref tr31_export())
 *
 * @param key Key object
 * @param data Key data
 * @param length Length of key data in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_set_data(struct tr31_key_t* key, const void* data, size_t length);

/**
 * Decode key version field and populate it in key object
 *
 * @param key Key object
 * @param key_version Key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_set_key_version(struct tr31_key_t* key, const char* key_version);

/**
 * Retrieve key version from key object and encode as key version field
 *
 * @param key Key object
 * @param key_version Key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_get_key_version(const struct tr31_key_t* key, char* key_version);

/**
 * Initialise key block context object
 *
 * @note Use @ref tr31_release() to release internal resources when done.
 *
 * @param version_id Key block format version
 * @param key Key object. If NULL, use @ref tr31_key_copy() to populate @p key field later.
 * @param ctx Key block context object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_init(
	uint8_t version_id,
	const struct tr31_key_t* key,
	struct tr31_ctx_t* ctx
);

/**
 * Initialise key block context object from key block header. The header may
 * also include optional blocks.
 *
 * @note The length specified in the key block header will be ignored.
 *
 * @note The total length of all optional blocks will not be validated against
 *       the encryption block length and it is therefore not necessary, but
 *       also not prohibited, to include optional block 'PB' for padding.
 *
 * @note Use @ref tr31_release() to release internal resources when done.
 *
 * @param key_block_header Key block header. If present, key block payload and
 *        authenticator will be ignored.
 * @param key_block_header_len Length of @p key_block_header in bytes. Must be
 *        at least 16 bytes.
 * @param flags Key block import flags
 * @param ctx Key block context object output
 */
int tr31_init_from_header(
	const char* key_block_header,
	size_t key_block_header_len,
	uint32_t flags,
	struct tr31_ctx_t* ctx
);

/**
 * Add optional block to key block context object
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param id Optional block identifier (see @ref optional-block-id-values "optional block IDs")
 * @param data Optional block data. Must be printable ASCII (format PA).
 * @param length Length of optional block data in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add(
	struct tr31_ctx_t* ctx,
	unsigned int id,
	const void* data,
	size_t length
);

/**
 * Find optional block in key block context object
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param id Optional block identifier (see @ref optional-block-id-values "optional block IDs")
 * @return Pointer to optional block context object, if found. Otherwise NULL.
 */
struct tr31_opt_ctx_t* tr31_opt_block_find(struct tr31_ctx_t* ctx, unsigned int id);

/**
 * Decode optional block containing Key Check Value (KCV) data. This may be
 * optional block 'KC', 'KP', 'PK' or any other proprietary optional block with
 * the same format.
 *
 * @note This function complies with ANSI X9.143 and ISO 20038, and will fail
 *       for non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_kcv(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'AL' for Asymmetric Key Life (AKL) of wrapped key to key
 * block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param akl Asymmetric Key Life (AKL). Either @ref TR31_OPT_BLOCK_AL_AKL_EPHEMERAL or @ref TR31_OPT_BLOCK_AL_AKL_STATIC.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_AL(
	struct tr31_ctx_t* ctx,
	uint8_t akl
);

/**
 * Decode optional block 'AL' for Asymmetric Key Life (AKL) of wrapped key.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param akl_data Decoded Asymmetric Key Life (AKL) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_AL(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_akl_data_t* akl_data
);

/**
 * Add optional block 'BI' for Base Derivation Key Identifier (BDK ID) for
 * DUKPT to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param key_type DUKPT key type. Either @ref TR31_OPT_BLOCK_BI_TDES_DUKPT or @ref TR31_OPT_BLOCK_BI_AES_DUKPT.
 * @param bdkid Key Set ID (KSI) or Base Derivation Key ID (BDK ID)
 * @param bdkid_len Length of @p bdkid in bytes. Must be 5 bytes for TDES DUKPT or 4 bytes for AES DUKPT (according to ANSI X9.143:2021, 6.3.6.2, table 9)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_BI(
	struct tr31_ctx_t* ctx,
	uint8_t key_type,
	const void* bdkid,
	size_t bdkid_len
);

/**
 * Decode optional block 'BI' for Base Derivation Key Identifier (BDK ID) for
 * DUKPT.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param bdkid_data Decoded Base Derivation Key ID (BDK ID) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_BI(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_bdkid_data_t* bdkid_data
);

/**
 * Add optional block 'CT' for asymmetric public key certificate or chain of
 * certificates to key block context object. Multiple calls to this function
 * will result in a certificate chain inside a singular optional block 'CT'. It
 * is the caller's responsibility to ensure that the certificates and resulting
 * certificate chain comply with ANSI X9.143.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param cert_format Certificate format. Either @ref TR31_OPT_BLOCK_CT_X509 or @ref TR31_OPT_BLOCK_CT_EMV.
 * @param cert_base64 Base64 encoded certificate data
 * @param cert_base64_len Length of @p cert_base64 in bytes.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_CT(
	struct tr31_ctx_t* ctx,
	uint8_t cert_format,
	const char* cert_base64,
	size_t cert_base64_len
);

/**
 * Add optional block 'DA' for Derivation(s) Allowed for Derivation Keys to key
 * block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param da Derivation sets (without version) as specified in ANSI X9.143:2021, 6.3.6.4
 * @param da_len Length of @p da in bytes. Must be a multiple of 5 bytes.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_DA(
	struct tr31_ctx_t* ctx,
	const void* da,
	size_t da_len
);

/**
 * Decode optional block 'DA' for Derivation(s) Allowed for Derivation Keys.
 * The caller is responsible for computing the length of the output data and
 * allocating a suitable buffer. The length can be calculated using:
 * @code
 * if (opt_ctx->data_length > 2) {
 *     da_attr_count = (opt_ctx->data_length - 2) / 5;
 *     da_data_len = sizeof(struct tr31_opt_blk_da_attr_t) * da_attr_count
 *         + sizeof(struct tr31_opt_blk_da_data_t);
 *     da_data = malloc(da_data_len);
 * }
 * @endcode
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param da_data Decoded Derivation(s) Allowed (DA) data output
 * @param da_data_len Length of @p da_data in bytes. See function description.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_DA(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_da_data_t* da_data,
	size_t da_data_len
);

/**
 * Add optional block 'HM' for HMAC hash algorithm of wrapped key to key block
 * context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param hash_algorithm HMAC hash algorithm (see @ref optional-block-hm-values "HMAC optional block values")
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_HM(
	struct tr31_ctx_t* ctx,
	uint8_t hash_algorithm
);

/**
 * Decode optional block 'HM' for HMAC hash algorithm of wrapped key.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param hash_algorithm HMAC hash algorithm output (see @ref optional-block-hm-values "HMAC optional block values")
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_HM(
	const struct tr31_opt_ctx_t* opt_ctx,
	uint8_t* hash_algorithm
);

/**
 * Add optional block 'IK' for Initial Key Identifier (IKID) of
 * Initial AES DUKPT Key to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param ikid Initial Key Identifier (IKID) for Initial AES DUKPT Key
 * @param ikid_len Length of @p ikid in bytes. Must be 8 bytes.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_IK(
	struct tr31_ctx_t* ctx,
	const void* ikid,
	size_t ikid_len
);

/**
 * Decode optional block 'IK' for Initial Key Identifier (IKID) of
 * Initial AES DUKPT Key.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param ikid Initial Key Identifier (IKID) output
 * @param ikid_len Length of @p ikid in bytes. Must be 8 bytes.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_IK(
	const struct tr31_opt_ctx_t* opt_ctx,
	void* ikid,
	size_t ikid_len
);

/**
 * Add optional block 'KC' for Key Check Value (KCV) of wrapped key to key
 * block context object. This function will not compute the KCV but cause it to
 * be computed by @ref tr31_export().
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_KC(struct tr31_ctx_t* ctx);

/**
 * Decode optional block 'KC' for Key Check Value (KCV) of wrapped key.
 * This function will not compute the KCV.
 *
 * @note This function complies with ANSI X9.143 and ISO 20038, and will fail
 *       for non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_KC(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'KP' for Key Check Value (KCV) of Key Block Protection
 * Key (KBPK) to key block context object. This function will not compute the
 * KCV but cause it to be computed by @ref tr31_export().
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_KP(struct tr31_ctx_t* ctx);

/**
 * Decode optional block 'KP' for Key Check Value (KCV) of Key Block Protection
 * Key (KBPK). This function will not compute the KCV.
 *
 * @note This function complies with ANSI X9.143 and ISO 20038, and will fail
 *       for non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_KP(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'KS' for Initial Key Serial Number (IKSN) of
 * Initial TDES DUKPT key to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param iksn Initial Key Serial Number (IKSN) for Initial TDES DUKPT Key
 * @param iksn_len of @p iksn in bytes. Must be 10 bytes (according to ANSI X9.143:2021, 6.3.6.8, table 16) or 8 bytes (for legacy implementations).
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_KS(
	struct tr31_ctx_t* ctx,
	const void* iksn,
	size_t iksn_len
);

/**
 * Decode optional block 'KS' for Initial Key Serial Number (IKSN) of
 * Initial TDES DUKPT key.
 *
 * @note This function complies with ANSI X9.143 and ISO 20038, and will fail
 *       for non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param iksn Initial Key Serial Number (IKSN) output
 * @param iksn_len of @p iksn in bytes. Must be 10 bytes (according to ANSI X9.143:2021, 6.3.6.8, table 16) or 8 bytes (for legacy implementations).
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_KS(
	const struct tr31_opt_ctx_t* opt_ctx,
	void* iksn,
	size_t iksn_len
);

/**
 * Add optional block 'KV' for Key Block Values to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 * @deprecated Optional block 'KV' is deprecated by ANSI X9.143.
 *
 * @param ctx Key block context object
 * @param version_id Version ID field. Must contain two printable ASCII characters or NULL for default value.
 * @param other Other reserved field. Must contain two printable ASCII characters or NULL for default value.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_KV(
	struct tr31_ctx_t* ctx,
	const char* version_id,
	const char* other
) __attribute__((deprecated));

/**
 * Add optional block 'LB' for label to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param label Label string. Must contain printable ASCII characters.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_LB(
	struct tr31_ctx_t* ctx,
	const char* label
);

/**
 * Add optional block 'PK' for Key Check Value (KCV) of export protection key
 * to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param kcv_algorithm KCV algorithm. Either @ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC.
 * @param kcv Key Check Value (KCV) according to algorithm specified by @p kcv_algorithm
 * @param kcv_len Length of @p kcv in bytes. Must comply with ANSI X9.24-1 Annex A.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_PK(
	struct tr31_ctx_t* ctx,
	uint8_t kcv_algorithm,
	const void* kcv,
	size_t kcv_len
);

/**
 * Decode optional block 'PK' for Key Check Value (KCV) of export protection
 * key.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_PK(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'TC' for time of creation of the wrapped key to key block
 * context object
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param tc_str Time of creation string in ISO 8601 UTC format (see ANSI X9.143:2021, 6.3.6.13, table 21)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_TC(
	struct tr31_ctx_t* ctx,
	const char* tc_str
);

/**
 * Add optional block 'TS' for time stamp indicating when key block was formed
 * to key block context object
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param ts_str Time stamp string in ISO 8601 UTC format (see ANSI X9.143:2021, 6.3.6.14, table 22)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_TS(
	struct tr31_ctx_t* ctx,
	const char* ts_str
);

/**
 * Add optional block 'WP' for Wrapping Pedigree to key block context object.
 *
 * @note This function requires an initialised key block context object to be provided.
 *
 * @param ctx Key block context object
 * @param wrapping_pedigree Wrapping Pedigree. Must be a value from 0 to 3 (see @ref optional-block-wp-values "Wrapping Pedigree (WP) optional block values").
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_WP(
	struct tr31_ctx_t* ctx,
	uint8_t wrapping_pedigree
);

/**
 * Decode optional block 'WP' for Wrapping Pedigree.
 *
 * @note This function complies with ANSI X9.143 and will fail for
 *       non-compliant encodings of this optional block.
 *
 * @param opt_ctx Optional block context object
 * @param wp_data Decoded Wrapping Pedigree (WP) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_WP(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_wp_data_t* wp_data
);

/**
 * Import key block. This function will also decrypt the key data if possible.
 *
 * @note This function will populate a new key block context object.
 *       Use @ref tr31_release() to release internal resources when done.
 *
 * @param key_block Key block. Must contain printable ASCII characters. Null-termination not required.
 * @param key_block_len Length of key block in bytes, excluding null-termination.
 * @param kbpk Key block protection key. NULL if not available or decryption is not required.
 * @param flags Key block import flags. See @ref import-flags "import flags".
 * @param ctx Key block context object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_import(
	const char* key_block,
	size_t key_block_len,
	const struct tr31_key_t* kbpk,
	uint32_t flags,
	struct tr31_ctx_t* ctx
);

/**
 * Export key block. This function will create and encrypt the key block.
 *
 * @note This function requires a populated key block context object to be
 *       provided. See #tr31_ctx_t for populating manually.
 *
 * @param ctx Key block context object input
 * @param kbpk Key block protection key.
 * @param flags Key block export flags. See @ref export-flags "export flags".
 * @param key_block Key block output. Will contain printable ASCII characters and will be null-terminated.
 * @param key_block_buf_len Key block output buffer length.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_export(
	const struct tr31_ctx_t* ctx,
	const struct tr31_key_t* kbpk,
	uint32_t flags,
	char* key_block,
	size_t key_block_buf_len
);

/**
 * Release key block context object resources
 * @param ctx Key block context object
 */
void tr31_release(struct tr31_ctx_t* ctx);

/**
 * Retrieve string associated with error value
 * @param error Error value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_error_string(enum tr31_error_t error);

__END_DECLS

#endif
