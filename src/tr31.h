/**
 * @file tr31.h
 * @brief High level TR-31 library interface
 *
 * Copyright (c) 2020, 2021, 2022, 2023 Leon Lynch
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

/// TR-31 format versions
enum tr31_version_t {
	TR31_VERSION_A = 'A', ///< TR-31 format version A as defined in TR-31:2005; uses TDES Key Variant Binding Method
	TR31_VERSION_B = 'B', ///< TR-31 format version B as defined in TR-31:2010; uses TDES Key Derivation Binding Method
	TR31_VERSION_C = 'C', ///< TR-31 format version C as defined in TR-31:2010; uses TDES Key Variant Binding Method
	TR31_VERSION_D = 'D', ///< TR-31 format version D as defined in TR-31:2018 and ISO 20038:2017; uses AES Key Derivation Binding Method
	TR31_VERSION_E = 'E', ///< TR-31 format version E as defined in ISO 20038:2017; uses AES Key Derivation Binding Method
};

// TR-31 key usage (see ANSI X9.143:2021, 6.3.1, table 2)
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
#define TR31_KEY_USAGE_TR31_KBPK        (0x4B31) ///< Key Usage K1: TR-31 Key Block Protection Key (KBPK)
#define TR31_KEY_USAGE_TR34_APK_KRD     (0x4B32) ///< Key Usage K2: TR-34 Asymmetric Key Pair for Key Receiving Device
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

// TR-31 algorithm (see ANSI X9.143:2021, 6.3.2, table 3)
#define TR31_KEY_ALGORITHM_AES          ('A') ///< Key Algorithm A: AES
#define TR31_KEY_ALGORITHM_DES          ('D') ///< Key Algorithm D: DES
#define TR31_KEY_ALGORITHM_EC           ('E') ///< Key Algorithm E: Elliptic Curve
#define TR31_KEY_ALGORITHM_HMAC         ('H') ///< Key Algorithm H: HMAC
#define TR31_KEY_ALGORITHM_RSA          ('R') ///< Key Algorithm R: RSA
#define TR31_KEY_ALGORITHM_DSA          ('S') ///< Key Algorithm S: DSA
#define TR31_KEY_ALGORITHM_TDES         ('T') ///< Key Algorithm T: Triple DES

// TR-31 mode of use (see ANSI X9.143:2021, 6.3.3, table 4)
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

/// TR-31 key version field interpretation (see ANSI X9.143:2021, 6.3.4, table 5)
enum tr31_key_version_t {
	TR31_KEY_VERSION_IS_UNUSED = 0, ///< Key version field unused
	TR31_KEY_VERSION_IS_COMPONENT, ///< key version field is component number
	TR31_KEY_VERSION_IS_VALID, ///< Key version field is valid
};

// TR-31 exportability (see ANSI X9.143:2021, 6.3.5, table 6)
#define TR31_KEY_EXPORT_TRUSTED         ('E') ///< Exportability E: Exportable in a trusted key block in accordance with ANSI X9.24
#define TR31_KEY_EXPORT_NONE            ('N') ///< Exportability N: Not exportable
#define TR31_KEY_EXPORT_SENSITIVE       ('S') ///< Exportability S: Sensitive; exportable in forms not in accordance with ANSI X9.24; eg ANSI X9.17

// TR-31 optional block IDs (see ANSI X9.143:2021, 6.3.6, table 7)
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

// TR-31 Asymmetric Key Life (AKL) optional block format (see ANSI X9.143:2021, 6.3.6.1, table 8)
#define TR31_OPT_BLOCK_AL_VERSION_1     (0x01) ///< Asymmetric Key Life version: 1
#define TR31_OPT_BLOCK_AL_AKL_EPHEMERAL (0x00) ///< Asymmetric Key Life: Ephemeral
#define TR31_OPT_BLOCK_AL_AKL_STATIC    (0x01) ///< Asymmetric Key Life: Static/Permanent

// TR-31 Base Derivation Key Identifier (BDK ID) for DUKPT optional block format (see ANSI X9.143:2021, 6.3.6.2, table 9)
#define TR31_OPT_BLOCK_BI_TDES_DUKPT    (0x00) ///< TDES DUKPT Key Set ID (KSI)
#define TR31_OPT_BLOCK_BI_AES_DUKPT     (0x01) ///< AES DUKPT Base Derivation Key ID (BDK ID)

// TR-31 Certificate Format for Public Key Certificate optional block format (see ANSI X9.143:2021, 6.3.6.3, table 10/11)
#define TR31_OPT_BLOCK_CT_X509          (0x00) ///< Certificate Format: X.509
#define TR31_OPT_BLOCK_CT_EMV           (0x01) ///< Certificate Format: EMV
#define TR31_OPT_BLOCK_CT_CERT_CHAIN    (0x02) ///< Certificate Format: Certificate Chain

// TR-31 Derivation(s) Allowed optional block format (see ANSI X9.143:2021, 6.3.6.4, table 12)
#define TR31_OPT_BLOCK_DA_VERSION_1     (0x01) ///< Derivation(s) Allowed version: 1

// TR-31 HMAC optional block format (see ANSI X9.143:2021, 6.3.6.5, table 13)
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

// TR-31 Key Check Value (KCV) optional block format (see ANSI X9.143:2021, 6.3.6.7, table 15)
#define TR31_OPT_BLOCK_KCV_LEGACY       (0x00) ///< KCV algorithm: Legacy KCV algorithm
#define TR31_OPT_BLOCK_KCV_CMAC         (0x01) ///< KCV algorithm: CMAC based KCV

// TR-31 Wrapping Pedigree (WP) optional block format (see ANSI X9.143:2021, 6.3.6.15, table 23)
#define TR31_OPT_BLOCK_WP_VERSION_0     (0x00) ///< Wrapping Pedigree (WP) version: 0
#define TR31_OPT_BLOCK_WP_EQ_GT         (0)    ///< Wrapping Pedigree: Equal or greater effective strength
#define TR31_OPT_BLOCK_WP_LT            (1)    ///< Wrapping Pedigree: Lesser effective strength
#define TR31_OPT_BLOCK_WP_ASYMMETRIC    (2)    ///< Asymmetric key at risk of quantum computing
#define TR31_OPT_BLOCK_WP_ASYMMETRIC_LT (3)    ///< Asymmetric key at risk of quantum computing and symmetric key of lesser effective strength

// TR-31 export flags
#define TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION   (0x01) ///< Disable ANSI X9.143 key length obfuscation during key block export
#define TR31_EXPORT_ZERO_OPT_BLOCK_PB           (0x02) ///< Fill optional block PB using zeros instead of random characters during TR-31 export.

/// TR-31 key object
struct tr31_key_t {
	unsigned int usage; ///< TR-31 key usage
	unsigned int algorithm; ///< TR-31 key algorithm
	unsigned int mode_of_use; ///< TR-31 key mode of use

	// key version field information
	enum tr31_key_version_t key_version; ///< TR-31 key version field interpretation
	char key_version_str[3]; ///< TR-31 key version string. Null terminated. Invalid if unused.

	unsigned int exportability; ///< TR-31 key exportability

	size_t length; ///< Key data length in bytes
	void* data; ///< Key data

	uint8_t kcv_algorithm; ///< KCV algorithm (@ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC)
	size_t kcv_len; ///< Key Check Value (KCV) length in bytes
	uint8_t kcv[5]; ///< Key Check Value (KCV)
};

/// TR-31 optional block context object
struct tr31_opt_ctx_t {
	unsigned int id; ///< TR-31 optional block identifier
	size_t data_length; ///< TR-31 optional block data length in bytes
	void* data; ///< TR-31 optional block data
};

/// Decoded optional block Base Derivation Key Identifier (BDK ID) data
struct tr31_opt_blk_bdkid_data_t {
	uint8_t key_type; ///< DUKPT key type. Either @ref TR31_OPT_BLOCK_BI_TDES_DUKPT or @ref TR31_OPT_BLOCK_BI_AES_DUKPT.
	size_t bdkid_len; ///< Length of @ref tr31_opt_blk_bdkid_data_t.bdkid in bytes. Must be 5 bytes for TDES DUKPT or 4 bytes for AES DUKPT (according to ANSI X9.143:2021, 6.3.6.2, table 9)
	uint8_t bdkid[5]; ///< Key Set ID (KSI) or Base Derivation Key ID (BDK ID)
};

/// Decoded optional block Key Check Value (KCV) data
struct tr31_opt_blk_kcv_data_t {
	uint8_t kcv_algorithm; ///< KCV algorithm output. Either @ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC.
	size_t kcv_len; ///< Length of @ref tr31_opt_blk_kcv_data_t.kcv in bytes. Must be at most 3 bytes for legacy KCV or at most 5 bytes for CMAC KCV (according to ANSI X9.24-1)
	uint8_t kcv[5]; ///< Key Check Value (KCV)
};

/**
 * @brief TR-31 context object
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
	enum tr31_version_t version; ///< TR-31 key block format version
	size_t length; ///< TR-31 key block length in bytes

	struct tr31_key_t key; ///< TR-31 key object

	size_t opt_blocks_count; ///< TR-31 number of optional blocks
	struct tr31_opt_ctx_t* opt_blocks; ///< TR-31 optional block context objects

	size_t header_length; ///< TR-31 header data length in bytes, including optional blocks
	const void* header; ///< Pointer to TR-31 header data for internal use only. @warning For internal use only!

	size_t payload_length; ///< TR-31 payload data length in bytes
	void* payload; ///< Decoded TR-31 payload data for internal use only. @warning For internal use only!

	size_t authenticator_length; ///< TR-31 authenticator data length in bytes
	void* authenticator; ///< Decoded TR-31 authenticator data for internal use only. @warning For internal use only!

	uint32_t export_flags; ///< Flags used during TR-31 export
};

/// TR-31 library errors
enum tr31_error_t {
	TR31_ERROR_INVALID_LENGTH = 1, ///< Invalid key block length
	TR31_ERROR_UNSUPPORTED_VERSION, ///< Unsupported key block format version
	TR31_ERROR_INVALID_LENGTH_FIELD, ///< Invalid key block length field
	TR31_ERROR_UNSUPPORTED_KEY_USAGE, ///< Unsupported key usage
	TR31_ERROR_UNSUPPORTED_ALGORITHM, ///< Unsupported key algorithm
	TR31_ERROR_UNSUPPORTED_MODE_OF_USE, ///< Unsupported key mode of use
	TR31_ERROR_INVALID_KEY_VERSION_FIELD, ///< Invalid key version field
	TR31_ERROR_UNSUPPORTED_EXPORTABILITY, ///< Unsupported key exportability
	TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD, ///< Invalid number of optional blocks field
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_LENGTH, ///< Invalid optional block length
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA, ///< Invalid optional block data
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
 * Populate TR-31 key object
 *
 * @note This function will populate a new TR-31 key object.
 *       Use @ref tr31_key_release() to release internal resources when done.
 *
 * @param usage TR-31 key usage
 * @param algorithm TR-31 key algorithm
 * @param mode_of_use TR-31 key mode of use
 * @param key_version TR-31 key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @param exportability TR-31 key exportability
 * @param data Key data. If NULL, use @ref tr31_key_set_data() to populate key data later.
 * @param length Length of key data in bytes
 * @param key TR-31 key object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_init(
	unsigned int usage,
	unsigned int algorithm,
	unsigned int mode_of_use,
	const char* key_version,
	unsigned int exportability,
	const void* data,
	size_t length,
	struct tr31_key_t* key
);

/**
 * Release TR-31 key object resources
 * @param key TR-31 key object
 */
void tr31_key_release(struct tr31_key_t* key);

/**
 * Copy TR-31 key object
 *
 * @note This function will populate a new TR-31 key object.
 *       Use @ref tr31_key_release() to release internal resources when done.
 *
 * @param src Source TR-31 key object from which to copy
 * @param key TR-31 key object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_copy(
	const struct tr31_key_t* src,
	struct tr31_key_t* key
);

/**
 * Populate key data in TR-31 key object. This function will also populate the
 * KCV in the TR-31 key object when possible.
 *
 * @note This function requires a populated TR-31 key object
 *       (after @ref tr31_key_init(), @ref tr31_key_copy() or @ref tr31_export())
 *
 * @param key TR-31 key object
 * @param data Key data
 * @param length Length of key data in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_set_data(struct tr31_key_t* key, const void* data, size_t length);

/**
 * Decode TR-31 key version field and populate it in TR-31 key object
 * @param key TR-31 key object
 * @param key_version TR-31 key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_set_key_version(struct tr31_key_t* key, const char* key_version);

/**
 * Retrieve key version from TR-31 key object and encode as TR-31 key version field
 * @param key TR-31 key object
 * @param key_version TR-31 key version; two bytes (see ANSI X9.143:2021, 6.3.4, table 5)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_key_get_key_version(const struct tr31_key_t* key, char* key_version);

/**
 * Initialise TR-31 context object
 *
 * @note Use @ref tr31_release() to release internal resources when done.
 *
 * @param version_id TR-31 format version
 * @param key TR-31 key object. If NULL, use @ref tr31_key_copy() to populate @p key field later.
 * @param ctx TR-31 context object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_init(
	uint8_t version_id,
	const struct tr31_key_t* key,
	struct tr31_ctx_t* ctx
);

/**
 * Add optional block to TR-31 context object
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param id TR-31 optional block identifier (see ANSI X9.143:2021, 6.3.6, table 7)
 * @param data TR-31 optional block data
 * @param length Length of TR-31 optional block data in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add(
	struct tr31_ctx_t* ctx,
	unsigned int id,
	const void* data,
	size_t length
);

/**
 * Find optional block in TR-31 context object
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param id TR-31 optional block identifier (see ANSI X9.143:2021, 6.3.6, table 7)
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
 * @param opt_ctx TR-31 optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_kcv(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'AL' for Asymmetric Key Life (AKL) of wrapped key to
 * TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param akl Asymmetric Key Life (AKL)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_AL(
	struct tr31_ctx_t* ctx,
	uint8_t akl
);

/**
 * Add optional block 'BI' for Base Derivation Key Identifier (BDK ID) for
 * DUKPT to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * @param opt_ctx TR-31 optional block context object
 * @param bdkid_data Decoded Base Derivation Key ID (BDK ID) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_BI(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_bdkid_data_t* bdkid_data
);

/**
 * Add optional block 'CT' for asymmetric public key certificate or chain of
 * certificates to TR-31 context object. Multiple calls to this function will
 * result in a certificate chain inside a singular optional block 'CT'. It is
 * the caller's responsibility to ensure that the certificates and resulting
 * certificate chain comply with ANSI X9.143.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * Add optional block 'DA' for Derivation(s) Allowed for Derivation Keys to
 * TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * Add optional block 'HM' for HMAC hash algorithm of wrapped key to TR-31
 * context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param hash_algorithm TR-31 HMAC hash algorithm (see ANSI X9.143:2021, 6.3.6.5, table 13)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_HM(
	struct tr31_ctx_t* ctx,
	uint8_t hash_algorithm
);

/**
 * Add optional block 'IK' for Initial Key Identifier (IKID) of
 * Initial AES DUKPT Key to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param ikid Initial Key Identifier (IKID) for Initial AES DUKPT Key
 * @param ikid_len of @p ikid in bytes. Must be 8 bytes.
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
 * @param opt_ctx TR-31 optional block context object
 * @param ikid Initial Key Identifier (IKID) output
 * @param ikid_len of @p ikid in bytes. Must be 8 bytes.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_IK(
	const struct tr31_opt_ctx_t* opt_ctx,
	void* ikid,
	size_t ikid_len
);

/**
 * Add optional block 'KC' for Key Check Value (KCV) of wrapped key to TR-31
 * context object. This function will not compute the KCV but cause it to be
 * computed by @ref tr31_export().
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * @param opt_ctx TR-31 optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_KC(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'KP' for Key Check Value (KCV) of Key Block Protection
 * Key (KBPK) to TR-31 context object. This function will not compute the KCV
 * but cause it to be computed by @ref tr31_export().
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * @param opt_ctx TR-31 optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_KP(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'KS' for Initial Key Serial Number (IKSN) of
 * Initial TDES DUKPT key to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
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
 * @param opt_ctx TR-31 optional block context object
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
 * Add optional block 'KV' for Key Block Values to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 * @deprecated Optional block 'KV' is deprecated by ANSI X9.143.
 *
 * @param ctx TR-31 context object
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
 * Add optional block 'LB' for label to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param label Label string. Must contain printable ASCII characters.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_LB(
	struct tr31_ctx_t* ctx,
	const char* label
);

/**
 * Add optional block 'PK' for Key Check Value (KCV) of export protection key
 * to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param kcv_algorithm KCV algorithm (@ref TR31_OPT_BLOCK_KCV_LEGACY or @ref TR31_OPT_BLOCK_KCV_CMAC)
 * @param kcv Key Check Value (KCV) according to algoritm specified by @p kcv_algorithm
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
 * @param opt_ctx TR-31 optional block context object
 * @param kcv_data Decoded optional block Key Check Value (KCV) data output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_decode_PK(
	const struct tr31_opt_ctx_t* opt_ctx,
	struct tr31_opt_blk_kcv_data_t* kcv_data
);

/**
 * Add optional block 'TC' for time of creation of the wrapped key to TR-31
 * context object
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param tc_str Time of creation string in ISO 8601 UTC format (see ANSI X9.143:2021, 6.3.6.13, table 21)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_TC(
	struct tr31_ctx_t* ctx,
	const char* tc_str
);

/**
 * Add optional block 'TS' for time stamp indicating when key block was formed
 * to TR-31 context object
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param ts_str Time stamp string in ISO 8601 UTC format (see ANSI X9.143:2021, 6.3.6.14, table 22)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_TS(
	struct tr31_ctx_t* ctx,
	const char* ts_str
);

/**
 * Add optional block 'WP' for wrapping pedigree to TR-31 context object.
 *
 * @note This function requires an initialised TR-31 context object to be provided.
 *
 * @param ctx TR-31 context object
 * @param wrapping_pedigree Wrapping Pedigree. Must be a value from 0 to 3 (see ANSI X9.143:2021, 6.3.6.15, table 23)
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_opt_block_add_WP(
	struct tr31_ctx_t* ctx,
	uint8_t wrapping_pedigree
);

/**
 * Import TR-31 key block. This function will also decrypt the key data if possible.
 *
 * @note This function will populate a new TR-31 context object.
 *       Use @ref tr31_release() to release internal resources when done.
 *
 * @param key_block TR-31 key block. Null terminated. At least the header must be ASCII encoded.
 * @param kbpk TR-31 key block protection key. NULL if not available or decryption is not required.
 * @param ctx TR-31 context object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_import(
	const char* key_block,
	const struct tr31_key_t* kbpk,
	struct tr31_ctx_t* ctx
);

/**
 * Export TR-31 key block. This function will create and encrypt the key block.
 *
 * @note This function requires a populated TR-31 context object to be provided. See #tr31_ctx_t for populating manually.
 *
 * @param ctx TR-31 context object input
 * @param kbpk TR-31 key block protection key.
 * @param key_block TR-31 key block output. Null terminated. At least the header will be ASCII encoded.
 * @param key_block_len TR-31 key block output buffer length.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. See @ref tr31_error_t
 */
int tr31_export(
	struct tr31_ctx_t* ctx,
	const struct tr31_key_t* kbpk,
	char* key_block,
	size_t key_block_len
);

/**
 * Release TR-31 context object resources
 * @param ctx TR-31 context object
 */
void tr31_release(struct tr31_ctx_t* ctx);

/**
 * Retrieve string associated with error value
 * @param error Error value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_error_string(enum tr31_error_t error);

/**
 * Create ASCII string associated with key usage value
 * @param usage Key usage value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_get_key_usage_ascii(unsigned int usage, char* ascii, size_t ascii_len);

/**
 * Retrieve string associated with key usage value
 * @param usage Key usage value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_usage_string(unsigned int usage);

/**
 * Retrieve string associated with key algorithm value
 * @param algorithm Key algorithm value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_algorithm_string(unsigned int algorithm);

/**
 * Retrieve string associated with key mode of use value
 * @param mode_of_use Key mode of use value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_mode_of_use_string(unsigned int mode_of_use);

/**
 * Retrieve string associated with key exportability value
 * @param exportability Key exportability value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_exportability_string(unsigned int exportability);

/**
 * Create ASCII string associated with optional block ID value
 * @param opt_block_id Optional block ID value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_get_opt_block_id_ascii(unsigned int opt_block_id, char* ascii, size_t ascii_len);

/**
 * Retrieve string associated with optional block ID value
 * @param opt_block_id Optional block ID value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_opt_block_id_string(unsigned int opt_block_id);

__END_DECLS

#endif
