/**
 * @file tr31.h
 *
 * Copyright (c) 2020, 2021 ono//connect
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
	TR31_VERSION_A = 'A', ///< TR-31 format version A as defined in TR-31:2005; uses Key Variant Binding Method
	TR31_VERSION_B = 'B', ///< TR-31 format version B as defined in TR-31:2010; uses Key Derivation Binding Method
	TR31_VERSION_C = 'C', ///< TR-31 format version C as defined in TR-31:2010; uses Key Variant Binding Method
	TR31_VERSION_D = 'D', ///< TR-31 format version D as defined in TR-31:2018; uses AES Key Derivation Binding Method
};

// TR-31 key usage (see TR-31:2018, A.5.1, table 6)
#define TR31_KEY_USAGE_BDK              (0x4230) ///< Key Usage B0: Base Derivation Key (BDK)
#define TR31_KEY_USAGE_DUKPT_IPEK       (0x4231) ///< Key Usage B1: Initial DUKPT Key (IPEK)
#define TR31_KEY_USAGE_BKV              (0x4232) ///< Key Usage B2: Base Key Variant
#define TR31_KEY_USAGE_CVK              (0x4330) ///< Key Usage C0: Card Verification Key (CVK)
#define TR31_KEY_USAGE_DATA             (0x4430) ///< Key Usage D0: Symmetric Data Encryption Key
#define TR31_KEY_USAGE_ASYMMETRIC_DATA  (0x4431) ///< Key Usage D1: Asymmetric Data Encryption Key
#define TR31_KEY_USAGE_DATA_DEC_TABLE   (0x4432) ///< Key Usage D2: Decimalization Table Data Encryption Key
#define TR31_KEY_USAGE_EMV_MKAC         (0x4530) ///< Key Usage E0: EMV/chip Issuer Master Key: Application cryptograms (MKAC)
#define TR31_KEY_USAGE_EMV_MKSMC        (0x4531) ///< Key Usage E1: EMV/chip Issuer Master Key: Secure Messaging for Confidentiality (MKSMC)
#define TR31_KEY_USAGE_EMV_MKSMI        (0x4532) ///< Key Usage E2: EMV/chip Issuer Master Key: Secure Messaging for Integrity (MKSMI)
#define TR31_KEY_USAGE_EMV_MKDAC        (0x4533) ///< Key Usage E3: EMV/chip Issuer Master Key: Data Authentication Code (MKDAC)
#define TR31_KEY_USAGE_EMV_MKDN         (0x4534) ///< Key Usage E4: EMV/chip Issuer Master Key: Dynamic Numbers (MKDN)
#define TR31_KEY_USAGE_EMV_CP           (0x4535) ///< Key Usage E5: EMV/chip Issuer Master Key: Card Personalization (CP)
#define TR31_KEY_USAGE_EMV_OTHER        (0x4536) ///< Key Usage E6: EMV/chip Issuer Master Key: Other
#define TR31_KEY_USAGE_IV               (0x4930) ///< Key Usage I0: Initialization Vector
#define TR31_KEY_USAGE_KEK              (0x4B30) ///< Key Usage K0: Key Encryption or Wrapping Key (KEK)
#define TR31_KEY_USAGE_TR31_KBPK        (0x4B31) ///< Key Usage K1: TR-31 Key Block Protection Key (KBPK)
#define TR31_KEY_USAGE_TR34_KEK         (0x4B32) ///< Key Usage K2: TR-34 Asymmetric Key Exchange Key (KEK)
#define TR31_KEY_USAGE_ASYMMETRIC_KEK   (0x4B33) ///< Key Usage K3: Asymmetric Key Agreement or Wrapping Key
#define TR31_KEY_USAGE_ISO16609_MAC_1   (0x4D30) ///< Key Usage M0: ISO 16609 MAC algorithm 1 (using TDES)
#define TR31_KEY_USAGE_ISO9797_1_MAC_1  (0x4D31) ///< Key Usage M1: ISO 9797-1 MAC Algorithm 1 (CBC-MAC)
#define TR31_KEY_USAGE_ISO9797_1_MAC_2  (0x4D32) ///< Key Usage M2: ISO 9797-1 MAC Algorithm 2
#define TR31_KEY_USAGE_ISO9797_1_MAC_3  (0x4D33) ///< Key Usage M3: ISO 9797-1 MAC Algorithm 3 (Retail MAC)
#define TR31_KEY_USAGE_ISO9797_1_MAC_4  (0x4D34) ///< Key Usage M4: ISO 9797-1 MAC Algorithm 4
#define TR31_KEY_USAGE_ISO9797_1_MAC_5  (0x4D35) ///< Key Usage M5: ISO 9797-1:1999 MAC Algorithm 5 (legacy)
#define TR31_KEY_USAGE_ISO9797_1_CMAC   (0x4D36) ///< Key Usage M6: ISO 9797-1:2011 MAC Algorithm 5 (CMAC)
#define TR31_KEY_USAGE_HMAC             (0x4D37) ///< Key Usage M7: HMAC
#define TR31_KEY_USAGE_ISO9797_1_MAC_6  (0x4D38) ///< Key Usage M8: ISO 9797-1 MAC Algorithm 6
#define TR31_KEY_USAGE_PIN              (0x5030) ///< Key Usage P0: PIN Encryption Key
#define TR31_KEY_USAGE_ASYMMETRIC_SIG   (0x5330) ///< Key Usage S0: Asymmetric key pair for digital signature
#define TR31_KEY_USAGE_ASYMMETRIC_CA    (0x5331) ///< Key Usage S1: Asymmetric key pair for CA use
#define TR31_KEY_USAGE_ASYMMETRIC_OTHER (0x5332) ///< Key Usage S2: Asymmetric key pair for non-X9.24 use
#define TR31_KEY_USAGE_PV               (0x5630) ///< Key Usage V0: PIN Verification Key (Other)
#define TR31_KEY_USAGE_PV_IBM3624       (0x5631) ///< Key Usage V1: PIN Verification Key (IBM 3624)
#define TR31_KEY_USAGE_PV_VISA          (0x5632) ///< Key Usage V2: PIN Verification Key (VISA PVV)
#define TR31_KEY_USAGE_PV_X9_132_1      (0x5633) ///< Key Usage V3: PIN Verification Key (X9-132 algorithm 1)
#define TR31_KEY_USAGE_PV_X9_132_2      (0x5634) ///< Key Usage V4: PIN Verification Key (X9-132 algorithm 2)

// TR-31 algorithm (see TR-31:2018, A.5.2, table 7)
#define TR31_KEY_ALGORITHM_AES          ('A') ///< Key Algorithm A: AES
#define TR31_KEY_ALGORITHM_DES          ('D') ///< Key Algorithm D: DES
#define TR31_KEY_ALGORITHM_EC           ('E') ///< Key Algorithm E: Elliptic Curve
#define TR31_KEY_ALGORITHM_HMAC         ('H') ///< Key Algorithm H: HMAC
#define TR31_KEY_ALGORITHM_RSA          ('R') ///< Key Algorithm R: RSA
#define TR31_KEY_ALGORITHM_DSA          ('S') ///< Key Algorithm S: DSA
#define TR31_KEY_ALGORITHM_TDES         ('T') ///< Key Algorithm T: Triple DES

// TR-31 mode of use (see TR-31:2018, A.5.3, table 8)
#define TR31_KEY_MODE_OF_USE_ENC_DEC    ('B') ///< Key Mode of Use B: Encrypt and Decrypt (Wrap and Unwrap)
#define TR31_KEY_MODE_OF_USE_MAC        ('C') ///< Key Mode of Use C: MAC Calculate (Generate and Verify)
#define TR31_KEY_MODE_OF_USE_DEC        ('D') ///< Key Mode of Use D: Decrypt / Unwrap Only
#define TR31_KEY_MODE_OF_USE_ENC        ('E') ///< Key Mode of Use E: Encrypt / Wrap Only
#define TR31_KEY_MODE_OF_USE_MAC_GEN    ('G') ///< Key Mode of Use G: MAC Generate Only
#define TR31_KEY_MODE_OF_USE_ANY        ('N') ///< Key Mode of Use N: No special restrictions or not applicable (other than restrictions implied by the Key Usage)
#define TR31_KEY_MODE_OF_USE_SIG        ('S') ///< Key Mode of Use S: Signature Only
#define TR31_KEY_MODE_OF_USE_MAC_VERIFY ('V') ///< Key Mode of Use V: MAC Verify Only
#define TR31_KEY_MODE_OF_USE_DERIVE     ('X') ///< Key Mode of Use X: Key Derivation
#define TR31_KEY_MODE_OF_USE_VARIANT    ('Y') ///< Key Mode of Use Y: Create Key Variants

/// TR-31 key version field interpretation (see TR-31:2018, A.5.4, table 9)
enum tr31_key_version_t {
	TR31_KEY_VERSION_IS_UNUSED = 0, ///< Key version field unused
	TR31_KEY_VERSION_IS_VALID, ///< Key version field is valid
	TR31_KEY_VERSION_IS_COMPONENT, ///< key version field is component number
};

// TR-31 exportability (see TR-31:2018, A.5.5, table 10)
#define TR31_KEY_EXPORT_TRUSTED         ('E') ///< Exportability E: Exportable in a trusted key block in accordance with ANSI X9.24
#define TR31_KEY_EXPORT_NONE            ('N') ///< Exportability N: Not exportable
#define TR31_KEY_EXPORT_SENSITIVE       ('S') ///< Exportability S: Sensitive; exportable in forms not in accordance with ANSI X9.24; eg ANSI X9.17

// TR-31 optional block IDs (see TR-31:2018, A.5.6, table 11)
#define TR31_OPT_BLOCK_CT               (0x4354) ///< Optional Block CT: Public Key Certificate
#define TR31_OPT_BLOCK_HM               (0x484D) ///< Optional Block HM: HMAC hash algorithm
#define TR31_OPT_BLOCK_IK               (0x494B) ///< Optional Block IK: Initial Key Identifier (see ANSI X9.24-3:2017, 4.17)
#define TR31_OPT_BLOCK_KC               (0x4B43) ///< Optional Block KC: Key Check Value (KCV) of wrapped key (see ANSI X9.24-1:2017, Annex A)
#define TR31_OPT_BLOCK_KP               (0x4B50) ///< Optional Block KP: Key Check Value (KCV) of KBPK (see ANSI X9.24-1:2017, Annex A)
#define TR31_OPT_BLOCK_KS               (0x4B53) ///< Optional Block KS: Key Set Identifier (see ANSI X9.24-1:2009, Annex D)
#define TR31_OPT_BLOCK_KV               (0x4B56) ///< Optional Block KV: Key Block Values
#define TR31_OPT_BLOCK_PB               (0x5042) ///< Optional Block PB: Padding Block
#define TR31_OPT_BLOCK_TS               (0x5453) ///< Optional Block TS: Time Stamp (in UTC time format)

// TR-31 KCV optional block format (see TR-31:2018, A.5.8)
#define TR31_OPT_BLOCK_KCV_LEGACY       (0x00) ///< KCV algorithm: Legacy KCV algorithm
#define TR31_OPT_BLOCK_KCV_CMAC         (0x01) ///< KCV algorithm: CMAC based KCV

// TR-31 HMAC optional block format (see TR-31:2018, A.5.9)
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

/// TR-31 key object
struct tr31_key_t {
	unsigned int usage; ///< TR-31 key usage
	unsigned int algorithm; ///< TR-31 key algorithm
	unsigned int mode_of_use; ///< TR-31 key mode of use

	// key version field information
	enum tr31_key_version_t key_version; ///< TR-31 key version field interpretation
	union {
		unsigned int key_version_value; ///< TR-31 key version number
		unsigned int key_component_number; ///< TR-31 key component number
	};

	unsigned int exportability; ///< TR-31 key exportability

	size_t length; ///< Key data length in bytes
	void* data; ///< Key data
	uint8_t kcv[3]; ///< Key Check Value (KCV)
};

/// TR-31 optional block context object
struct tr31_opt_ctx_t {
	unsigned int id; ///< TR-31 optional block identifier
	size_t data_length; ///< TR-31 optional block data length in bytes
	void* data; ///< TR-31 optional block data
};

/**
 * @brief TR-31 context object
 * @note Resources should be released using #tr31_release
 */
struct tr31_ctx_t {
	enum tr31_version_t version; ///< TR-31 key block format version
	size_t length; ///< TR-31 key block length in bytes

	struct tr31_key_t key; ///< TR-31 key object

	size_t opt_blocks_count; ///< TR-31 number of optional blocks
	struct tr31_opt_ctx_t* opt_blocks; ///< TR-31 optional block context objects

	size_t header_length; ///< TR-31 header data length in bytes, including optional blocks
	void* header; ///< TR-31 header data, including optional blocks

	size_t payload_length; ///< TR-31 payload data length in bytes
	void* payload; ///< TR-31 payload data

	size_t authenticator_length; ///< TR-31 authenticator data length in bytes
	void* authenticator; ///< TR-31 authenticator data
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
	TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA, ///< Invalid optional block data
	TR31_ERROR_INVALID_PAYLOAD_FIELD, ///< Invalid payload data field
	TR31_ERROR_INVALID_AUTHENTICATOR_FIELD, ///< Invalid authenticator data field
	TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM, ///< Unsupported key block protection key algorithm
	TR31_ERROR_UNSUPPORTED_KBPK_LENGTH, ///< Unsupported key block protection key length
	TR31_ERROR_INVALID_KEY_LENGTH, ///< Invalid key length; possibly incorrect key block protection key
	TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED, ///< Key block verification failed; possibly incorrect key block protection key
};

/**
 * Retrieve TR-31 library version string
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_lib_version_string(void);

/**
 * Import TR-31 key block. This function will also decrypt the key data if possible.
 * @param key_block TR-31 key block. Null terminated. At least the header must be ASCII encoded.
 * @param kbpk TR-31 key block protection key. NULL if not available or decryption is not required.
 * @param ctx TR-31 context object output
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. @see #tr31_error_t
 */
int tr31_import(
	const char* key_block,
	const struct tr31_key_t* kbpk,
	struct tr31_ctx_t* ctx
);

/**
 * Export TR-31 key block. This function will create and encrypt the key block.
 * @param ctx TR-31 context object input.
 * @param kbpk TR-31 key block protection key.
 * @param key_block TR-31 key block output. Null terminated. At least the header will be ASCII encoded.
 * @param key_block_len TR-31 key block output buffer length.
 * @return Zero for success. Less than zero for internal error. Greater than zero for data error. @see #tr31_error_t
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

/**
 * Create formatted string associated with optional block data
 * @param opt_block Optional block
 * @return Pointer to null-terminated string. Do not free. NULL if unknown or not applicable.
 */
const char* tr31_get_opt_block_data_string(const struct tr31_opt_ctx_t* opt_block);

__END_DECLS

#endif
