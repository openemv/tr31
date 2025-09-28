/**
 * @file tr31_strings.c
 * @brief TR-31 string helper functions
 *
 * Copyright 2023, 2025 Leon Lynch
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

#include "tr31_strings.h"
#include "tr31.h"
#include "tr31_config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h> // for htons
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#ifdef TR31_ENABLE_DATETIME_CONVERSION
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifndef HAVE_STRPTIME
#include <stdio.h> // For sscanf()
#endif
#endif // TR31_ENABLE_DATETIME_CONVERSION

// Helper functions
static int tr31_validate_format_an(const char* buf, size_t buf_len);
static const char* tr31_opt_block_akl_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_BI_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_CT_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_hmac_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_kcv_get_string(const struct tr31_opt_ctx_t* opt_block);
static int tr31_opt_block_iso8601_get_string(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len);
static const char* tr31_opt_block_wrapping_pedigree_get_string(const struct tr31_opt_ctx_t* opt_block);
static bool tr31_opt_block_is_ibm(const struct tr31_opt_ctx_t* opt_block);
static bool tr31_opt_block_ibm_found(const struct tr31_ctx_t* ctx);
static const char* tr31_opt_block_ibm_get_string(const struct tr31_opt_ctx_t* opt_block);

static int tr31_validate_format_an(const char* buf, size_t buf_len)
{
	while (buf_len--) {
		// Alphanumeric characters are in the ranges 0x30 - 0x39, 0x41 - 0x5A
		// and 0x61 - 0x7A
		// See ANSI X9.143:2021, 4
		if ((*buf < 0x30 || *buf > 0x39) &&
			(*buf < 0x41 || *buf > 0x5A) &&
			(*buf < 0x61 || *buf > 0x7A)
		) {
			return -1;
		}

		++buf;
	}

	return 0;
}

const char* tr31_key_usage_get_ascii(unsigned int usage, char* ascii, size_t ascii_len)
{
	union {
		uint16_t value;
		char bytes[2];
	} usage_ascii;

	usage_ascii.value = htons(usage);

	if (ascii_len < 3) {
		return NULL;
	}
	for (size_t i = 0; i < sizeof(usage_ascii.bytes); ++i) {
		if (tr31_validate_format_an(usage_ascii.bytes, sizeof(usage_ascii.bytes)) == 0) {
			ascii[i] = usage_ascii.bytes[i];
		} else {
			ascii[i] = '?';
		}
	}
	ascii[2] = 0;

	return ascii;
}

const char* tr31_key_usage_get_desc(const struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.1, table 2
	switch (ctx->key.usage) {
		case TR31_KEY_USAGE_BDK:                return "Base Derivation Key (BDK)";
		case TR31_KEY_USAGE_DUKPT_IK:           return "Initial DUKPT Key (IK/IPEK)";
		case TR31_KEY_USAGE_BKV:                return "Base Key Variant Key";
		case TR31_KEY_USAGE_KDK:                return "Key Derivation Key";
		case TR31_KEY_USAGE_CVK:                return "Card Verification Key (CVK)";
		case TR31_KEY_USAGE_DATA:               return "Symmetric Key for Data Encryption";
		case TR31_KEY_USAGE_ASYMMETRIC_DATA:    return "Asymmetric Key for Data Encryption";
		case TR31_KEY_USAGE_DATA_DEC_TABLE:     return "Data Encryption Key for Decimalization Table";
		case TR31_KEY_USAGE_DATA_SENSITIVE:     return "Data Encryption Key for Sensitive Data";
		case TR31_KEY_USAGE_EMV_MKAC:           return "EMV/Chip Issuer Master Key: Application Cryptograms (MKAC)";
		case TR31_KEY_USAGE_EMV_MKSMC:          return "EMV/Chip Issuer Master Key: Secure Messaging for Confidentiality (MKSMC)";
		case TR31_KEY_USAGE_EMV_MKSMI:          return "EMV/Chip Issuer Master Key: Secure Messaging for Integrity (MKSMI)";
		case TR31_KEY_USAGE_EMV_MKDAC:          return "EMV/Chip Issuer Master Key: Data Authentication Code (MKDAC)";
		case TR31_KEY_USAGE_EMV_MKDN:           return "EMV/Chip Issuer Master Key: Dynamic Numbers (MKDN)";
		case TR31_KEY_USAGE_EMV_CP:             return "EMV/Chip Issuer Master Key: Card Personalization (CP)";
		case TR31_KEY_USAGE_EMV_OTHER:          return "EMV/Chip Issuer Master Key: Other";
		case TR31_KEY_USAGE_EMV_AKP_PIN:        return "EMV/Chip Asymmetric Key Pair for PIN Encryption";
		case TR31_KEY_USAGE_IV:                 return "Initialization Vector (IV)";
		case TR31_KEY_USAGE_KEK:                return "Key Encryption or Wrapping Key (KEK)";
		case TR31_KEY_USAGE_TR31_KBPK:          return "ANSI X9.143 / TR-31 Key Block Protection Key (KBPK)";
		case TR31_KEY_USAGE_TR34_APK_KRD:       return "ANSI X9.139 / TR-34 Asymmetric Key Pair for Key Receiving Device";
		case TR31_KEY_USAGE_APK:                return "Asymmetric Key Pair for Key Wrapping or Key Agreement";
		case TR31_KEY_USAGE_ISO20038_KBPK:      return "ISO 20038 Key Block Protection Key (KBPK)";
		case TR31_KEY_USAGE_ISO16609_MAC_1:     return "ISO 16609 MAC algorithm 1 (using TDES)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_1:    return "ISO 9797-1 MAC Algorithm 1 (CBC-MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_2:    return "ISO 9797-1 MAC Algorithm 2";
		case TR31_KEY_USAGE_ISO9797_1_MAC_3:    return "ISO 9797-1 MAC Algorithm 3 (Retail MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_4:    return "ISO 9797-1 MAC Algorithm 4";
		case TR31_KEY_USAGE_ISO9797_1_MAC_5:    return "ISO 9797-1:1999 MAC Algorithm 5 (legacy)";
		case TR31_KEY_USAGE_ISO9797_1_CMAC:     return "ISO 9797-1:2011 MAC Algorithm 5 (CMAC)";
		case TR31_KEY_USAGE_HMAC:               return "HMAC Key";
		case TR31_KEY_USAGE_ISO9797_1_MAC_6:    return "ISO 9797-1 MAC Algorithm 6";
		case TR31_KEY_USAGE_PEK:                return "PIN Encryption Key";
		case TR31_KEY_USAGE_PGK:                return "PIN Generation Key";
		case TR31_KEY_USAGE_AKP_SIG:            return "Asymmetric Key Pair for Digital Signature";
		case TR31_KEY_USAGE_AKP_CA:             return "Asymmetric Key Pair for CA use";
		case TR31_KEY_USAGE_AKP_OTHER:          return "Asymmetric Key Pair for non-X9.24 use";
		case TR31_KEY_USAGE_PVK:                return "PIN Verification Key (Other)";
		case TR31_KEY_USAGE_PVK_IBM3624:        return "PIN Verification Key (IBM 3624)";
		case TR31_KEY_USAGE_PVK_VISA_PVV:       return "PIN Verification Key (VISA PVV)";
		case TR31_KEY_USAGE_PVK_X9_132_ALG_1:   return "PIN Verification Key (ANSI X9.132 algorithm 1)";
		case TR31_KEY_USAGE_PVK_X9_132_ALG_2:   return "PIN Verification Key (ANSI X9.132 algorithm 2)";
		case TR31_KEY_USAGE_PVK_X9_132_ALG_3:   return "PIN Verification Key (ANSI X9.132 algorithm 3)";
	}

	// See https://www.ibm.com/docs/en/zos/3.1.0?topic=ktf-x9143-tr-31-key-block-header-optional-block-data
	if (ctx->key.usage == TR31_KEY_USAGE_IBM &&
		tr31_opt_block_ibm_found(ctx)
	) {
		return "IBM";
	}

	return "Unknown key usage value";
}

const char* tr31_key_algorithm_get_desc(const struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.2, table 3
	// See ISO 20038:2017, Annex A.2.4, table A.4
	switch (ctx->key.algorithm) {
		case TR31_KEY_ALGORITHM_AES:        return "AES";
		case TR31_KEY_ALGORITHM_DES:        return "DES";
		case TR31_KEY_ALGORITHM_EC:         return "Elliptic Curve";
		case TR31_KEY_ALGORITHM_HMAC: {
			if (tr31_opt_block_find((struct tr31_ctx_t*)ctx, TR31_OPT_BLOCK_HM)) {
				// ANSI X9.143 requires optional block HM for key algorithm HMAC
				return "HMAC";
			} else {
				// ISO 20038 associates the HMAC digest to the key algorithm
				return "HMAC-SHA-1 (ISO 20038)";
			}
		}
		case TR31_KEY_ALGORITHM_HMAC_SHA2:  return "HMAC-SHA-2 (ISO 20038)";
		case TR31_KEY_ALGORITHM_HMAC_SHA3:  return "HMAC-SHA-3 (ISO 20038)";
		case TR31_KEY_ALGORITHM_RSA:        return "RSA";
		case TR31_KEY_ALGORITHM_DSA:        return "DSA";
		case TR31_KEY_ALGORITHM_TDES:       return "TDES";
	}

	return "Unknown key algorithm value";
}

const char* tr31_key_mode_of_use_get_desc(const struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.3, table 4
	switch (ctx->key.mode_of_use) {
		case TR31_KEY_MODE_OF_USE_ENC_DEC:      return "Encrypt/Wrap and Decrypt/Unwrap";
		case TR31_KEY_MODE_OF_USE_MAC:          return "MAC Generate and Verify";
		case TR31_KEY_MODE_OF_USE_DEC:          return "Decrypt/Unwrap Only";
		case TR31_KEY_MODE_OF_USE_ENC:          return "Encrypt/Wrap Only";
		case TR31_KEY_MODE_OF_USE_MAC_GEN:      return "MAC Generate Only";
		case TR31_KEY_MODE_OF_USE_ANY:          return "No special restrictions";
		case TR31_KEY_MODE_OF_USE_SIG:          return "Signature Only";
		case TR31_KEY_MODE_OF_USE_MAC_VERIFY:   return "MAC Verify Only";
		case TR31_KEY_MODE_OF_USE_DERIVE:       return "Key Derivation";
		case TR31_KEY_MODE_OF_USE_VARIANT:      return "Create Key Variants";
	}

	// See https://www.ibm.com/docs/en/zos/3.1.0?topic=ktf-x9143-tr-31-key-block-header-optional-block-data
	if (ctx->key.mode_of_use == TR31_KEY_MODE_OF_USE_IBM &&
		tr31_opt_block_ibm_found(ctx)
	) {
		return "IBM";
	}

	return "Unknown key mode of use value";
}

const char* tr31_key_exportability_get_desc(const struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.5, table 6
	switch (ctx->key.exportability) {
		case TR31_KEY_EXPORT_TRUSTED:           return "Exportable in a trusted key block only";
		case TR31_KEY_EXPORT_NONE:              return "Not exportable";
		case TR31_KEY_EXPORT_SENSITIVE:         return "Sensitive";
	}

	return "Unknown key exportability value";
}

const char* tr31_key_context_get_desc(const struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.2, table 1
	switch (ctx->key.key_context) {
		case TR31_KEY_CONTEXT_NONE:             return "Determined by wrapping key";
		case TR31_KEY_CONTEXT_STORAGE:          return "Storage context only";
		case TR31_KEY_CONTEXT_EXCHANGE:         return "Key exchange context only";
	}

	return "Unknown key context value";
}

const char* tr31_opt_block_id_get_ascii(unsigned int opt_block_id, char* ascii, size_t ascii_len)
{
	union {
		uint16_t value;
		char bytes[2];
	} opt_block_id_ascii;

	opt_block_id_ascii.value = htons(opt_block_id);

	if (ascii_len < 3) {
		return NULL;
	}
	for (size_t i = 0; i < sizeof(opt_block_id_ascii.bytes); ++i) {
		if (tr31_validate_format_an(opt_block_id_ascii.bytes, sizeof(opt_block_id_ascii.bytes)) == 0) {
			ascii[i] = opt_block_id_ascii.bytes[i];
		} else {
			ascii[i] = '?';
		}
	}
	ascii[2] = 0;

	return ascii;
}

const char* tr31_opt_block_id_get_desc(const struct tr31_opt_ctx_t* opt_block)
{
	if (!opt_block) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.6, table 7
	switch (opt_block->id) {
		case TR31_OPT_BLOCK_AL:         return "Asymmetric Key Life (AKL)";
		case TR31_OPT_BLOCK_BI:         return "Base Derivation Key (BDK) Identifier";
		case TR31_OPT_BLOCK_CT:         return "Public Key Certificate";
		case TR31_OPT_BLOCK_DA:         return "Derivation(s) Allowed for Derivation Keys";
		case TR31_OPT_BLOCK_FL:         return "Flags";
		case TR31_OPT_BLOCK_HM:         return "Hash algorithm for HMAC";
		case TR31_OPT_BLOCK_IK:         return "Initial Key Identifier (IKID)";
		case TR31_OPT_BLOCK_KC:         return "Key Check Value (KCV) of wrapped key";
		case TR31_OPT_BLOCK_KP:         return "Key Check Value (KCV) of KBPK";
		case TR31_OPT_BLOCK_KS:         return "Initial Key Serial Number (KSN)";
		case TR31_OPT_BLOCK_KV:         return "Key Block Values";
		case TR31_OPT_BLOCK_LB:         return "Label";
		case TR31_OPT_BLOCK_PB:         return "Padding Block";
		case TR31_OPT_BLOCK_PK:         return "Protection Key Check Value (KCV) of export KBPK";
		case TR31_OPT_BLOCK_TC:         return "Time of Creation";
		case TR31_OPT_BLOCK_TS:         return "Time Stamp";
		case TR31_OPT_BLOCK_WP:         return "Wrapping Pedigree";
		default: {
			if (tr31_opt_block_is_ibm(opt_block)) {
				return "IBM";
			}
			break;
		}
	}

	return "Unknown";
}

int tr31_opt_block_data_get_desc(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len)
{
	const char* simple_str = NULL;

	if (!opt_block || !str || !str_len) {
		return -1;
	}
	str[0] = 0; // Default to empty string

	switch (opt_block->id) {
		case TR31_OPT_BLOCK_AL:
			simple_str = tr31_opt_block_akl_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_BI:
			simple_str = tr31_opt_block_BI_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_CT:
			simple_str = tr31_opt_block_CT_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_HM:
			simple_str = tr31_opt_block_hmac_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_KC:
		case TR31_OPT_BLOCK_KP:
		case TR31_OPT_BLOCK_PK:
			simple_str = tr31_opt_block_kcv_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_TC:
		case TR31_OPT_BLOCK_TS:
			return tr31_opt_block_iso8601_get_string(opt_block, str, str_len);

		case TR31_OPT_BLOCK_WP:
			simple_str =  tr31_opt_block_wrapping_pedigree_get_string(opt_block);
			break;

		default:
			simple_str = tr31_opt_block_ibm_get_string(opt_block);
			break;
	}

	if (simple_str) {
		strncpy(str, simple_str, str_len - 1);
		str[str_len - 1] = 0;
	}

	return 0;
}

static const char* tr31_opt_block_akl_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	int r;
	struct tr31_opt_blk_akl_data_t akl_data;

	// Use canary value to know whether AKL version was decoded
	akl_data.version = 0xFF;
	r = tr31_opt_block_decode_AL(opt_block, &akl_data);
	if (r < 0) {
		return NULL;
	}
	if (r > 0) {
		// If at least the AKL version is available, report it as unknown
		if (akl_data.version != 0xFF &&
			akl_data.version != TR31_OPT_BLOCK_AL_VERSION_1
		) {
			return "Unknown AKL version";
		} else {
			// Invalid
			return NULL;
		}
	}

	// See ANSI X9.143:2021, 6.3.6.1, table 8
	if (akl_data.version != TR31_OPT_BLOCK_AL_VERSION_1) {
		return "Unknown AKL version";
	}
	switch (akl_data.v1.akl) {
		case TR31_OPT_BLOCK_AL_AKL_EPHEMERAL: return "Ephemeral";
		case TR31_OPT_BLOCK_AL_AKL_STATIC: return "Static";
	}

	return "Unknown";
}

static const char* tr31_opt_block_BI_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	int r;
	struct tr31_opt_blk_bdkid_data_t bdkid_data;

	r = tr31_opt_block_decode_BI(opt_block, &bdkid_data);
	if (r) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.6.2, table 9
	switch (bdkid_data.key_type) {
		case TR31_OPT_BLOCK_BI_TDES_DUKPT: return "Key Set ID";
		case TR31_OPT_BLOCK_BI_AES_DUKPT: return "Base Derivation Key ID";
	}

	return "Unknown";
}

static const char* tr31_opt_block_CT_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	const char* data;

	if (!opt_block ||
		opt_block->id != TR31_OPT_BLOCK_CT ||
		opt_block->data_length < 2
	) {
		return NULL;
	}
	data = opt_block->data;

	// See ANSI X9.143:2021, 6.3.6.3, table 10/11
	if (data[0] == '0' && data[1] == '0') {
		return "X.509 certificate";
	} else if (data[0] == '0' && data[1] == '1') {
		return "EMV certificate";
	} else if (data[0] == '0' && data[1] == '2') {
		return "Certificate chain";
	} else {
		// Unknown certificate format
		return "Unknown";
	}
}

static const char* tr31_opt_block_hmac_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	int r;
	uint8_t hash_algorithm;

	// Use canary value to know whether hash algorithm was decoded
	hash_algorithm = 0xFF;
	r = tr31_opt_block_decode_HM(opt_block, &hash_algorithm);
	if (r < 0) {
		return NULL;
	}
	if (r > 0) {
		if (hash_algorithm != 0xFF) {
			return "Unknown";
		} else {
			return NULL;
		}
	}

	// See ANSI X9.143:2021, 6.3.6.5, table 13
	switch (hash_algorithm) {
		case TR31_OPT_BLOCK_HM_SHA1:            return "SHA-1";
		case TR31_OPT_BLOCK_HM_SHA224:          return "SHA-224";
		case TR31_OPT_BLOCK_HM_SHA256:          return "SHA-256";
		case TR31_OPT_BLOCK_HM_SHA384:          return "SHA-384";
		case TR31_OPT_BLOCK_HM_SHA512:          return "SHA-512";
		case TR31_OPT_BLOCK_HM_SHA512_224:      return "SHA-512/224";
		case TR31_OPT_BLOCK_HM_SHA512_256:      return "SHA-512/256";
		case TR31_OPT_BLOCK_HM_SHA3_224:        return "SHA3-224";
		case TR31_OPT_BLOCK_HM_SHA3_256:        return "SHA3-256";
		case TR31_OPT_BLOCK_HM_SHA3_384:        return "SHA3-384";
		case TR31_OPT_BLOCK_HM_SHA3_512:        return "SHA3-512";
		case TR31_OPT_BLOCK_HM_SHAKE128:        return "SHAKE128";
		case TR31_OPT_BLOCK_HM_SHAKE256:        return "SHAKE256";
	}

	return "Unknown";
}

static const char* tr31_opt_block_kcv_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	int r;
	struct tr31_opt_blk_kcv_data_t kcv_data;

	r = tr31_opt_block_decode_kcv(opt_block, &kcv_data);
	if (r) {
		return NULL;
	}

	// See ANSI X9.143:2021, 6.3.6.7, table 15
	// See ANSI X9.143:2021, 6.3.6.12, table 20
	switch (kcv_data.kcv_algorithm) {
		case TR31_OPT_BLOCK_KCV_LEGACY: return "Legacy KCV algorithm";
		case TR31_OPT_BLOCK_KCV_CMAC: return "CMAC based KCV";
	}

	return "Unknown";
}

static int tr31_opt_block_iso8601_get_string(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len)
{
#ifdef TR31_ENABLE_DATETIME_CONVERSION
	char* iso8601_str;
#ifdef HAVE_STRPTIME
	char* ptr;
#else
	int r;
#endif
	struct tm ztm; // Time structure in UTC
	time_t lt; // Calendar/Unix/POSIX time in local time
	struct tm* ltm; // Time structure in local time
	size_t ret;

	if (!opt_block->data_length) {
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}

	// Copy optional block data to NULL-terminated string
	iso8601_str = malloc(opt_block->data_length + 1);
	if (!iso8601_str) {
		return -1;
	}
	memcpy(iso8601_str, opt_block->data, opt_block->data_length);
	iso8601_str[opt_block->data_length] = 0;

	// Validate ISO 8601 format based on string length
	// NOTE: struct tm cannot hold sub-second values and they will be ignored
	// during parsing
	// See ANSI X9.143:2021, 6.3.6.13, table 21
	// See ANSI X9.143:2021, 6.3.6.14, table 22
	memset(&ztm, 0, sizeof(ztm));
#ifdef HAVE_STRPTIME
	switch (opt_block->data_length) {
		case 0x13 - 4: // YYYYMMDDhhmmssZ
			ptr = strptime(iso8601_str, "%Y%m%d%H%M%SZ", &ztm);
			break;

		case 0x15 - 4: // YYYYMMDDhhmmssssZ
			ptr = strptime(iso8601_str, "%Y%m%d%H%M%S", &ztm);
			if (ptr - iso8601_str == 0x15 - 4 - 3 && *(ptr + 2) == 'Z') {
				ptr += 3;
			}
			break;

		case 0x18 - 4: // YYYY-MM-DDThh:mm:ssZ
			ptr = strptime(iso8601_str, "%Y-%m-%dT%H:%M:%SZ", &ztm);
			break;

		case 0x1B - 4: // YYYY-MM-DDThh:mm:ss.ssZ
			ptr = strptime(iso8601_str, "%Y-%m-%dT%H:%M:%S", &ztm);
			if (ptr - iso8601_str == 0x1B - 4 - 4 && *ptr == '.' && *(ptr + 3) == 'Z') {
				ptr += 4;
			}
			break;

		default:
			ptr = NULL; // Don't return before free()'ing iso8601_str
	}
	// NOTE: strptime() returns NULL if it fails to match the format string or
	// returns a pointer to the first character after the matched format
	// string. Therefore iso8601_str may only be free()'d after evaluating *ptr
	if (!ptr || *ptr) {
		free(iso8601_str);
		iso8601_str = NULL;
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}
#else
	switch (opt_block->data_length) {
		case 0x13 - 4: // YYYYMMDDhhmmssZ
			r = sscanf(iso8601_str, "%4d%2d%2d%2d%2d%2dZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x15 - 4: // YYYYMMDDhhmmssssZ
			r = sscanf(iso8601_str, "%4d%2d%2d%2d%2d%2d%*c%*cZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x18 - 4: // YYYY-MM-DDThh:mm:ssZ
			r = sscanf(iso8601_str, "%4d-%2d-%2dT%2d:%2d:%2dZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x1B - 4: // YYYY-MM-DDThh:mm:ss.ssZ
			r = sscanf(iso8601_str, "%4d-%2d-%2dT%2d:%2d:%2d*c%*cZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		default:
			r = 0; // Don't return before free()'ing iso8601_str
	}
	// Fix year and month in time structure
	ztm.tm_year -= 1900;
	ztm.tm_min -= 1;
	// NOTE: sscanf() returns number of matched input items
	if (r != 6) {
		free(iso8601_str);
		iso8601_str = NULL;
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}
#endif
	free(iso8601_str);
	iso8601_str = NULL;

	// Convert UTC time to local time
#ifdef HAVE_TIMEGM
	lt = timegm(&ztm);
#elif defined(HAVE_MKGMTIME)
	lt = _mkgmtime(&ztm);
#else
#error "No platform function to convert UTC time to local time"
#endif
	ltm = localtime(&lt);
	ztm = *ltm;

	// Set time locale according to environment variable
	setlocale(LC_TIME, "");

	// Provide time according to locale
	ret = strftime(str, str_len, "%c", &ztm);
	if (!ret) {
		// Unexpected failure
		return -2;
	}

	return 0;
#else
	str[0] = 0;
	return 0;
#endif
}

static const char* tr31_opt_block_wrapping_pedigree_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	int r;
	struct tr31_opt_blk_wp_data_t wp_data;

	// Use canary value to know whether WP version was decoded
	wp_data.version = 0xFF;
	r = tr31_opt_block_decode_WP(opt_block, &wp_data);
	if (r < 0) {
		return NULL;
	}
	if (r > 0) {
		// If at least the WP version is available, report it as unknown
		if (wp_data.version != 0xFF &&
			wp_data.version != TR31_OPT_BLOCK_WP_VERSION_0
		) {
			return "Unknown wrapping pedigree version";
		} else {
			// Invalid
			return NULL;
		}
	}

	if (wp_data.version != TR31_OPT_BLOCK_WP_VERSION_0) {
		return "Unknown wrapping pedigree version";
	}

	// See ANSI X9.143:2021, 6.3.6.15, table 23
	switch (wp_data.v0.wrapping_pedigree) {
		case TR31_OPT_BLOCK_WP_EQ_GT: return "Equal or greater effective strength";
		case TR31_OPT_BLOCK_WP_LT: return "Lesser effective strength";
		case TR31_OPT_BLOCK_WP_ASYMMETRIC: return "Asymmetric key at risk of quantum computing";
		case TR31_OPT_BLOCK_WP_ASYMMETRIC_LT: return "Asymmetric key at risk of quantum computing and symmetric key of lesser effective strength";
	}

	return "Unknown";
}

static bool tr31_opt_block_is_ibm(const struct tr31_opt_ctx_t* opt_block)
{
	if (opt_block->id != TR31_OPT_BLOCK_10_IBM) {
		return false;
	}

	// See https://www.ibm.com/docs/en/zos/3.1.0?topic=ktf-x9143-tr-31-key-block-header-optional-block-data
	if (opt_block->data_length < strlen(TR31_OPT_BLOCK_10_IBM_MAGIC)) {
		return false;
	}
	if (memcmp(opt_block->data, TR31_OPT_BLOCK_10_IBM_MAGIC, strlen(TR31_OPT_BLOCK_10_IBM_MAGIC)) != 0) {
		return false;
	}

	if ((opt_block->data_length == 0x1C - 4 || opt_block->data_length != 0x2C - 4) &&
		memcmp(opt_block->data + 4, "01", 2) == 0
	) {
		// IBM Common Cryptographic Architecture (CCA) Control Vector (CV)
		return true;
	}

	if (opt_block->data_length == 0x24 - 4 &&
		memcmp(opt_block->data + 4, "02", 2) == 0
	) {
		// IBM Internal X9-SWKB controls
		return true;
	}

	return false;
}

static bool tr31_opt_block_ibm_found(const struct tr31_ctx_t* ctx)
{
	struct tr31_opt_ctx_t* opt_block;

	opt_block = tr31_opt_block_find((struct tr31_ctx_t*)ctx, TR31_OPT_BLOCK_10_IBM);
	if (!opt_block) {
		return false;
	}

	return tr31_opt_block_is_ibm(opt_block);
}

static const char* tr31_opt_block_ibm_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	if (!tr31_opt_block_is_ibm(opt_block)) {
		return NULL;
	}

	// See https://www.ibm.com/docs/en/zos/3.1.0?topic=ktf-x9143-tr-31-key-block-header-optional-block-data
	if (memcmp(opt_block->data + 4, "01", 2) == 0) {
		return "Common Cryptographic Architecture (CCA) Control Vector (CV)";
	}
	if (memcmp(opt_block->data + 4, "02", 2) == 0) {
		return "Internal X9-SWKB controls";
	}

	return 0;
}
