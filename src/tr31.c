/**
 * @file tr31.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31.h"
#include "tr31_crypto.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <arpa/inet.h> // for ntohs and friends

struct tr31_opt_header_t {
	uint16_t id;
	char length[2];
	char data[];
} __attribute__((packed));

struct tr31_header_t {
	uint8_t version_id;
	char length[4];
	uint16_t key_usage;
	uint8_t algorithm;
	uint8_t mode_of_use;
	char key_version[2];
	uint8_t exportability;
	char opt_blocks_count[2];
	char reserved[2];
} __attribute__((packed));

struct tr31_payload_t {
	uint16_t length;
	uint8_t data[];
} __attribute__((packed));

#define TR31_MIN_PAYLOAD_LENGTH (DES_BLOCK_SIZE)
#define TR31_MIN_KEY_BLOCK_LENGTH (sizeof(struct tr31_header_t) + TR31_MIN_PAYLOAD_LENGTH + 8) // Minimum TR-31 key block length: header + minimum payload + authenticator

static int dec_to_int(const char* str, size_t length)
{
	int value;

	value = 0;
	for (size_t i = 0; i < length; ++i) {
		if (!isdigit(str[i])) {
			return -1;
		}

		value *= 10; // shift decimal value
		value += str[i] - 0x30; // convert ASCII decimal to numeric value
	}

	return value;
}

static int hex_to_int(const char* str, size_t length)
{
	int value;

	value = 0;
	for (size_t i = 0; i < length; ++i) {
		if (!isxdigit(str[i])) {
			return -1;
		}

		value <<= 4; // shift hex value
		// convert ASCII hex to numeric value
		if (str[i] >= '0' && str[i] <= '9') {
			value += str[i] - 0x30;
		}
		if (str[i] >= 'A' && str[i] <= 'F') {
			value += str[i] - ('A' - 10);
		}
		if (str[i] >= 'a' && str[i] <= 'f') {
			value += str[i] - ('a' - 10);
		}
	}

	return value;
}

static int hex_to_bin(const char* hex, void* bin, size_t bin_len)
{
	size_t hex_len = bin_len * 2;

	for (size_t i = 0; i < hex_len; ++i) {
		if (!isxdigit(hex[i])) {
			return -1;
		}
	}

	while (*hex && bin_len--) {
		uint8_t* ptr = bin;

		char str[3];
		strncpy(str, hex, 2);
		str[2] = 0;

		*ptr = strtoul(str, NULL, 16);

		hex += 2;
		++bin;
	}

	return 0;
}

int tr31_import(
	const char* key_block,
	const struct tr31_key_t* kbpk,
	struct tr31_ctx_t* ctx
)
{
	int r;
	size_t key_block_len;
	const struct tr31_header_t* header;
	const void* ptr;

	if (!key_block || !ctx) {
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));

	key_block_len = strlen(key_block);
	header = (const struct tr31_header_t*)key_block;

	// validate minimum length
	if (key_block_len < TR31_MIN_KEY_BLOCK_LENGTH) {
		return TR31_ERROR_INVALID_LENGTH;
	}

	// decode key block format
	ctx->version = header->version_id;
	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_B:
		case TR31_VERSION_C:
			break;

		case TR31_VERSION_D:
		default:
			return TR31_ERROR_UNSUPPORTED_VERSION;
	}

	// decode key block length field
	ctx->length = dec_to_int(header->length, sizeof(header->length));
	if (ctx->length != key_block_len) {
		return TR31_ERROR_INVALID_LENGTH_FIELD;
	}

	// decode key usage field
	ctx->key.usage = ntohs(header->key_usage);
	switch (ctx->key.usage) {
		case TR31_KEY_USAGE_BDK:
		case TR31_KEY_USAGE_DUKPT_IPEK:
		case TR31_KEY_USAGE_CVK:
		case TR31_KEY_USAGE_DATA:
		case TR31_KEY_USAGE_EMV_MKAC:
		case TR31_KEY_USAGE_EMV_MKSMC:
		case TR31_KEY_USAGE_EMV_MKSMI:
		case TR31_KEY_USAGE_EMV_MKDAC:
		case TR31_KEY_USAGE_EMV_MKDN:
		case TR31_KEY_USAGE_EMV_CP:
		case TR31_KEY_USAGE_EMV_OTHER:
		case TR31_KEY_USAGE_IV:
		case TR31_KEY_USAGE_KEY:
		case TR31_KEY_USAGE_ISO16609_MAC_1:
		case TR31_KEY_USAGE_ISO9797_1_MAC_1:
		case TR31_KEY_USAGE_ISO9797_1_MAC_2:
		case TR31_KEY_USAGE_ISO9797_1_MAC_3:
		case TR31_KEY_USAGE_ISO9797_1_MAC_4:
		case TR31_KEY_USAGE_ISO9797_1_MAC_5:
		case TR31_KEY_USAGE_ISO9797_1_MAC_6:
		case TR31_KEY_USAGE_PIN:
		case TR31_KEY_USAGE_PV:
		case TR31_KEY_USAGE_PV_IBM3624:
		case TR31_KEY_USAGE_PV_VISA:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_KEY_USAGE;
	}

	// decode algorithm field
	ctx->key.algorithm = header->algorithm;
	switch (ctx->key.algorithm) {
		case TR31_KEY_ALGORITHM_AES:
		case TR31_KEY_ALGORITHM_DES:
		case TR31_KEY_ALGORITHM_EC:
		case TR31_KEY_ALGORITHM_HMAC:
		case TR31_KEY_ALGORITHM_RSA:
		case TR31_KEY_ALGORITHM_DSA:
		case TR31_KEY_ALGORITHM_TDES:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_ALGORITHM;
	}
	
	// decode mode of use field
	ctx->key.mode_of_use = header->mode_of_use;
	switch (ctx->key.mode_of_use) {
		case TR31_KEY_MODE_OF_USE_ENC_DEC:
		case TR31_KEY_MODE_OF_USE_MAC:
		case TR31_KEY_MODE_OF_USE_DEC:
		case TR31_KEY_MODE_OF_USE_ENC:
		case TR31_KEY_MODE_OF_USE_MAC_GEN:
		case TR31_KEY_MODE_OF_USE_ANY:
		case TR31_KEY_MODE_OF_USE_SIG:
		case TR31_KEY_MODE_OF_USE_MAC_VERIFY:
		case TR31_KEY_MODE_OF_USE_DERIVE:
		case TR31_KEY_MODE_OF_USE_VARIANT:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_MODE_OF_USE;
	}

	// decode key version number field
	if (header->key_version[0] == '0' && header->key_version[1] == '0') {
		ctx->key.key_version = TR31_KEY_VERSION_IS_UNUSED;
	} else if (header->key_version[0] == 'c') {
		ctx->key.key_version = TR31_KEY_VERSION_IS_COMPONENT;
		ctx->key.key_component_number = dec_to_int(&header->key_version[1], sizeof(header->key_version[1]));
	} else {
		int key_version_value = dec_to_int(header->key_version, sizeof(header->key_version));
		if (key_version_value < 0) {
			return TR31_ERROR_INVALID_KEY_VERSION_FIELD;
		}

		ctx->key.key_version = TR31_KEY_VERSION_IS_VALID;
		ctx->key.key_version_value = key_version_value;
	}

	// decode exportability field
	ctx->key.exportability = header->exportability;
	switch (ctx->key.exportability) {
		case TR31_KEY_EXPORT_TRUSTED:
		case TR31_KEY_EXPORT_NONE:
		case TR31_KEY_EXPORT_SENSITIVE:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_EXPORTABILITY;
	}

	// decode number of optional header blocks field
	int opt_blocks_count = dec_to_int(header->opt_blocks_count, sizeof(header->opt_blocks_count));
	if (opt_blocks_count < 0) {
		return TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD;
	}
	ctx->opt_blocks_count = opt_blocks_count;

	// decode optional header blocks
	ptr = header + 1; // optional header blocks, if any, are after the header
	if (ctx->opt_blocks_count) {
		ctx->opt_blocks = calloc(ctx->opt_blocks_count, sizeof(ctx->opt_blocks[0]));
	}
	for (int i = 0; i < opt_blocks_count; ++i) {
		// ensure that current pointer is valid for minimal optional header block
		if (ptr + sizeof(struct tr31_opt_header_t) - (void*)header > key_block_len) {
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		const struct tr31_opt_header_t* opt_header = ptr;

		// ensure that optional header block length is valid
		int opt_hdr_len = hex_to_int(opt_header->length, sizeof(opt_header->length));
		if (opt_hdr_len < sizeof(struct tr31_opt_header_t)) {
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		if (ptr + opt_hdr_len - (void*)header > key_block_len) {
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}

		// copy optional header block fields
		ctx->opt_blocks[i].id = ntohs(opt_header->id);
		ctx->opt_blocks[i].data_length = (opt_hdr_len - 4) / 2;
		ctx->opt_blocks[i].data = calloc(1, ctx->opt_blocks[i].data_length);
		r = hex_to_bin(opt_header->data, ctx->opt_blocks[i].data, ctx->opt_blocks[i].data_length);
		if (r) {
			r = TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
			goto error;
		}

		// advance current pointer
		ptr += opt_hdr_len;
	}

	// determine authenticator length based on format version
	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_C:
			ctx->authenticator_length = 4; // 4 bytes; 8 ASCII hex digits
			break;

		case TR31_VERSION_B:
			ctx->authenticator_length = 8; // 8 bytes; 16 ASCII hex digits
			break;

		case TR31_VERSION_D:
			// TODO: implement TR-31:2018
			return -1;

		default:
			// invalid format version
			return -1;
	}

	// ensure that current pointer is valid for minimal payload and authenticator
	if (ptr - (void*)header + TR31_MIN_PAYLOAD_LENGTH + (ctx->authenticator_length * 2) > key_block_len) {
		r = TR31_ERROR_INVALID_LENGTH;
		goto error;
	}

	// determine header and payload lengths
	size_t key_block_header_len = ptr - (void*)header;
	size_t key_block_payload_length = key_block_len - key_block_header_len - (ctx->authenticator_length * 2);
	ctx->payload_length = key_block_payload_length / 2;

	// add payload data to context object
	ctx->payload = calloc(1, ctx->payload_length);
	r = hex_to_bin(ptr, ctx->payload, ctx->payload_length);
	if (r) {
		r = TR31_ERROR_INVALID_PAYLOAD_FIELD;
		goto error;
	}
	ptr += key_block_payload_length;

	// ensure that current point is valid for remaining authenticator
	if (ptr - (void*)header + (ctx->authenticator_length * 2) != key_block_len) {
		r = TR31_ERROR_INVALID_LENGTH;
		goto error;
	}

	// add authenticator to context object
	ctx->authenticator = calloc(1, ctx->authenticator_length);
	r = hex_to_bin(ptr, ctx->authenticator, ctx->authenticator_length);
	if (r) {
		r = TR31_ERROR_INVALID_AUTHENTICATOR_FIELD;
		goto error;
	}

	// if no key block protection key was provided, we are done
	if (!kbpk) {
		r = 0;
		goto exit;
	}

	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_C: {
			// only allow TDES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_TDES) {
				r = TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
				goto error;
			}

			// validate payload length
			if (ctx->payload_length != TR31_TDES2_KEY_UNDER_DES_LENGTH &&
				ctx->payload_length != TR31_TDES3_KEY_UNDER_DES_LENGTH
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			uint8_t kbek[TDES3_KEY_SIZE];
			uint8_t kbak[TDES3_KEY_SIZE];

			// buffer for decryption
			uint8_t decrypted_payload_buf[ctx->payload_length];
			struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)decrypted_payload_buf;

			// buffer for MAC verification
			uint8_t mac_buf[key_block_header_len + ctx->payload_length];
			memcpy(mac_buf, key_block, key_block_header_len);
			memcpy(mac_buf + key_block_header_len, ctx->payload, ctx->payload_length);

			// output key block encryption key variant and key block authentication key variant
			r = tr31_tdes_kbpk_variant(kbpk->data, kbpk->length, kbek, kbak);
			if (r) {
				// return error value as-is
				goto error;
			}

			// verify authenticator
			r = tr31_tdes_verify_cbcmac(kbak, kbpk->length, mac_buf, sizeof(mac_buf), ctx->authenticator);
			if (r) {
				// return error value as-is
				goto error;
			}

			// decrypt key payload; note that the TR-31 header is used as the IV
			r = tr31_tdes_decrypt_cbc(kbek, kbpk->length, header, ctx->payload, ctx->payload_length, decrypted_payload);
			if (r) {
				// return error value as-is
				goto error;
			}

			// validate payload length field
			ctx->key.length = ntohs(decrypted_payload->length) / 8; // payload length is big endian and in bits, not bytes
			if (ctx->key.length != TDES2_KEY_SIZE && ctx->key.length != TDES3_KEY_SIZE) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// extract key data
			ctx->key.data = calloc(1, ctx->key.length);
			memcpy(ctx->key.data, decrypted_payload->data, ctx->key.length);

			// TODO: clean decrypted_payload_buf

			break;
		}

		case TR31_VERSION_B: {
			// only allow TDES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_TDES) {
				r = TR31_ERROR_UNSUPPORTED_KBPK_LENGTH;
				goto error;
			}

			// validate payload length
			if (ctx->payload_length != TR31_TDES2_KEY_UNDER_DES_LENGTH &&
				ctx->payload_length != TR31_TDES3_KEY_UNDER_DES_LENGTH
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			uint8_t kbek[TDES3_KEY_SIZE];
			uint8_t kbak[TDES3_KEY_SIZE];

			// buffer for decryption and CMAC verification
			uint8_t decrypted_key_block[key_block_header_len + ctx->payload_length];
			struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)(decrypted_key_block + key_block_header_len);
			memcpy(decrypted_key_block, key_block, key_block_header_len);

			// derive key block encryption key and key block authentication key from key block protection key
			r = tr31_tdes_kbpk_derive(kbpk->data, kbpk->length, kbek, kbak);
			if (r) {
				// return error value as-is
				goto error;
			}

			// decrypt key payload; note that the authenticator is used as the IV
			r = tr31_tdes_decrypt_cbc(kbek, kbpk->length, ctx->authenticator, ctx->payload, ctx->payload_length, decrypted_payload);
			if (r) {
				// return error value as-is
				goto error;
			}

			// validate payload length field
			ctx->key.length = ntohs(decrypted_payload->length) / 8; // payload length is big endian and in bits, not bytes
			if (ctx->key.length != TDES2_KEY_SIZE && ctx->key.length != TDES3_KEY_SIZE) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// extract key data
			ctx->key.data = calloc(1, ctx->key.length);
			memcpy(ctx->key.data, decrypted_payload->data, ctx->key.length);

			// verify authenticator
			r = tr31_tdes_verify_cmac(kbak, kbpk->length, decrypted_key_block, sizeof(decrypted_key_block), ctx->authenticator);
			if (r) {
				r = TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED;
				goto error;
			}

			// TODO: clean decrypted_key_block

			break;
		}

		default:
			// invalid format version
			return -1;
	}

	r = 0;
	goto exit;

error:
	tr31_release(ctx);
exit:
	return r;
}

void tr31_release(struct tr31_ctx_t* ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->key.data) {
		free(ctx->key.data);
		ctx->key.data = NULL;
	}

	if (ctx->opt_blocks) {
		for (size_t i = 0; i < ctx->opt_blocks_count; ++i) {
			free(ctx->opt_blocks[i].data);
			ctx->opt_blocks[i].data = NULL;
		}

		free(ctx->opt_blocks);
		ctx->opt_blocks = NULL;
	}

	if (ctx->payload) {
		free(ctx->payload);
		ctx->payload = NULL;
	}
	if (ctx->authenticator) {
		free(ctx->authenticator);
		ctx->authenticator = NULL;
	}
}

const char* tr31_get_error_string(enum tr31_error_t error)
{
	if (error < 0) {
		return "Internal error";
	}

	switch (error) {
		case TR31_ERROR_INVALID_LENGTH: return "Invalid key block length";
		case TR31_ERROR_UNSUPPORTED_VERSION: return "Unsupported key block format version";
		case TR31_ERROR_INVALID_LENGTH_FIELD: return "Invalid key block length field";
		case TR31_ERROR_UNSUPPORTED_KEY_USAGE: return "Unsupported key usage";
		case TR31_ERROR_UNSUPPORTED_ALGORITHM: return "Unsupported key algorithm";
		case TR31_ERROR_UNSUPPORTED_MODE_OF_USE: return "Unsupported key mode of use";
		case TR31_ERROR_INVALID_KEY_VERSION_FIELD: return "Invalid key version field";
		case TR31_ERROR_UNSUPPORTED_EXPORTABILITY: return "Unsupported key exportability";
		case TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD: return "Invalid number of optional blocks field";
		case TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA: return "Invalid optional block data";
		case TR31_ERROR_INVALID_PAYLOAD_FIELD: return "Invalid payload data field";
		case TR31_ERROR_INVALID_AUTHENTICATOR_FIELD: return "Invalid authenticator data field";
		case TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM: return "Unsupported key block protection key algorithm";
		case TR31_ERROR_UNSUPPORTED_KBPK_LENGTH: return "Unsupported key block protection key length";
		case TR31_ERROR_INVALID_KEY_LENGTH: return "Invalid key length";
		case TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED: return "Key block verification failed";
	}

	return "Unknown error";
}

const char* tr31_get_key_usage_ascii(unsigned int usage, char* ascii, size_t ascii_len)
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
		if (isalnum(usage_ascii.bytes[i])) {
			ascii[i] = usage_ascii.bytes[i];
		} else {
			ascii[i] = '?';
		}
	}
	ascii[2] = 0;

	return ascii;
}

const char* tr31_get_key_usage_string(unsigned int usage)
{
	switch (usage) {
		case TR31_KEY_USAGE_BDK:                return "Base Derivation Key (BDK)";
		case TR31_KEY_USAGE_DUKPT_IPEK:         return "DUKPT Initial Key (IPEK)";
		case TR31_KEY_USAGE_CVK:                return "Card Verification Key (CVK)";
		case TR31_KEY_USAGE_DATA:               return "Data Encryption Key (Generic)";
		case TR31_KEY_USAGE_EMV_MKAC:           return "EMV/chip Issuer Master Key: Application cryptograms (MKAC)";
		case TR31_KEY_USAGE_EMV_MKSMC:          return "EMV/chip Issuer Master Key: Secure Messaging for Confidentiality (MKSMC)";
		case TR31_KEY_USAGE_EMV_MKSMI:          return "EMV/chip Issuer Master Key: Secure Messaging for Integrity (MKSMI)";
		case TR31_KEY_USAGE_EMV_MKDAC:          return "EMV/chip Issuer Master Key: Data Authentication Code (MKDAC)";
		case TR31_KEY_USAGE_EMV_MKDN:           return "EMV/chip Issuer Master Key: Dynamic Numbers (MKDN)";
		case TR31_KEY_USAGE_EMV_CP:             return "EMV/chip Issuer Master Key: Card Personalization (CP)";
		case TR31_KEY_USAGE_EMV_OTHER:          return "EMV/chip Issuer Master Key: Other";
		case TR31_KEY_USAGE_IV:                 return "Initialization Vector";
		case TR31_KEY_USAGE_KEY:                return "Key Encryption / Wrapping Key (Generic)";
		case TR31_KEY_USAGE_ISO16609_MAC_1:     return "ISO 16609 MAC algorithm 1 (using 3DES)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_1:    return "ISO 9797-1 MAC Algorithm 1 (CBC-MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_2:    return "ISO 9797-1 MAC Algorithm 2";
		case TR31_KEY_USAGE_ISO9797_1_MAC_3:    return "ISO 9797-1 MAC Algorithm 3 (Retail MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_4:    return "ISO 9797-1 MAC Algorithm 4";
		case TR31_KEY_USAGE_ISO9797_1_MAC_5:    return "ISO 9797-1 MAC Algorithm 5 (CMAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_6:    return "ISO 9797-1 MAC Algorithm 6";
		case TR31_KEY_USAGE_PIN:                return "PIN Encryption Key (Generic)";
		case TR31_KEY_USAGE_PV:                 return "PIN Verification Key (Generic)";
		case TR31_KEY_USAGE_PV_IBM3624:         return "PIN Verification Key (IBM 3624)";
		case TR31_KEY_USAGE_PV_VISA:            return "PIN Verification Key (VISA PVV)";
	}

	return "Unknown key usage value";
}

const char* tr31_get_key_algorithm_string(unsigned int algorithm)
{
	switch (algorithm) {
		case TR31_KEY_ALGORITHM_AES:    return "AES";
		case TR31_KEY_ALGORITHM_DES:    return "DES";
		case TR31_KEY_ALGORITHM_EC:     return "Elliptic Curve";
		case TR31_KEY_ALGORITHM_HMAC:   return "HMAC-SHA1";
		case TR31_KEY_ALGORITHM_RSA:    return "RSA";
		case TR31_KEY_ALGORITHM_DSA:    return "DSA";
		case TR31_KEY_ALGORITHM_TDES:   return "TDES";
	}

	return "Unknown key algorithm value";
}
