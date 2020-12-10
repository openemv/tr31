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
		case TR31_VERSION_D:
			break;

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
	ctx->opt_blocks = calloc(ctx->opt_blocks_count, sizeof(ctx->opt_blocks[0]));
	ptr = header + 1; // optional header blocks, if any, are after the header
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
		return TR31_ERROR_INVALID_LENGTH;
	}

	// determine payload length in bytes
	size_t payload_length = key_block_len - (ptr - (void*)header) - (ctx->authenticator_length * 2);
	switch (ctx->key.algorithm) {
		case TR31_KEY_ALGORITHM_DES:
		case TR31_KEY_ALGORITHM_TDES:
			ctx->payload_length = payload_length / 2;

			// ensure that payload length is a multiple of the DES block size
			if ((ctx->payload_length & (DES_KEY_SZ-1)) != 0) {
				return TR31_ERROR_INVALID_PAYLOAD_DATA;
			}
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_ALGORITHM;
	}

	// add payload data to context object
	ctx->payload = calloc(1, ctx->payload_length);
	r = hex_to_bin(ptr, ctx->payload, ctx->payload_length);
	if (r) {
		r = TR31_ERROR_INVALID_PAYLOAD_DATA;
		goto error;
	}
	ptr += payload_length;

	// ensure that current point is valid for remaining authenticator
	if (ptr - (void*)header + (ctx->authenticator_length * 2) != key_block_len) {
		r = TR31_ERROR_INVALID_LENGTH;
		goto error;
	}

	// add authenticator to context object
	ctx->authenticator = calloc(1, ctx->authenticator_length);
	r = hex_to_bin(ptr, ctx->authenticator, ctx->authenticator_length);
	if (r) {
		r = TR31_ERROR_INVALID_AUTHENTICATOR_DATA;
		goto error;
	}

	// if no key block protection key was provided, we are done
	if (!kbpk) {
		r = 0;
		goto exit;
	}

	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_C:
			// TODO: verify payload length
			// TODO: derive keys
			// TODO: verify MAC
			// TODO: decrypt
			break;

		case TR31_VERSION_B:
			// TODO: verify payload length
			// TODO: derive keys
			// TODO: decrypt
			// TODO: verify MAC
			break;

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
