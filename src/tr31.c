/**
 * @file tr31.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include <arpa/inet.h> // for ntohs and friends

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

#define TR31_MIN_LENGTH (sizeof(struct tr31_header_t) + 8 + 8) // TR-31 header + 3DES block length + authenticator

static int decimal_to_int(const char* str, size_t length)
{
	int value;

	value = 0;
	for (size_t i = 0; i < length; ++i) {
		if (!isdigit(str[i])) {
			return -1;
		}

		value *= 10; // shift decimal value
		value += str[i] - 0x30; // convert ASCII to numeric value
	}

	return value;
}

int tr31_decode(const char* encoded, struct tr31_info_t* info)
{
	size_t encoded_len;
	struct tr31_header_t* header;

	if (!encoded || !info) {
		return -1;
	}
	memset(info, 0, sizeof(*info));

	encoded_len = strlen(encoded);
	header = (struct tr31_header_t*)encoded;

	// validate minimum length
	if (encoded_len < TR31_MIN_LENGTH) {
		return TR31_ERROR_INVALID_LENGTH;
	}

	// decode key block format
	info->version = header->version_id;
	switch (info->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_B:
		case TR31_VERSION_C:
		case TR31_VERSION_D:
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_VERSION;
	}

	// decode key block length field
	info->length = decimal_to_int(header->length, sizeof(header->length));
	if (info->length != encoded_len) {
		return TR31_ERROR_INVALID_LENGTH_FIELD;
	}

	// decode key usage field
	info->key_usage = ntohs(header->key_usage);
	switch (info->key_usage) {
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
	info->algorithm = header->algorithm;
	switch (info->algorithm) {
		case TR31_ALGORITHM_AES:
		case TR31_ALGORITHM_DES:
		case TR31_ALGORITHM_EC:
		case TR31_ALGORITHM_HMAC:
		case TR31_ALGORITHM_RSA:
		case TR31_ALGORITHM_DSA:
		case TR31_ALGORITHM_TDES:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_ALGORITHM;
	}
	
	// decode mode of use field
	info->mode_of_use = header->mode_of_use;
	switch (info->mode_of_use) {
		case TR31_MODE_OF_USE_ENC_DEC:
		case TR31_MODE_OF_USE_MAC:
		case TR31_MODE_OF_USE_DEC:
		case TR31_MODE_OF_USE_ENC:
		case TR31_MODE_OF_USE_MAC_GEN:
		case TR31_MODE_OF_USE_ANY:
		case TR31_MODE_OF_USE_SIG:
		case TR31_MODE_OF_USE_MAC_VERIFY:
		case TR31_MODE_OF_USE_DERIVE:
		case TR31_MODE_OF_USE_VARIANT:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_MODE_OF_USE;
	}

	// decode key version number field
	if (header->key_version[0] == '0' && header->key_version[1] == '0') {
		info->key_version = TR31_KEY_VERSION_IS_UNUSED;
	} else if (header->key_version[0] == 'c') {
		info->key_version = TR31_KEY_VERSION_IS_COMPONENT;
		info->key_component_number = decimal_to_int(&header->key_version[1], sizeof(header->key_version[1]));
	} else {
		int key_version_value = decimal_to_int(header->key_version, sizeof(header->key_version));
		if (key_version_value < 0) {
			return TR31_ERROR_INVALID_KEY_VERSION_FIELD;
		}

		info->key_version = TR31_KEY_VERSION_IS_VALID;
		info->key_version_value = key_version_value;
	}

	// decode exportability field
	info->exportability = header->exportability;
	switch (info->exportability) {
		case TR31_KEY_EXPORT_TRUSTED:
		case TR31_KEY_EXPORT_NONE:
		case TR31_KEY_EXPORT_SENSITIVE:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_EXPORTABILITY;
	}

	// decode number of optional blocks field
	int opt_blocks_count = decimal_to_int(header->opt_blocks_count, sizeof(header->opt_blocks_count));
	if (opt_blocks_count < 0) {
		return TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD;
	}
	info->opt_blocks_count = opt_blocks_count;

	return 0;
}
