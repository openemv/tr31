/**
 * @file tr31.c
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

#include "tr31.h"
#include "tr31_config.h"
#include "tr31_crypto.h"

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <arpa/inet.h> // for ntohs and friends

// TR-31 header
// see TR-31:2018, A.2, table 4
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

// TR-31 optional block
// see TR-31:2018, A.2, table 4
struct tr31_opt_blk_t {
	uint16_t id;
	char length[2];
	char data[];
} __attribute__((packed));

// TR-31 payload
// see TR-31:2018, A.3, table 5
struct tr31_payload_t {
	uint16_t length;
	uint8_t data[];
} __attribute__((packed));

#define TR31_MIN_PAYLOAD_LENGTH (DES_BLOCK_SIZE)
#define TR31_MIN_KEY_BLOCK_LENGTH (sizeof(struct tr31_header_t) + TR31_MIN_PAYLOAD_LENGTH + 8) // Minimum TR-31 key block length: header + minimum payload + authenticator

// helper functions
static int dec_to_int(const char* str, size_t str_len);
static void int_to_dec(unsigned int value, char* str, size_t str_len);
static int hex_to_int(const char* str, size_t str_len);
static void int_to_hex(unsigned int value, char* str, size_t str_len);
static int hex_to_bin(const char* hex, void* bin, size_t bin_len);
static int bin_to_hex(const void* bin, size_t bin_len, char* str, size_t str_len);
static int tr31_tdes_decrypt_verify_variant_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk);
static int tr31_tdes_encrypt_sign_variant_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk);
static int tr31_tdes_decrypt_verify_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk);
static int tr31_tdes_encrypt_sign_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk);
static int tr31_aes_decrypt_verify_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk);
static const char* tr31_get_opt_block_kcv_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_get_opt_block_hmac_string(const struct tr31_opt_ctx_t* opt_block);

static int dec_to_int(const char* str, size_t str_len)
{
	int value;

	value = 0;
	for (size_t i = 0; i < str_len; ++i) {
		if (!isdigit(str[i])) {
			return -1;
		}

		value *= 10; // shift decimal value
		value += str[i] - '0'; // convert ASCII decimal to numeric value
	}

	return value;
}

static void int_to_dec(unsigned int value, char* str, size_t str_len)
{
	// pack string digits, right justified
	while (str_len) {
		uint8_t digit;

		digit = value % 10; // extract digit
		value /= 10; // shift decimal value

		str[str_len - 1] = digit + '0'; // convert numeric value to ASCII decimal
		--str_len;
	}
}

static int hex_to_int(const char* str, size_t str_len)
{
	int value;

	value = 0;
	for (size_t i = 0; i < str_len; ++i) {
		if (!isxdigit(str[i])) {
			return -1;
		}

		value <<= 4; // shift hex value
		// convert ASCII hex to numeric value
		if (str[i] >= '0' && str[i] <= '9') {
			value += str[i] - '0';
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

static void int_to_hex(unsigned int value, char* str, size_t str_len)
{
	// pack string digits, right justified
	while (str_len) {
		uint8_t digit;

		digit = value & 0xF; // extract digit
		value >>= 4; // shift hex value

		// convert numeric value to ASCII hex
		if (digit < 0xA) {
			str[str_len - 1] = digit + '0';
		} else {
			str[str_len - 1] = digit - 0xA + 'A';
		}
		--str_len;
	}
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

static int bin_to_hex(const void* bin, size_t bin_len, char* hex, size_t hex_len)
{
	const uint8_t* buf = bin;

	// minimum string length
	if (hex_len < bin_len * 2) {
		return -1;
	}

	// pack hex digits, left justified
	for (unsigned int i = 0; i < bin_len; ++i) {
		uint8_t digit;

		// convert most significant nibble
		digit = buf[i] >> 4;
		if (digit < 0xA) {
			hex[(i * 2)] = digit + '0';
		} else {
			hex[(i * 2)] = digit - 0xA + 'A';
		}

		// convert least significant nibble
		digit = buf[i] & 0xf;
		if (digit < 0xA) {
			hex[(i * 2) + 1] = digit + '0';
		} else {
			hex[(i * 2) + 1] = digit - 0xA + 'A';
		}
	}

	return 0;
}

const char* tr31_lib_version_string(void)
{
	return TR31_LIB_VERSION_STRING;
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
			// supported
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
	// see TR-31:2018, A.5.1, table 6
	ctx->key.usage = ntohs(header->key_usage);
	switch (ctx->key.usage) {
		case TR31_KEY_USAGE_BDK:
		case TR31_KEY_USAGE_DUKPT_IPEK:
		case TR31_KEY_USAGE_BKV:
		case TR31_KEY_USAGE_CVK:
		case TR31_KEY_USAGE_DATA:
		case TR31_KEY_USAGE_ASYMMETRIC_DATA:
		case TR31_KEY_USAGE_DATA_DEC_TABLE:
		case TR31_KEY_USAGE_EMV_MKAC:
		case TR31_KEY_USAGE_EMV_MKSMC:
		case TR31_KEY_USAGE_EMV_MKSMI:
		case TR31_KEY_USAGE_EMV_MKDAC:
		case TR31_KEY_USAGE_EMV_MKDN:
		case TR31_KEY_USAGE_EMV_CP:
		case TR31_KEY_USAGE_EMV_OTHER:
		case TR31_KEY_USAGE_IV:
		case TR31_KEY_USAGE_KEK:
		case TR31_KEY_USAGE_TR31_KBPK:
		case TR31_KEY_USAGE_TR34_KEK:
		case TR31_KEY_USAGE_ASYMMETRIC_KEK:
		case TR31_KEY_USAGE_ISO16609_MAC_1:
		case TR31_KEY_USAGE_ISO9797_1_MAC_1:
		case TR31_KEY_USAGE_ISO9797_1_MAC_2:
		case TR31_KEY_USAGE_ISO9797_1_MAC_3:
		case TR31_KEY_USAGE_ISO9797_1_MAC_4:
		case TR31_KEY_USAGE_ISO9797_1_MAC_5:
		case TR31_KEY_USAGE_ISO9797_1_CMAC:
		case TR31_KEY_USAGE_HMAC:
		case TR31_KEY_USAGE_ISO9797_1_MAC_6:
		case TR31_KEY_USAGE_PIN:
		case TR31_KEY_USAGE_ASYMMETRIC_SIG:
		case TR31_KEY_USAGE_ASYMMETRIC_CA:
		case TR31_KEY_USAGE_ASYMMETRIC_OTHER:
		case TR31_KEY_USAGE_PV:
		case TR31_KEY_USAGE_PV_IBM3624:
		case TR31_KEY_USAGE_PV_VISA:
		case TR31_KEY_USAGE_PV_X9_132_1:
		case TR31_KEY_USAGE_PV_X9_132_2:
			// supported
			break;

		default:
			return TR31_ERROR_UNSUPPORTED_KEY_USAGE;
	}

	// decode algorithm field
	// see TR-31:2018, A.5.2, table 7
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
	// see TR-31:2018, A.5.3, table 8
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
	// see TR-31:2018, A.5.4, table 9
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
	// see TR-31:2018, A.5.5, table 10
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

	// decode number of optional blocks field
	int opt_blocks_count = dec_to_int(header->opt_blocks_count, sizeof(header->opt_blocks_count));
	if (opt_blocks_count < 0) {
		return TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD;
	}
	ctx->opt_blocks_count = opt_blocks_count;

	// decode optional blocks
	// see TR-31:2018, A.5.6
	ptr = header + 1; // optional blocks, if any, are after the header
	if (ctx->opt_blocks_count) {
		ctx->opt_blocks = calloc(ctx->opt_blocks_count, sizeof(ctx->opt_blocks[0]));
	}
	for (int i = 0; i < opt_blocks_count; ++i) {
		// ensure that current pointer is valid for minimal optional block
		if (ptr + sizeof(struct tr31_opt_blk_t) - (void*)header > key_block_len) {
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		const struct tr31_opt_blk_t* opt_blk = ptr;

		// ensure that optional block length is valid
		int opt_hdr_len = hex_to_int(opt_blk->length, sizeof(opt_blk->length));
		if (opt_hdr_len < 0) {
			// parse error
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		if (opt_hdr_len == 0) {
			// extended optional block length not supported
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		if (opt_hdr_len < sizeof(struct tr31_opt_blk_t)) {
			// optional block length must be at least 4 bytes (2 byte id + 2 byte length)
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}
		if (ptr + opt_hdr_len - (void*)header > key_block_len) {
			// optional block length exceeds total key block length
			r = TR31_ERROR_INVALID_LENGTH;
			goto error;
		}

		// copy optional block field
		ctx->opt_blocks[i].id = ntohs(opt_blk->id);
		ctx->opt_blocks[i].data_length = (opt_hdr_len - 4) / 2;
		ctx->opt_blocks[i].data = calloc(1, ctx->opt_blocks[i].data_length);
		r = hex_to_bin(opt_blk->data, ctx->opt_blocks[i].data, ctx->opt_blocks[i].data_length);
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
			ctx->authenticator_length = 16; // 16 bytes; 32 ASCII hex digits
			break;

		default:
			// invalid format version
			return -1;
	}

	// ensure that current pointer is valid for minimal payload and authenticator
	if (ptr - (void*)header + TR31_MIN_PAYLOAD_LENGTH + (ctx->authenticator_length * 2) > key_block_len) {
		r = TR31_ERROR_INVALID_LENGTH;
		goto error;
	}

	// add header data to context object
	ctx->header_length = ptr - (void*)header;
	ctx->header = calloc(1, ctx->header_length);
	memcpy(ctx->header, header, ctx->header_length);

	// determine payload length
	size_t key_block_payload_length = key_block_len - ctx->header_length - (ctx->authenticator_length * 2);
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
				r = TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM;
				goto error;
			}

			// validate payload length
			if (ctx->payload_length != TR31_TDES2_KEY_UNDER_DES_LENGTH &&
				ctx->payload_length != TR31_TDES3_KEY_UNDER_DES_LENGTH
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// verify and decrypt payload
			r = tr31_tdes_decrypt_verify_variant_binding(ctx, kbpk);
			if (r) {
				// return error value as-is
				goto error;
			}

			// validate payload length field
			if (ctx->key.length != TDES2_KEY_SIZE &&
				ctx->key.length != TDES3_KEY_SIZE
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// populate KCV
			r = tr31_tdes_kcv(ctx->key.data, ctx->key.length, ctx->key.kcv);
			if (r) {
				// return error value as-is
				goto error;
			}

			break;
		}

		case TR31_VERSION_B: {
			// only allow TDES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_TDES) {
				r = TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM;
				goto error;
			}

			// validate payload length
			if (ctx->payload_length != TR31_TDES2_KEY_UNDER_DES_LENGTH &&
				ctx->payload_length != TR31_TDES3_KEY_UNDER_DES_LENGTH
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// decrypt and verify payload
			r = tr31_tdes_decrypt_verify_derivation_binding(ctx, kbpk);
			if (r) {
				// return error value as-is
				goto error;
			}

			// validate payload length field
			if (ctx->key.length != TDES2_KEY_SIZE &&
				ctx->key.length != TDES3_KEY_SIZE
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// populate KCV
			r = tr31_tdes_kcv(ctx->key.data, ctx->key.length, ctx->key.kcv);
			if (r) {
				// return error value as-is
				goto error;
			}

			break;
		}

		case TR31_VERSION_D: {
			// only allow AES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_AES) {
				r = TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM;
				goto error;
			}

			// validate payload length
			if (ctx->payload_length != TR31_TDES2_KEY_UNDER_AES_LENGTH &&
				ctx->payload_length != TR31_TDES3_KEY_UNDER_AES_LENGTH &&
				ctx->payload_length != TR31_AES128_KEY_UNDER_AES_LENGTH &&
				ctx->payload_length != TR31_AES192_KEY_UNDER_AES_LENGTH &&
				ctx->payload_length != TR31_AES256_KEY_UNDER_AES_LENGTH
			) {
				r = TR31_ERROR_INVALID_KEY_LENGTH;
				goto error;
			}

			// decrypt and verify payload
			r = tr31_aes_decrypt_verify_derivation_binding(ctx, kbpk);
			if (r) {
				// return error value as-is
				goto error;
			}

			// validate payload length field
			switch (ctx->key.algorithm) {
				case TR31_KEY_ALGORITHM_TDES:
					if (ctx->key.length != TDES2_KEY_SIZE &&
						ctx->key.length != TDES3_KEY_SIZE
					) {
						r = TR31_ERROR_INVALID_KEY_LENGTH;
						goto error;
					}
					break;

				case TR31_KEY_ALGORITHM_AES:
					if (ctx->key.length != AES128_KEY_SIZE &&
						ctx->key.length != AES192_KEY_SIZE &&
						ctx->key.length != AES256_KEY_SIZE
					) {
						r = TR31_ERROR_INVALID_KEY_LENGTH;
						goto error;
					}
					break;

				default:
					// unsupported; continue
					break;
			}

			// populate KCV
			switch (ctx->key.algorithm) {
				case TR31_KEY_ALGORITHM_TDES:
					r = tr31_tdes_kcv(ctx->key.data, ctx->key.length, ctx->key.kcv);
					break;

				case TR31_KEY_ALGORITHM_AES:
					r = tr31_aes_kcv(ctx->key.data, ctx->key.length, ctx->key.kcv);
					break;

				default:
					// KCV is not available
					memset(ctx->key.kcv, 0, sizeof(ctx->key.kcv));
					r = 0;
			}
			if (r) {
				// return error value as-is
				goto error;
			}

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

int tr31_export(
	struct tr31_ctx_t* ctx,
	const struct tr31_key_t* kbpk,
	char* key_block,
	size_t key_block_len
)
{
	int r;
	struct tr31_header_t* header;
	size_t opt_blk_len_total = 0;
	void* ptr;

	if (!ctx || !kbpk || !key_block || !key_block_len) {
		return -1;
	}

	// ensure space for null-termination
	--key_block_len;

	// validate minimum length
	if (key_block_len < TR31_MIN_KEY_BLOCK_LENGTH) {
		return TR31_ERROR_INVALID_LENGTH;
	}
	memset(key_block, 0, key_block_len);

	// validate key block format version
	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_C:
			// supported
			break;

		case TR31_VERSION_B:
			// supported
			break;

		case TR31_VERSION_D:
			// supported
			break;

		default:
			// unsupported
			return TR31_ERROR_UNSUPPORTED_VERSION;
	}

	// populate key block header
	header = (struct tr31_header_t*)key_block;
	header->version_id = ctx->version;
	int_to_dec(ctx->length, header->length, sizeof(header->length)); // verify later
	header->key_usage = htons(ctx->key.usage);
	header->algorithm = ctx->key.algorithm;
	header->mode_of_use = ctx->key.mode_of_use;
	header->exportability = ctx->key.exportability;
	memset(header->reserved, '0', sizeof(header->reserved));

	// populate key version field
	switch (ctx->key.key_version) {
		case TR31_KEY_VERSION_IS_UNUSED:
			memset(header->key_version, '0', sizeof(header->key_version));
			break;

		case TR31_KEY_VERSION_IS_COMPONENT:
			header->key_version[0] = 'c';
			int_to_dec(ctx->key.key_component_number, &header->key_version[1], sizeof(header->key_version[1]));
			break;

		case TR31_KEY_VERSION_IS_VALID:
			int_to_dec(ctx->key.key_version_value, header->key_version, sizeof(header->key_version));
			break;

		default:
			return TR31_ERROR_INVALID_KEY_VERSION_FIELD;
	}

	// populate optional blocks
	int_to_dec(ctx->opt_blocks_count, header->opt_blocks_count, sizeof(header->opt_blocks_count));
	ptr = header + 1; // optional blocks, if any, are after the header
	if (ctx->opt_blocks_count && !ctx->opt_blocks) {
		// optional block count is non-zero but optional block data is missing
		return TR31_ERROR_INVALID_NUMBER_OF_OPTIONAL_BLOCKS_FIELD;
	}
	for (int i = 0; i < ctx->opt_blocks_count; ++i) {
		// ensure that current pointer is valid for minimal optional block
		if (ptr + sizeof(struct tr31_opt_blk_t) - (void*)header > key_block_len) {
			return TR31_ERROR_INVALID_LENGTH;
		}
		struct tr31_opt_blk_t* opt_blk = ptr;

		// ensure that optional block length is valid
		size_t opt_blk_len = (ctx->opt_blocks[i].data_length * 2) + 4;
		if (ptr + opt_blk_len - (void*)header > key_block_len) {
			// optional block length exceeds total key block length
			return TR31_ERROR_INVALID_LENGTH;
		}
		opt_blk_len_total += opt_blk_len;

		// populate optional block id and length
		opt_blk->id = htons(ctx->opt_blocks[i].id);
		int_to_hex(opt_blk_len, opt_blk->length, sizeof(opt_blk->length));

		// populate optional block data
		if (ctx->opt_blocks[i].data_length && !ctx->opt_blocks[i].data) {
			// optional block payload length is non-zero but optional block data is missing
			return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
		}
		r = bin_to_hex(
			ctx->opt_blocks[i].data,
			ctx->opt_blocks[i].data_length,
			opt_blk->data,
			ctx->opt_blocks[i].data_length * 2
		);
		if (r) {
			return -2;
		}

		// advance current pointer
		ptr += opt_blk_len;
	}

	// TR-31:2018, A.5.6 indicates that the total optional block length must
	// be a multiple of 8
	if (opt_blk_len_total & 0x7) {
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}

	// add header data to context object
	ctx->header_length = ptr - (void*)header;
	ctx->header = calloc(1, ctx->header_length);
	memcpy(ctx->header, header, ctx->header_length);

	switch (ctx->version) {
		case TR31_VERSION_A:
		case TR31_VERSION_C:
			// only allow TDES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_TDES) {
				return TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM;
			}

			// encrypt and sign payload
			// this will populate:
			//   ctx->payload_length
			//   ctx->payload
			//   ctx->authenticator
			r = tr31_tdes_encrypt_sign_variant_binding(ctx, kbpk);
			if (r) {
				// return error value as-is
				return r;
			}
			break;

		case TR31_VERSION_B:
			// only allow TDES key block protection keys
			if (kbpk->algorithm != TR31_KEY_ALGORITHM_TDES) {
				return TR31_ERROR_UNSUPPORTED_KBPK_ALGORITHM;
			}

			// sign and encrypt payload
			// this will populate:
			//   ctx->payload_length
			//   ctx->payload
			//   ctx->authenticator
			r = tr31_tdes_encrypt_sign_derivation_binding(ctx, kbpk);
			if (r) {
				// return error value as-is
				return r;
			}
			break;

		default:
			// invalid format version
			return -3;
	}

	// ensure that encrypted payload and authenticator are available
	if (!ctx->payload || !ctx->authenticator) {
		// internal error
		return -4;
	}

	// validate key block buffer length
	if (sizeof(*header) + opt_blk_len_total + (ctx->payload_length * 2) + (ctx->authenticator_length * 2)
		> key_block_len
	) {
		return TR31_ERROR_INVALID_LENGTH;
	}

	// add payload to key block
	r = bin_to_hex(ctx->payload, ctx->payload_length, ptr, key_block_len);
	if (r) {
		// internal error
		return -5;
	}
	ptr += (ctx->payload_length * 2);

	// add authenticator to key block
	r = bin_to_hex(ctx->authenticator, ctx->authenticator_length, ptr, key_block_len);
	if (r) {
		// internal error
		return -6;
	}

	return 0;
}

static int tr31_tdes_decrypt_verify_variant_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk)
{
	int r;
	uint8_t kbek[TDES3_KEY_SIZE];
	uint8_t kbak[TDES3_KEY_SIZE];

	// buffer for decryption
	uint8_t decrypted_payload_buf[ctx->payload_length];
	struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)decrypted_payload_buf;

	// buffer for MAC verification
	uint8_t mac_input[ctx->header_length + ctx->payload_length];
	memcpy(mac_input, ctx->header, ctx->header_length);
	memcpy(mac_input + ctx->header_length, ctx->payload, ctx->payload_length);

	// output key block encryption key variant and key block authentication key variant
	r = tr31_tdes_kbpk_variant(kbpk->data, kbpk->length, kbek, kbak);
	if (r) {
		// return error value as-is
		goto error;
	}

	// verify authenticator
	r = tr31_tdes_verify_cbcmac(kbak, kbpk->length, mac_input, sizeof(mac_input), ctx->authenticator);
	if (r) {
		r = TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED;
		goto error;
	}

	// decrypt key payload; note that the TR-31 header is used as the IV
	r = tr31_tdes_decrypt_cbc(kbek, kbpk->length, ctx->header, ctx->payload, ctx->payload_length, decrypted_payload);
	if (r) {
		// return error value as-is
		goto error;
	}

	// validate payload length field
	ctx->key.length = ntohs(decrypted_payload->length) / 8; // payload length is big endian and in bits, not bytes
	if (ctx->key.length > ctx->payload_length - 2) {
		// invalid key length relative to encrypted payload length
		r = TR31_ERROR_INVALID_KEY_LENGTH;
		goto error;
	}

	// extract key data
	ctx->key.data = calloc(1, ctx->key.length);
	memcpy(ctx->key.data, decrypted_payload->data, ctx->key.length);

	// success
	r = 0;
	goto exit;

error:
exit:
	// cleanse sensitive buffers
	tr31_cleanse(kbek, sizeof(kbek));
	tr31_cleanse(kbak, sizeof(kbak));
	tr31_cleanse(decrypted_payload_buf, sizeof(decrypted_payload_buf));
	tr31_cleanse(mac_input, sizeof(mac_input));

	return r;
}

static int tr31_tdes_encrypt_sign_variant_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk)
{
	int r;
	uint8_t kbek[TDES3_KEY_SIZE];
	uint8_t kbak[TDES3_KEY_SIZE];

	// add payload data to context object
	ctx->payload_length = DES_CIPHERTEXT_LENGTH(sizeof(struct tr31_payload_t) + ctx->key.length);
	ctx->payload = calloc(1, ctx->payload_length);

	// add authenticator to context object
	ctx->authenticator_length = 4; // 4 bytes; 8 ASCII hex digits
	ctx->authenticator = calloc(1, ctx->authenticator_length);

	// buffer for encrypted
	uint8_t decrypted_payload_buf[ctx->payload_length];
	struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)decrypted_payload_buf;

	// buffer for MAC generation
	uint8_t mac_input[ctx->header_length + ctx->payload_length];

	// populate payload key
	decrypted_payload->length = htons(ctx->key.length * 8); // payload length is big endian and in bits, not bytes
	memcpy(decrypted_payload->data, ctx->key.data, ctx->key.length);
	tr31_rand(
		decrypted_payload->data + ctx->key.length,
		ctx->payload_length - sizeof(struct tr31_payload_t) - ctx->key.length
	);

	// output key block encryption key variant and key block authentication key variant
	r = tr31_tdes_kbpk_variant(kbpk->data, kbpk->length, kbek, kbak);
	if (r) {
		// return error value as-is
		goto error;
	}

	// encrypt key payload; note that the TR-31 header is used as the IV
	r = tr31_tdes_encrypt_cbc(kbek, kbpk->length, ctx->header, decrypted_payload, ctx->payload_length, ctx->payload);
	if (r) {
		// return error value as-is
		goto error;
	}

	// generate authenticator
	memcpy(mac_input, ctx->header, ctx->header_length);
	memcpy(mac_input + ctx->header_length, ctx->payload, ctx->payload_length);
	r = tr31_tdes_cbcmac(kbak, kbpk->length, mac_input, sizeof(mac_input), ctx->authenticator);
	if (r) {
		// return error value as-is
		goto error;
	}

	// success
	r = 0;
	goto exit;

error:
exit:
	// cleanse sensitive buffers
	tr31_cleanse(kbek, sizeof(kbek));
	tr31_cleanse(kbak, sizeof(kbak));
	tr31_cleanse(decrypted_payload_buf, sizeof(decrypted_payload_buf));
	tr31_cleanse(mac_input, sizeof(mac_input));

	return r;
}

static int tr31_tdes_decrypt_verify_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk)
{
	int r;
	uint8_t kbek[TDES3_KEY_SIZE];
	uint8_t kbak[TDES3_KEY_SIZE];

	// buffer for decryption and CMAC verification
	uint8_t decrypted_key_block[ctx->header_length + ctx->payload_length];
	memcpy(decrypted_key_block, ctx->header, ctx->header_length);
	struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)(decrypted_key_block + ctx->header_length);

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

	// extract payload length field
	ctx->key.length = ntohs(decrypted_payload->length) / 8; // payload length is big endian and in bits, not bytes
	if (ctx->key.length > ctx->payload_length - 2) {
		// invalid key length relative to encrypted payload length
		r = TR31_ERROR_INVALID_KEY_LENGTH;
		goto error;
	}

	// verify authenticator
	r = tr31_tdes_verify_cmac(kbak, kbpk->length, decrypted_key_block, sizeof(decrypted_key_block), ctx->authenticator);
	if (r) {
		r = TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED;
		goto error;
	}

	// extract key data
	ctx->key.data = calloc(1, ctx->key.length);
	memcpy(ctx->key.data, decrypted_payload->data, ctx->key.length);

	// success
	r = 0;
	goto exit;

error:
exit:
	// cleanse sensitive buffers
	tr31_cleanse(kbek, sizeof(kbek));
	tr31_cleanse(kbak, sizeof(kbak));
	tr31_cleanse(decrypted_key_block, sizeof(decrypted_key_block));

	return r;
}

static int tr31_tdes_encrypt_sign_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk)
{
	int r;
	uint8_t kbek[TDES3_KEY_SIZE];
	uint8_t kbak[TDES3_KEY_SIZE];

	// add payload data to context object
	ctx->payload_length = DES_CIPHERTEXT_LENGTH(sizeof(struct tr31_payload_t) + ctx->key.length);
	ctx->payload = calloc(1, ctx->payload_length);

	// add authenticator to context object
	ctx->authenticator_length = 8; // 8 bytes; 16 ASCII hex digits
	ctx->authenticator = calloc(1, ctx->authenticator_length);

	// buffer for CMAC generation and encryption
	uint8_t decrypted_key_block[ctx->header_length + ctx->payload_length];
	memcpy(decrypted_key_block, ctx->header, ctx->header_length);
	struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)(decrypted_key_block + ctx->header_length);

	// populate payload key
	decrypted_payload->length = htons(ctx->key.length * 8); // payload length is big endian and in bits, not bytes
	memcpy(decrypted_payload->data, ctx->key.data, ctx->key.length);
	tr31_rand(
		decrypted_payload->data + ctx->key.length,
		ctx->payload_length - sizeof(struct tr31_payload_t) - ctx->key.length
	);

	// derive key block encryption key and key block authentication key from key block protection key
	r = tr31_tdes_kbpk_derive(kbpk->data, kbpk->length, kbek, kbak);
	if (r) {
		// return error value as-is
		goto error;
	}

	// generate authenticator
	r = tr31_tdes_cmac(kbak, kbpk->length, decrypted_key_block, sizeof(decrypted_key_block), ctx->authenticator);
	if (r) {
		// return error value as-is
		goto error;
	}

	// encrypt key payload; note that the authenticator is used as the IV
	r = tr31_tdes_encrypt_cbc(kbek, kbpk->length, ctx->authenticator, decrypted_payload, ctx->payload_length, ctx->payload);
	if (r) {
		// return error value as-is
		goto error;
	}

	// success
	r = 0;
	goto exit;

error:
exit:
	// cleanse sensitive buffers
	tr31_cleanse(kbek, sizeof(kbek));
	tr31_cleanse(kbak, sizeof(kbak));
	tr31_cleanse(decrypted_key_block, sizeof(decrypted_key_block));

	return r;
}

static int tr31_aes_decrypt_verify_derivation_binding(struct tr31_ctx_t* ctx, const struct tr31_key_t* kbpk)
{
	int r;
	uint8_t kbek[AES256_KEY_SIZE];
	uint8_t kbak[AES256_KEY_SIZE];

	// buffer for decryption and CMAC verification
	uint8_t decrypted_key_block[ctx->header_length + ctx->payload_length];
	memcpy(decrypted_key_block, ctx->header, ctx->header_length);
	struct tr31_payload_t* decrypted_payload = (struct tr31_payload_t*)(decrypted_key_block + ctx->header_length);

	// derive key block encryption key and key block authentication key from key block protection key
	r = tr31_aes_kbpk_derive(kbpk->data, kbpk->length, kbek, kbak);
	if (r) {
		// return error value as-is
		goto error;
	}

	// decrypt key payload; note that the authenticator is used as the IV
	r = tr31_aes_decrypt_cbc(kbek, kbpk->length, ctx->authenticator, ctx->payload, ctx->payload_length, decrypted_payload);
	if (r) {
		// return error value as-is
		goto error;
	}

	// extract payload length field
	ctx->key.length = ntohs(decrypted_payload->length) / 8; // payload length is big endian and in bits, not bytes
	if (ctx->key.length > ctx->payload_length - 2) {
		// invalid key length relative to encrypted payload length
		r = TR31_ERROR_INVALID_KEY_LENGTH;
		goto error;
	}

	// verify authenticator
	r = tr31_aes_verify_cmac(kbak, kbpk->length, decrypted_key_block, sizeof(decrypted_key_block), ctx->authenticator);
	if (r) {
		r = TR31_ERROR_KEY_BLOCK_VERIFICATION_FAILED;
		goto error;
	}

	// extract key data
	ctx->key.data = calloc(1, ctx->key.length);
	memcpy(ctx->key.data, decrypted_payload->data, ctx->key.length);

	// success
	r = 0;
	goto exit;

error:
exit:
	// cleanse sensitive buffers
	tr31_cleanse(kbek, sizeof(kbek));
	tr31_cleanse(kbak, sizeof(kbak));
	tr31_cleanse(decrypted_key_block, sizeof(decrypted_key_block));

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

	if (ctx->header) {
		free(ctx->header);
		ctx->header = NULL;
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
	// see TR-31:2018, A.5.1, table 6
	switch (usage) {
		case TR31_KEY_USAGE_BDK:                return "Base Derivation Key (BDK)";
		case TR31_KEY_USAGE_DUKPT_IPEK:         return "Initial DUKPT Key (IPEK)";
		case TR31_KEY_USAGE_BKV:                return "Base Key Variant";
		case TR31_KEY_USAGE_CVK:                return "Card Verification Key (CVK)";
		case TR31_KEY_USAGE_DATA:               return "Symmetric Data Encryption Key";
		case TR31_KEY_USAGE_ASYMMETRIC_DATA:    return "Asymmetric Data Encryption Key";
		case TR31_KEY_USAGE_DATA_DEC_TABLE:     return "Decimalization Table Data Encryption Key";
		case TR31_KEY_USAGE_EMV_MKAC:           return "EMV/chip Issuer Master Key: Application cryptograms (MKAC)";
		case TR31_KEY_USAGE_EMV_MKSMC:          return "EMV/chip Issuer Master Key: Secure Messaging for Confidentiality (MKSMC)";
		case TR31_KEY_USAGE_EMV_MKSMI:          return "EMV/chip Issuer Master Key: Secure Messaging for Integrity (MKSMI)";
		case TR31_KEY_USAGE_EMV_MKDAC:          return "EMV/chip Issuer Master Key: Data Authentication Code (MKDAC)";
		case TR31_KEY_USAGE_EMV_MKDN:           return "EMV/chip Issuer Master Key: Dynamic Numbers (MKDN)";
		case TR31_KEY_USAGE_EMV_CP:             return "EMV/chip Issuer Master Key: Card Personalization (CP)";
		case TR31_KEY_USAGE_EMV_OTHER:          return "EMV/chip Issuer Master Key: Other";
		case TR31_KEY_USAGE_IV:                 return "Initialization Vector";
		case TR31_KEY_USAGE_KEK:                return "Key Encryption or Wrapping Key (KEK)";
		case TR31_KEY_USAGE_TR31_KBPK:          return "TR-31 Key Block Protection Key (KBPK)";
		case TR31_KEY_USAGE_TR34_KEK:           return "TR-34 Asymmetric Key Exchange Key (KEK)";
		case TR31_KEY_USAGE_ASYMMETRIC_KEK:     return "Asymmetric Key Agreement or Wrapping Key";
		case TR31_KEY_USAGE_ISO16609_MAC_1:     return "ISO 16609 MAC algorithm 1 (using TDES)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_1:    return "ISO 9797-1 MAC Algorithm 1 (CBC-MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_2:    return "ISO 9797-1 MAC Algorithm 2";
		case TR31_KEY_USAGE_ISO9797_1_MAC_3:    return "ISO 9797-1 MAC Algorithm 3 (Retail MAC)";
		case TR31_KEY_USAGE_ISO9797_1_MAC_4:    return "ISO 9797-1 MAC Algorithm 4";
		case TR31_KEY_USAGE_ISO9797_1_MAC_5:    return "ISO 9797-1:1999 MAC Algorithm 5 (legacy)";
		case TR31_KEY_USAGE_ISO9797_1_CMAC:     return "ISO 9797-1:2011 MAC Algorithm 5 (CMAC)";
		case TR31_KEY_USAGE_HMAC:               return "HMAC";
		case TR31_KEY_USAGE_ISO9797_1_MAC_6:    return "ISO 9797-1 MAC Algorithm 6";
		case TR31_KEY_USAGE_PIN:                return "PIN Encryption Key";
		case TR31_KEY_USAGE_ASYMMETRIC_SIG:     return "Asymmetric key pair for digital signature";
		case TR31_KEY_USAGE_ASYMMETRIC_CA:      return "Asymmetric key pair for CA use";
		case TR31_KEY_USAGE_ASYMMETRIC_OTHER:   return "Asymmetric key pair for non-X9.24 use";
		case TR31_KEY_USAGE_PV:                 return "PIN Verification Key (Other)";
		case TR31_KEY_USAGE_PV_IBM3624:         return "PIN Verification Key (IBM 3624)";
		case TR31_KEY_USAGE_PV_VISA:            return "PIN Verification Key (VISA PVV)";
		case TR31_KEY_USAGE_PV_X9_132_1:        return "PIN Verification Key (X9-132 algorithm 1)";
		case TR31_KEY_USAGE_PV_X9_132_2:        return "PIN Verification Key (X9-132 algorithm 2)";
	}

	return "Unknown key usage value";
}

const char* tr31_get_key_algorithm_string(unsigned int algorithm)
{
	// see TR-31:2018, A.5.2, table 7
	switch (algorithm) {
		case TR31_KEY_ALGORITHM_AES:    return "AES";
		case TR31_KEY_ALGORITHM_DES:    return "DES";
		case TR31_KEY_ALGORITHM_EC:     return "Elliptic Curve";
		case TR31_KEY_ALGORITHM_HMAC:   return "HMAC";
		case TR31_KEY_ALGORITHM_RSA:    return "RSA";
		case TR31_KEY_ALGORITHM_DSA:    return "DSA";
		case TR31_KEY_ALGORITHM_TDES:   return "TDES";
	}

	return "Unknown key algorithm value";
}

const char* tr31_get_key_mode_of_use_string(unsigned int mode_of_use)
{
	// see TR-31:2018, A.5.3, table 8
	switch (mode_of_use) {
		case TR31_KEY_MODE_OF_USE_ENC_DEC:      return "Encrypt and Decrypt (Wrap and Unwrap)";
		case TR31_KEY_MODE_OF_USE_MAC:          return "MAC Calculate (Generate and Verify)";
		case TR31_KEY_MODE_OF_USE_DEC:          return "Decrypt / Unwrap Only";
		case TR31_KEY_MODE_OF_USE_ENC:          return "Encrypt / Wrap Only";
		case TR31_KEY_MODE_OF_USE_MAC_GEN:      return "MAC Generate Only";
		case TR31_KEY_MODE_OF_USE_ANY:          return "No special restrictions";
		case TR31_KEY_MODE_OF_USE_SIG:          return "Signature Only";
		case TR31_KEY_MODE_OF_USE_MAC_VERIFY:   return "MAC Verify Only";
		case TR31_KEY_MODE_OF_USE_DERIVE:       return "Key Derivation";
		case TR31_KEY_MODE_OF_USE_VARIANT:      return "Create Key Variants";
	}

	return "Unknown key mode of use value";
}

const char* tr31_get_key_exportability_string(unsigned int exportability)
{
	// see TR-31:2018, A.5.5, table 10
	switch (exportability) {
		case TR31_KEY_EXPORT_TRUSTED:           return "Exportable in a trusted key block only";
		case TR31_KEY_EXPORT_NONE:              return "Not exportable";
		case TR31_KEY_EXPORT_SENSITIVE:         return "Sensitive";
	}

	return "Unknown key exportability value";
}

const char* tr31_get_opt_block_id_ascii(unsigned int opt_block_id, char* ascii, size_t ascii_len)
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
		if (isalnum(opt_block_id_ascii.bytes[i])) {
			ascii[i] = opt_block_id_ascii.bytes[i];
		} else {
			ascii[i] = '?';
		}
	}
	ascii[2] = 0;

	return ascii;
}

const char* tr31_get_opt_block_id_string(unsigned int opt_block_id)
{
	// see TR-31:2018, A.5.6, table 11
	switch (opt_block_id) {
		case TR31_OPT_BLOCK_CT:         return "Public Key Certificate";
		case TR31_OPT_BLOCK_HM:         return "HMAC hash algorithm";
		case TR31_OPT_BLOCK_IK:         return "Initial Key Identifier";
		case TR31_OPT_BLOCK_KC:         return "Key Check Value (KCV) of wrapped key";
		case TR31_OPT_BLOCK_KP:         return "Key Check Value (KCV) of KBPK";
		case TR31_OPT_BLOCK_KS:         return "Key Set Identifier";
		case TR31_OPT_BLOCK_KV:         return "Key Block Values";
		case TR31_OPT_BLOCK_PB:         return "Padding Block";
		case TR31_OPT_BLOCK_TS:         return "Time Stamp";
	}

	return "Unknown";
}

const char* tr31_get_opt_block_data_string(const struct tr31_opt_ctx_t* opt_block)
{
	if (!opt_block) {
		return NULL;
	}

	switch (opt_block->id) {
		case TR31_OPT_BLOCK_KC: return tr31_get_opt_block_kcv_string(opt_block);
		case TR31_OPT_BLOCK_KP: return tr31_get_opt_block_kcv_string(opt_block);
		case TR31_OPT_BLOCK_HM: return tr31_get_opt_block_hmac_string(opt_block);
	}

	return NULL;
}

static const char* tr31_get_opt_block_kcv_string(const struct tr31_opt_ctx_t* opt_block)
{
	const uint8_t* data;

	if (!opt_block ||
		opt_block->data_length < 2
	) {
		return NULL;
	}
	if (opt_block->id != TR31_OPT_BLOCK_KC &&
		opt_block->id != TR31_OPT_BLOCK_KP
	) {
		return NULL;
	}
	data = opt_block->data;

	// see TR-31:2018, A.5.8
	switch (data[0]) {
		case TR31_OPT_BLOCK_KCV_LEGACY:         return "Legacy KCV algorithm";
		case TR31_OPT_BLOCK_KCV_CMAC:           return "CMAC based KCV";
	}

	return "Unknown";
}

static const char* tr31_get_opt_block_hmac_string(const struct tr31_opt_ctx_t* opt_block)
{
	const uint8_t* data;

	if (!opt_block ||
		opt_block->id != TR31_OPT_BLOCK_HM ||
		opt_block->data_length != 1
	) {
		return NULL;
	}
	data = opt_block->data;

	// see TR-31:2018, A.5.9
	switch (data[0]) {
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
	}

	return "Unknown";
}
