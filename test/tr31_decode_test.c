/**
 * @file tr31_decode_test.c
 *
 * Copyright (c) 2020, 2021, 2022, 2023 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "tr31.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char test1_tr31_ascii[] = "B0104B1TX00S0100KS18820220A0200001E00000B51725B5DD1F18D7A28B3EBD15BA8DE978DC20E5FA695FEAA249855AA226C65F";
static const uint8_t test1_ksn_verify[] = { 0x82, 0x02, 0x20, 0xA0, 0x20, 0x00, 0x01, 0xE0, 0x00, 0x00 };

static const char test2_tr31_ascii[] = "D0112B0TN00N000037DB9B046B7B0048785690759580ABC3B9842AB4BB7717B49E92528E575785D8123559376A2553B27BE94F054F4E971C";

static const char test3_tr31_ascii[] = "D0144D0AN00N0000127862F945C2DED04530FAF7CDBC8B0BA10C7AA79BD5E0C2C5D6AC173BF588E4B19ACF1357178D50EA0AB193228E13958304FC6149632DFDCADF3A5B3D57E814";

static const char test4_tr31_ascii[] = "B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5";
static const uint8_t test4_ksn_verify[] = { 0xFF, 0xFF, 0x00, 0xA0, 0x20, 0x00, 0x01, 0xE0, 0x00, 0x00 };
static const uint8_t test4_kcv_verify[] = { 0x01, 0x69, 0xE3 };
static const uint8_t test4_kcv_kbpk_verify[] = { 0xEC, 0xAD, 0x62 };

int main(void)
{
	int r;
	struct tr31_ctx_t test_tr31;
	const struct tr31_opt_ctx_t* opt_ctx;
	uint8_t tmp[32];
	struct tr31_opt_blk_kcv_data_t kcv_data;

	// test key block decoding for format version B with optional block KS
	printf("Test 1 (Format version B with optional block KS)...\n");
	r = tr31_import(test1_tr31_ascii, strlen(test1_tr31_ascii), NULL, 0, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 104 ||
		test_tr31.key.usage != TR31_KEY_USAGE_DUKPT_IK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.key_context != TR31_KEY_CONTEXT_NONE ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test1_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(tmp, 0, sizeof(tmp));
	r = tr31_opt_block_decode_KS(opt_ctx, tmp, sizeof(test1_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(tmp, test1_ksn_verify, sizeof(test1_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decoding for format version D containing TDES key
	printf("Test 2 (Format version D containing TDES key)...\n");
	r = tr31_import(test2_tr31_ascii, strlen(test2_tr31_ascii), NULL, 0, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.key_context != TR31_KEY_CONTEXT_NONE ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decoding for format version D containing AES key
	printf("Test 3 (Format version D containing AES key)...\n");
	r = tr31_import(test3_tr31_ascii, strlen(test3_tr31_ascii), NULL, 0, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 144 ||
		test_tr31.key.usage != TR31_KEY_USAGE_DATA ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.key_context != TR31_KEY_CONTEXT_NONE ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decoding for format version B with optional blocks KS, KC, and KP
	printf("Test 4 (Format version B with optional block KS, KC, KP)...\n");
	r = tr31_import(test4_tr31_ascii, strlen(test4_tr31_ascii), NULL, 0, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 128 ||
		test_tr31.key.usage != TR31_KEY_USAGE_DUKPT_IK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_str[0] != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.key_context != TR31_KEY_CONTEXT_NONE ||
		test_tr31.opt_blocks_count != 3 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data == NULL ||
		test_tr31.opt_blocks[1].id != TR31_OPT_BLOCK_KC ||
		test_tr31.opt_blocks[1].data == NULL ||
		test_tr31.opt_blocks[2].id != TR31_OPT_BLOCK_KP ||
		test_tr31.opt_blocks[2].data == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KS);
	if (opt_ctx != &test_tr31.opt_blocks[0]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != sizeof(test4_ksn_verify) * 2) {
		fprintf(stderr, "TR-31 optional block KS data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(tmp, 0, sizeof(tmp));
	r = tr31_opt_block_decode_KS(opt_ctx, tmp, sizeof(test4_ksn_verify));
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KS() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(tmp, test4_ksn_verify, sizeof(test4_ksn_verify)) != 0) {
		fprintf(stderr, "TR-31 optional block KS decoded data is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KC);
	if (opt_ctx != &test_tr31.opt_blocks[1]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != (sizeof(test4_kcv_verify) + 1) * 2) {
		fprintf(stderr, "TR-31 optional block KC data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(&kcv_data, 0, sizeof(kcv_data));
	r = tr31_opt_block_decode_KC(opt_ctx, &kcv_data);
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KC() failed; r=%d\n", r);
		goto exit;
	}
	if (kcv_data.kcv_algorithm != TR31_OPT_BLOCK_KCV_LEGACY) {
		fprintf(stderr, "TR-31 optional block KC algorithm is incorrect\n");
		r = 1;
		goto exit;
	}
	if (kcv_data.kcv_len != sizeof(test4_kcv_verify) ||
		memcmp(kcv_data.kcv, test4_kcv_verify, sizeof(test4_kcv_verify)) != 0
	) {
		fprintf(stderr, "TR-31 optional block KC data is incorrect\n");
		r = 1;
		goto exit;
	}
	opt_ctx = tr31_opt_block_find(&test_tr31, TR31_OPT_BLOCK_KP);
	if (opt_ctx != &test_tr31.opt_blocks[2]) {
		fprintf(stderr, "tr31_opt_block_find() failed; r=%d\n", r);
		r = 1;
		goto exit;
	}
	if (opt_ctx->data_length != (sizeof(test4_kcv_kbpk_verify) + 1) * 2) {
		fprintf(stderr, "TR-31 optional block KP data length is incorrect\n");
		r = 1;
		goto exit;
	}
	memset(&kcv_data, 0, sizeof(kcv_data));
	r = tr31_opt_block_decode_KP(opt_ctx, &kcv_data);
	if (r) {
		fprintf(stderr, "tr31_opt_block_decode_KP() failed; r=%d\n", r);
		goto exit;
	}
	if (kcv_data.kcv_algorithm != TR31_OPT_BLOCK_KCV_LEGACY) {
		fprintf(stderr, "TR-31 optional block KP algorithm is incorrect\n");
		r = 1;
		goto exit;
	}
	if (kcv_data.kcv_len != sizeof(test4_kcv_kbpk_verify) ||
		memcmp(kcv_data.kcv, test4_kcv_kbpk_verify, sizeof(test4_kcv_kbpk_verify)) != 0
	) {
		fprintf(stderr, "TR-31 optional block KP data is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
