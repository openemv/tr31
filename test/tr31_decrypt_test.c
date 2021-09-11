/**
 * @file tr31_decrypt_test.c
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t test_kbpk_data[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };

static const char test1_tr31_format_a[] = "A0072K0TN00N0000F40D5672C6D0EC86F860BA88D44D00F0CA9A8CE8CD2F640287A9A9EB";
static const char test1_tr31_format_b[] = "B0080K0TN00N00001C414014375212C24995E405B5EE052CB92B67F455EA2680F6751088F9F1C228";
static const char test1_tr31_format_c[] = "C0072K0TN00N0000C9B875FF7A5316BF221C09ED52080DE0B45632A4EA9CE87699CB565E";
static const uint8_t test1_tr31_key_verify[] = { 0x5D, 0xB5, 0x0B, 0x45, 0x4F, 0x83, 0x89, 0xAD, 0xCE, 0x57, 0x3B, 0xE5, 0x08, 0x61, 0xF2, 0xBF };
static const uint8_t test1_tr31_kcv_verify[] = { 0x5C, 0x94, 0x05 };

static const char test2_tr31_format_b[] = "B0080K0TN00E00004C80841B66EA4C638AA70226B5857A1A5F310533A249562C316B2491C05BF802";
static const uint8_t test2_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test2_tr31_kcv_verify[] = { 0x57, 0xC4, 0x09 };

int main(void)
{
	int r;
	struct tr31_key_t test_kbpk;
	struct tr31_ctx_t test_tr31;

	// populate key block protection key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEY;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test_kbpk_data);
	test_kbpk.data = (void*)test_kbpk_data;

	// test key block decryption for format version A
	r = tr31_import(test1_tr31_format_a, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_A ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEY ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != 16 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 4 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version B
	r = tr31_import(test1_tr31_format_b, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 80 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEY ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != 16 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 8 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version C
	r = tr31_import(test1_tr31_format_c, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_C ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEY ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != 16 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 4 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test1_tr31_key_verify, sizeof(test1_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test1_tr31_kcv_verify, sizeof(test1_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version B
	r = tr31_import(test2_tr31_format_b, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 80 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEY ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != 16 ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 8 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test2_tr31_key_verify, sizeof(test2_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test2_tr31_kcv_verify, sizeof(test2_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
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
