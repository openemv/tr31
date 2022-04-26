/**
 * @file tr31_export_test.c
 *
 * Copyright (c) 2021, 2022 Leon Lynch
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

// TR-31:2018, A.7.2.1
static const uint8_t test1_kbpk_raw[] = { 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C };
static struct tr31_key_t test1_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test1_key_raw[] = { 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 };
static const struct tr31_key_t test1_key = {
	.usage = TR31_KEY_USAGE_PIN,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
	.key_version = TR31_KEY_VERSION_IS_UNUSED,
	.exportability = TR31_KEY_EXPORT_TRUSTED,
	.length = sizeof(test1_key_raw),
	.data = (void*)test1_key_raw,
};
static const char test1_tr31_header_verify[] = "A0072P0TE00E0000";
static const size_t test1_tr31_length_verify =
	16 /* header */
	+ 0 /* opt block */
	+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
	+ (4 /* authenticator */) * 2;

// TR-31:2018, A.7.3.2
static const uint8_t test2_kbpk_raw[] = { 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC };
static struct tr31_key_t test2_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test2_key_raw[] = { 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 };
static const struct tr31_key_t test2_key = {
	.usage = TR31_KEY_USAGE_BDK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
	.key_version = TR31_KEY_VERSION_IS_VALID,
	.key_version_value = 12,
	.exportability = TR31_KEY_EXPORT_SENSITIVE,
	.length = sizeof(test2_key_raw),
	.data = (void*)test2_key_raw,
};
static const uint8_t test2_ksn[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const char test2_tr31_header_verify[] = "B0104B0TX12S0100KS1800604B120F9292800000";
static const size_t test2_tr31_length_verify =
	16 /* header */
	+ 24 /* opt block */
	+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
	+ (8 /* authenticator */) * 2;

// TR-31:2018, A.7.3.1
static const uint8_t test3_kbpk_raw[] = { 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 };
static struct tr31_key_t test3_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test3_key_raw[] = { 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 };
static const struct tr31_key_t test3_key = {
	.usage = TR31_KEY_USAGE_BDK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
	.key_version = TR31_KEY_VERSION_IS_VALID,
	.key_version_value = 12,
	.exportability = TR31_KEY_EXPORT_SENSITIVE,
	.length = sizeof(test3_key_raw),
	.data = (void*)test3_key_raw,
};
static const uint8_t test3_ksn[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const char test3_tr31_header_verify[] = "C0096B0TX12S0100KS1800604B120F9292800000";
static const size_t test3_tr31_length_verify =
	16 /* header */
	+ 24 /* opt block */
	+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
	+ (4 /* authenticator */) * 2;

// TR-31:2018, A.7.4
static const uint8_t test4_kbpk_raw[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static struct tr31_key_t test4_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_AES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test4_key_raw[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const struct tr31_key_t test4_key = {
	.usage = TR31_KEY_USAGE_PIN,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
	.key_version = TR31_KEY_VERSION_IS_UNUSED,
	.exportability = TR31_KEY_EXPORT_TRUSTED,
	.length = sizeof(test4_key_raw),
	.data = (void*)test4_key_raw,
};
static const char test4_tr31_header_verify[] = "D0144P0TE00E0300KC0C0057C409KP10012331550BC9PB04";
static const size_t test4_tr31_length_verify =
	16 /* header */
	+ 12 /* opt block KC */ + 16 /* opt block KP */ + 4 /* opt block PB */
	+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
	+ (16 /* authenticator */) * 2;

// unfortunately no official TR-31:2018 HMAC test vectors are available
// so here is a hand crafted one (which may be wrong)
static const uint8_t test5_kbpk_raw[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static struct tr31_key_t test5_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_AES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test5_key_raw[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const struct tr31_key_t test5_key = {
	.usage = TR31_KEY_USAGE_HMAC,
	.algorithm = TR31_KEY_ALGORITHM_HMAC,
	.mode_of_use = TR31_KEY_MODE_OF_USE_MAC,
	.key_version = TR31_KEY_VERSION_IS_VALID,
	.key_version_value = 12,
	.exportability = TR31_KEY_EXPORT_NONE,
	.length = sizeof(test5_key_raw),
	.data = (void*)test5_key_raw,
};
static const char test5_tr31_header_verify[] = "D0128M7HC12N0200HM0621PB0A000000";
static const size_t test5_tr31_length_verify =
	16 /* header */
	+ 6 /* opt block HM */ + 10 /* opt block PB */
	+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
	+ (16 /* authenticator */) * 2;

// ISO 20038:2017, B.2
static const uint8_t test6_kbpk_raw[] = {
	0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
};
static struct tr31_key_t test6_kbpk = {
	.usage = TR31_KEY_USAGE_TR31_KBPK,
	.algorithm = TR31_KEY_ALGORITHM_AES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
	.length = 0,
	.data = NULL,
};
static const uint8_t test6_key_raw[] = {
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79,
};
static const struct tr31_key_t test6_key = {
	.usage = TR31_KEY_USAGE_BDK,
	.algorithm = TR31_KEY_ALGORITHM_TDES,
	.mode_of_use = TR31_KEY_MODE_OF_USE_MAC_VERIFY,
	.key_version = TR31_KEY_VERSION_IS_VALID,
	.key_version_value = 16,
	.exportability = TR31_KEY_EXPORT_NONE,
	.length = sizeof(test6_key_raw),
	.data = (void*)test6_key_raw,
};
static const char test6_tr31_verify[] = "E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A52DB52F0AEACB94C57547";

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(void)
{
	int r;
	struct tr31_ctx_t test_tr31;
	char key_block[1024];

	// TR-31:2018, A.7.2.1
	printf("Test 1...\n");
	print_buf("key", test1_key.data, test1_key.length);
	r = tr31_init(TR31_VERSION_A, &test1_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test1_kbpk_raw, sizeof(test1_kbpk_raw));
	r = tr31_key_set_data(&test1_kbpk, test1_kbpk_raw, sizeof(test1_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test1_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strncmp(key_block, test1_tr31_header_verify, strlen(test1_tr31_header_verify)) != 0) {
		fprintf(stderr, "TR-31 header encoding is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test1_tr31_header_verify);
		r = 1;
		goto exit;
	}
	if (strlen(key_block) != test1_tr31_length_verify) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test1_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test1_key_raw) ||
		memcmp(test_tr31.key.data, test1_key_raw, sizeof(test1_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test1_key_raw, sizeof(test1_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.2
	printf("Test 2...\n");
	print_buf("key", test2_key.data, test2_key.length);
	r = tr31_init(TR31_VERSION_B, &test2_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}
	r = tr31_opt_block_add(
		&test_tr31,
		TR31_OPT_BLOCK_KS,
		test2_ksn,
		sizeof(test2_ksn)
	);
	if (r) {
		fprintf(stderr, "tr31_opt_block_add() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test2_kbpk_raw, sizeof(test2_kbpk_raw));
	r = tr31_key_set_data(&test2_kbpk, test2_kbpk_raw, sizeof(test2_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test2_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strncmp(key_block, test2_tr31_header_verify, strlen(test2_tr31_header_verify)) != 0) {
		fprintf(stderr, "TR-31 header encoding is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test2_tr31_header_verify);
		r = 1;
		goto exit;
	}
	if (strlen(key_block) != test2_tr31_length_verify) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test2_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test2_key_raw) ||
		memcmp(test_tr31.key.data, test2_key_raw, sizeof(test2_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test2_key_raw, sizeof(test2_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.1
	printf("Test 3...\n");
	print_buf("key", test3_key.data, test3_key.length);
	r = tr31_init(TR31_VERSION_C, &test3_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}
	r = tr31_opt_block_add(
		&test_tr31,
		TR31_OPT_BLOCK_KS,
		test3_ksn,
		sizeof(test3_ksn)
	);
	if (r) {
		fprintf(stderr, "tr31_opt_block_add() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test3_kbpk_raw, sizeof(test3_kbpk_raw));
	r = tr31_key_set_data(&test3_kbpk, test3_kbpk_raw, sizeof(test3_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test3_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strncmp(key_block, test3_tr31_header_verify, strlen(test3_tr31_header_verify)) != 0) {
		fprintf(stderr, "TR-31 header encoding is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test3_tr31_header_verify);
		r = 1;
		goto exit;
	}
	if (strlen(key_block) != test3_tr31_length_verify) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test3_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test3_key_raw) ||
		memcmp(test_tr31.key.data, test3_key_raw, sizeof(test3_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test3_key_raw, sizeof(test3_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.4
	printf("Test 4...\n");
	print_buf("key", test4_key.data, test4_key.length);
	r = tr31_init(TR31_VERSION_D, &test4_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}
	r = tr31_opt_block_add_KC(&test_tr31);
	if (r) {
		fprintf(stderr, "tr31_opt_block_add_KC() failed; r=%d\n", r);
		goto exit;
	}
	r = tr31_opt_block_add_KP(&test_tr31);
	if (r) {
		fprintf(stderr, "tr31_opt_block_add_KP() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test4_kbpk_raw, sizeof(test4_kbpk_raw));
	r = tr31_key_set_data(&test4_kbpk, test4_kbpk_raw, sizeof(test4_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test4_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strncmp(key_block, test4_tr31_header_verify, strlen(test4_tr31_header_verify)) != 0) {
		fprintf(stderr, "TR-31 header encoding is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test4_tr31_header_verify);
		r = 1;
		goto exit;
	}
	if (strlen(key_block) != test4_tr31_length_verify) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test4_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test4_key_raw) ||
		memcmp(test_tr31.key.data, test4_key_raw, sizeof(test4_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test4_key_raw, sizeof(test4_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// unfortunately no official TR-31:2018 HMAC test vectors are available
	// so here is a hand crafted one (which may be wrong)
	printf("Test 5...\n");
	print_buf("key", test5_key.data, test5_key.length);
	r = tr31_init(TR31_VERSION_D, &test5_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}
	r = tr31_opt_block_add_HM(&test_tr31, TR31_OPT_BLOCK_HM_SHA256);
	if (r) {
		fprintf(stderr, "tr31_opt_block_add_HM() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test5_kbpk_raw, sizeof(test5_kbpk_raw));
	r = tr31_key_set_data(&test5_kbpk, test5_kbpk_raw, sizeof(test5_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test5_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strncmp(key_block, test5_tr31_header_verify, strlen(test5_tr31_header_verify)) != 0) {
		fprintf(stderr, "TR-31 header encoding is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test5_tr31_header_verify);
		r = 1;
		goto exit;
	}
	if (strlen(key_block) != test5_tr31_length_verify) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test5_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test5_key_raw) ||
		memcmp(test_tr31.key.data, test5_key_raw, sizeof(test5_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test5_key_raw, sizeof(test5_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// ISO 20038:2017, B.2
	// Without padding, format version E is deterministic and the exported
	// key block can be verified using a sample from ISO 20038:2017
	printf("Test 6...\n");
	print_buf("key", test6_key.data, test6_key.length);
	r = tr31_init(TR31_VERSION_E, &test6_key, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		goto exit;
	}

	print_buf("kbpk", test6_kbpk_raw, sizeof(test6_kbpk_raw));
	r = tr31_key_set_data(&test6_kbpk, test6_kbpk_raw, sizeof(test6_kbpk_raw));
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		goto exit;
	}

	r = tr31_export(&test_tr31, &test6_kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "tr31_export() failed; r=%d\n", r);
		goto exit;
	}
	printf("TR-31: %s\n", key_block);
	if (strlen(key_block) != strlen(test6_tr31_verify)) {
		fprintf(stderr, "TR-31 length is incorrect\n");
		r = 1;
		goto exit;
	}
	if (strncmp(key_block, test6_tr31_verify, strlen(test6_tr31_verify)) != 0) {
		fprintf(stderr, "TR-31 key block is incorrect\n");
		fprintf(stderr, "%s\n%s\n", key_block, test6_tr31_verify);
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// Verify and decrypt key block
	r = tr31_import(key_block, &test6_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.key.length != sizeof(test6_key_raw) ||
		memcmp(test_tr31.key.data, test6_key_raw, sizeof(test6_key_raw)) != 0)
	{
		fprintf(stderr, "Key verification failed\n");
		print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
		print_buf("expected", test6_key_raw, sizeof(test6_key_raw));
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	tr31_key_release(&test1_kbpk);
	tr31_key_release(&test2_kbpk);
	tr31_key_release(&test3_kbpk);
	tr31_key_release(&test4_kbpk);
	tr31_key_release(&test5_kbpk);
	tr31_key_release(&test6_kbpk);
	return r;
}
