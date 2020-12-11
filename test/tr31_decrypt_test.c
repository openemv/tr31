/**
 * @file tr31_decrypt_test.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t test_kbpk_data[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };
static const char test_tr31_ascii[] = "B0080K0TN00E00004C80841B66EA4C638AA70226B5857A1A5F310533A249562C316B2491C05BF802";
static const uint8_t test_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };

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

	// test key block decryption
	r = tr31_import(test_tr31_ascii, &test_kbpk, &test_tr31);
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
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 8 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test_tr31_key_verify, sizeof(test_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
