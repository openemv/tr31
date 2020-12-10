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
//static const uint8_t test_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };

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
	test_kbpk.data = test_kbpk_data;

	// test key block decryption
	r = tr31_import(test_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}

	// TODO: verify key

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
