/**
 * @file tr31_decode_test.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31.h"

#include <stdio.h>

static const char test_key_block[] = "B0104B1TX00S0100KS18820220A0200001E00000B51725B5DD1F18D7A28B3EBD15BA8DE978DC20E5FA695FEAA249855AA226C65F";

int main(void)
{
	int r;
	struct tr31_info_t tr31_info;

	r = tr31_decode(test_key_block, &tr31_info);
	if (r) {
		fprintf(stderr, "tr31_decode() failed; r=%d\n", r);
		goto exit;
	}
	if (tr31_info.version != TR31_VERSION_B ||
		tr31_info.length != 104 ||
		tr31_info.key_usage != TR31_KEY_USAGE_DUKPT_IPEK ||
		tr31_info.algorithm != TR31_ALGORITHM_TDEA ||
		tr31_info.mode_of_use != TR31_MODE_OF_USE_DERIVE ||
		tr31_info.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		tr31_info.key_version_value != 0 ||
		tr31_info.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		tr31_info.opt_blocks_count != 1
	) {
		fprintf(stderr, "tr31_info is incorrect\n");
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
