/**
 * @file tr31_decode_test.c
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

static const char test_tr31_ascii[] = "B0104B1TX00S0100KS18820220A0200001E00000B51725B5DD1F18D7A28B3EBD15BA8DE978DC20E5FA695FEAA249855AA226C65F";
static const uint8_t test_ksn_verify[] = { 0x82, 0x02, 0x20, 0xA0, 0x20, 0x00, 0x01, 0xE0, 0x00, 0x00 };

int main(void)
{
	int r;
	struct tr31_ctx_t test_tr31;

	r = tr31_decode(test_tr31_ascii, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_decode() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 104 ||
		test_tr31.key_usage != TR31_KEY_USAGE_DUKPT_IPEK ||
		test_tr31.algorithm != TR31_ALGORITHM_TDES ||
		test_tr31.mode_of_use != TR31_MODE_OF_USE_DERIVE ||
		test_tr31.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key_version_value != 0 ||
		test_tr31.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_HDR_BLOCK_KS ||
		test_tr31.opt_blocks[0].data_length != sizeof(test_ksn_verify) ||
		test_tr31.opt_blocks[0].data == NULL ||
		memcmp(test_tr31.opt_blocks[0].data, test_ksn_verify, sizeof(test_ksn_verify)) != 0 ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 8 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
