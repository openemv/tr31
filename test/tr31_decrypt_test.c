/**
 * @file tr31_decrypt_test.c
 *
 * Copyright (c) 2020, 2021, 2022 Leon Lynch
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

// example data generated using a Thales payShield 10k HSM
static const uint8_t test1_kbpk[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };
static const char test1_tr31_format_a[] = "A0072K0TN00N0000F40D5672C6D0EC86F860BA88D44D00F0CA9A8CE8CD2F640287A9A9EB";
static const char test1_tr31_format_b[] = "B0080K0TN00N00001C414014375212C24995E405B5EE052CB92B67F455EA2680F6751088F9F1C228";
static const char test1_tr31_format_c[] = "C0072K0TN00N0000C9B875FF7A5316BF221C09ED52080DE0B45632A4EA9CE87699CB565E";
static const uint8_t test1_tr31_key_verify[] = { 0x5D, 0xB5, 0x0B, 0x45, 0x4F, 0x83, 0x89, 0xAD, 0xCE, 0x57, 0x3B, 0xE5, 0x08, 0x61, 0xF2, 0xBF };
static const uint8_t test1_tr31_kcv_verify[] = { 0x5C, 0x94, 0x05 };

// TR-31:2018, A.7.2.1
static const uint8_t test2_kbpk[] = { 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C };
static const char test2_tr31_ascii[] = "A0072P0TE00E0000F5161ED902807AF26F1D62263644BD24192FDB3193C730301CEE8701";
static const uint8_t test2_tr31_key_verify[] = { 0xF0, 0x39, 0x12, 0x1B, 0xEC, 0x83, 0xD2, 0x6B, 0x16, 0x9B, 0xDC, 0xD5, 0xB2, 0x2A, 0xAF, 0x8F };
static const uint8_t test2_tr31_kcv_verify[] = { 0xCB, 0x9D, 0xEA };

// TR-31:2018, A.7.2.2
static const uint8_t test3_kbpk[] = { 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 };
static const char test3_tr31_ascii[] = "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E";
static const uint8_t test3_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test3_tr31_kcv_verify[] = { 0x57, 0xC4, 0x09 };

// TR-31:2018, A.7.3.1
static const uint8_t test4_kbpk[] = { 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 };
static const char test4_tr31_ascii[] = "C0096B0TX12S0100KS1800604B120F9292800000BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D60989015D02155C";
static const uint8_t test4_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test4_tr31_key_verify[] = { 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 };
static const uint8_t test4_tr31_kcv_verify[] = { 0xF4, 0xB0, 0x8D };

// TR-31:2018, A.7.3.2
static const uint8_t test5_kbpk[] = { 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC };
static const char test5_tr31_ascii[] = "B0104B0TX12S0100KS1800604B120F9292800000BB68BE8680A400D9191AD4ECE45B6E6C0D21C4738A52190E248719E24B433627";
static const uint8_t test5_tr31_ksn_verify[] = { 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 };
static const uint8_t test5_tr31_key_verify[] = { 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 };
static const uint8_t test5_tr31_kcv_verify[] = { 0x9A, 0x42, 0x12 };

// TR-31:2018, A.7.4
static const uint8_t test6_kbpk[] = {
	0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
	0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
};
static const char test6_tr31_ascii[] = "D0112P0AE00E0000B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A27E8E31DA05F7425509593D03A457DC34";
static const uint8_t test6_tr31_key_verify[] = { 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 };
static const uint8_t test6_tr31_kcv_verify[] = { 0x08, 0x79, 0x3E };

// example data generated using a Thales payShield 10k HSM
static const uint8_t test7_kbpk[] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};
static const char test7_tr31_ascii[] = "D0112B0TN00N000037DB9B046B7B0048785690759580ABC3B9842AB4BB7717B49E92528E575785D8123559376A2553B27BE94F054F4E971C";
static const uint8_t test7_tr31_key_verify[] = { 0x1F, 0xA1, 0xF7, 0xCE, 0xC7, 0x98, 0xD9, 0x15, 0x45, 0xDA, 0x8A, 0xE0, 0xC7, 0x79, 0x6B, 0xD9 };
static const uint8_t test7_tr31_kcv_verify[] = { 0xFF, 0x50, 0x87 };

// example data generated using a Thales payShield 10k HSM
static const uint8_t test8_kbpk[] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};
static const char test8_tr31_ascii[] = "D0144D0AN00N0000127862F945C2DED04530FAF7CDBC8B0BA10C7AA79BD5E0C2C5D6AC173BF588E4B19ACF1357178D50EA0AB193228E13958304FC6149632DFDCADF3A5B3D57E814";
static const uint8_t test8_tr31_key_verify[] = {
	0xBE, 0x19, 0xE6, 0xA0, 0x7A, 0x76, 0x0F, 0x10, 0xEF, 0x8E, 0x83, 0xA2, 0x26, 0xB6, 0x3A, 0xAD,
	0x14, 0x1F, 0x46, 0x3F, 0xDD, 0xD4, 0xF4, 0x7D, 0xB2, 0x44, 0xB4, 0x02, 0x3E, 0xC3, 0xCA, 0xCC,
};
static const uint8_t test8_tr31_kcv_verify[] = { 0x0A, 0x00, 0xE3 };

// ISO 20038:2017, B.2
static const uint8_t test9_kbpk[] = {
	0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
};
static const char test9_tr31_ascii[] = "E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A52DB52F0AEACB94C57547";
static const uint8_t test9_tr31_key_verify[] = {
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79,
};
static const uint8_t test9_tr31_kcv_verify[] = { 0xB2, 0x9D, 0x42 };

// ISO 20038:2017, B.3
static const uint8_t test10_kbpk[] = {
	0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
};
static const char test10_tr31_ascii[] = "D0112M3TV16N000018462FA5903B8D2B82FEE26B29713C0BE7ED81601087F12252093D06FC0A012C1CF769AD0E3E9E4877166AB013FC22B4";
static const uint8_t test10_tr31_key_verify[] = {
	// ISO 20038:2017, B.3 provides this is the wrapped key, but it doesn't match the input data...
	//0x76, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79,

	// ISO 20038:2017, B.3 MAC input data shows that this is the wrapped key...
	0x76, 0x73, 0x61, 0x70, 0x70, 0x64, 0x64, 0x20, 0x32, 0x45, 0x45, 0x52, 0x20, 0x6B, 0x64, 0x79,
};
static const uint8_t test10_tr31_kcv_verify[] = { 0xB2, 0x9D, 0x42 };

int main(void)
{
	int r;
	struct tr31_key_t test_kbpk;
	struct tr31_ctx_t test_tr31;

	// populate key block protection key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test1_kbpk);
	test_kbpk.data = (void*)test1_kbpk;

	// test key block decryption for format version A
	r = tr31_import(test1_tr31_format_a, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_A ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
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
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
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
		test_tr31.key.usage != TR31_KEY_USAGE_KEK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test1_tr31_key_verify) ||
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

	// TR-31:2018, A.7.2.1
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test2_kbpk);
	test_kbpk.data = (void*)test2_kbpk;
	r = tr31_import(test2_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_A ||
		test_tr31.length != 72 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PIN ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test2_tr31_key_verify) ||
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

	// TR-31:2018, A.7.2.2
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test3_kbpk);
	test_kbpk.data = (void*)test3_kbpk;
	r = tr31_import(test3_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 80 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PIN ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test3_tr31_key_verify) ||
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
	if (memcmp(test_tr31.key.data, test3_tr31_key_verify, sizeof(test3_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test3_tr31_kcv_verify, sizeof(test3_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.1
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test4_kbpk);
	test_kbpk.data = (void*)test4_kbpk;
	r = tr31_import(test4_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_C ||
		test_tr31.length != 96 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		test_tr31.key.key_version_value != 12 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test4_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data_length != sizeof(test4_tr31_ksn_verify) ||
		test_tr31.opt_blocks[0].data == NULL ||
		memcmp(test_tr31.opt_blocks[0].data, test4_tr31_ksn_verify, sizeof(test4_tr31_ksn_verify)) != 0 ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 4 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test4_tr31_key_verify, sizeof(test4_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test4_tr31_kcv_verify, sizeof(test4_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.3.2
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test5_kbpk);
	test_kbpk.data = (void*)test5_kbpk;
	r = tr31_import(test5_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_B ||
		test_tr31.length != 104 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_DERIVE||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		test_tr31.key.key_version_value != 12 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_SENSITIVE ||
		test_tr31.key.length != sizeof(test5_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 1 ||
		test_tr31.opt_blocks == NULL ||
		test_tr31.opt_blocks[0].id != TR31_OPT_BLOCK_KS ||
		test_tr31.opt_blocks[0].data_length != sizeof(test5_tr31_ksn_verify) ||
		test_tr31.opt_blocks[0].data == NULL ||
		memcmp(test_tr31.opt_blocks[0].data, test5_tr31_ksn_verify, sizeof(test5_tr31_ksn_verify)) != 0 ||
		test_tr31.payload_length != 24 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 8 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test5_tr31_key_verify, sizeof(test5_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test5_tr31_kcv_verify, sizeof(test5_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// TR-31:2018, A.7.4
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test6_kbpk);
	test_kbpk.data = (void*)test6_kbpk;
	r = tr31_import(test6_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_PIN ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ENC ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_TRUSTED ||
		test_tr31.key.length != sizeof(test6_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 32 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 16 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test6_tr31_key_verify, sizeof(test6_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test6_tr31_kcv_verify, sizeof(test6_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version D containing TDES key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test7_kbpk);
	test_kbpk.data = (void*)test7_kbpk;
	r = tr31_import(test7_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test7_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 32 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 16 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test7_tr31_key_verify, sizeof(test7_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test7_tr31_kcv_verify, sizeof(test7_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version D containing AES key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test8_kbpk);
	test_kbpk.data = (void*)test8_kbpk;
	r = tr31_import(test8_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 144 ||
		test_tr31.key.usage != TR31_KEY_USAGE_DATA ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_AES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_ANY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_UNUSED ||
		test_tr31.key.key_version_value != 0 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test8_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 48 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 16 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test8_tr31_key_verify, sizeof(test8_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test8_tr31_kcv_verify, sizeof(test8_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version E containing TDES key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test9_kbpk);
	test_kbpk.data = (void*)test9_kbpk;
	r = tr31_import(test9_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_E ||
		test_tr31.length != 84 ||
		test_tr31.key.usage != TR31_KEY_USAGE_BDK ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_MAC_VERIFY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		test_tr31.key.key_version_value != 16 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test9_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 18 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 16 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test9_tr31_key_verify, sizeof(test9_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test9_tr31_kcv_verify, sizeof(test9_tr31_kcv_verify)) != 0) {
		fprintf(stderr, "TR-31 key data KCV is incorrect\n");
		r = 1;
		goto exit;
	}
	tr31_release(&test_tr31);

	// test key block decryption for format version D containing TDES key
	memset(&test_kbpk, 0, sizeof(test_kbpk));
	test_kbpk.usage = TR31_KEY_USAGE_KEK;
	test_kbpk.algorithm = TR31_KEY_ALGORITHM_AES;
	test_kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	test_kbpk.length = sizeof(test10_kbpk);
	test_kbpk.data = (void*)test10_kbpk;
	r = tr31_import(test10_tr31_ascii, &test_kbpk, &test_tr31);
	if (r) {
		fprintf(stderr, "tr31_import() failed; r=%d\n", r);
		goto exit;
	}
	if (test_tr31.version != TR31_VERSION_D ||
		test_tr31.length != 112 ||
		test_tr31.key.usage != TR31_KEY_USAGE_ISO9797_1_MAC_3 ||
		test_tr31.key.algorithm != TR31_KEY_ALGORITHM_TDES ||
		test_tr31.key.mode_of_use != TR31_KEY_MODE_OF_USE_MAC_VERIFY ||
		test_tr31.key.key_version != TR31_KEY_VERSION_IS_VALID ||
		test_tr31.key.key_version_value != 16 ||
		test_tr31.key.exportability != TR31_KEY_EXPORT_NONE ||
		test_tr31.key.length != sizeof(test10_tr31_key_verify) ||
		test_tr31.key.data == NULL ||
		test_tr31.opt_blocks_count != 0 ||
		test_tr31.opt_blocks != NULL ||
		test_tr31.payload_length != 32 ||
		test_tr31.payload == NULL ||
		test_tr31.authenticator_length != 16 ||
		test_tr31.authenticator == NULL
	) {
		fprintf(stderr, "TR-31 context is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.data, test10_tr31_key_verify, sizeof(test10_tr31_key_verify)) != 0) {
		fprintf(stderr, "TR-31 key data is incorrect\n");
		r = 1;
		goto exit;
	}
	if (memcmp(test_tr31.key.kcv, test10_tr31_kcv_verify, sizeof(test10_tr31_kcv_verify)) != 0) {
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
