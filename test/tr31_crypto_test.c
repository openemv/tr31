/**
 * @file tr31_crypto_test.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t test_kbpk[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };
static const uint8_t test_kbek_variant_verify[] = { 0xAA, 0xA5, 0xC0, 0x7E, 0x60, 0x2E, 0x1D, 0x78, 0xC3, 0xCA, 0x60, 0x59, 0xAC, 0xDB, 0xE4, 0x9C };
static const uint8_t test_kbak_variant_verify[] = { 0xA2, 0xAD, 0xC8, 0x76, 0x68, 0x26, 0x15, 0x70, 0xCB, 0xC2, 0x68, 0x51, 0xA4, 0xD3, 0xEC, 0x94 };
static const uint8_t test_kbek_derive_verify[] = { 0x60, 0xC1, 0x7C, 0x9B, 0x43, 0x02, 0x01, 0x23, 0xC1, 0x60, 0x40, 0xCC, 0xDC, 0xBC, 0x76, 0xF1 };
static const uint8_t test_kbak_derive_verify[] = { 0x8A, 0x15, 0x42, 0xBD, 0x19, 0xE8, 0xC0, 0x81, 0x24, 0x2A, 0x14, 0x31, 0x76, 0xE7, 0x45, 0xB8 };

int main(void)
{
	int r;
	uint8_t test_kbek[sizeof(test_kbpk)];
	uint8_t test_kbak[sizeof(test_kbpk)];

	r = tr31_tdes_kbpk_variant(test_kbpk, sizeof(test_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_variant() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test_kbek_variant_verify, sizeof(test_kbek_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test_kbak_variant_verify, sizeof(test_kbak_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block authentication key is invalid\n");
		return 1;
	}

	r = tr31_tdes_kbpk_derive(test_kbpk, sizeof(test_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_derive() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test_kbek_derive_verify, sizeof(test_kbek_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test_kbak_derive_verify, sizeof(test_kbak_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block authentication key is invalid\n");
		return 1;
	}

	printf("All tests passed.\n");

	return 0;
}
