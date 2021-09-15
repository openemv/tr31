/**
 * @file tr31_crypto_test.c
 *
 * Copyright (c) 2020 ono//connect
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

#include "tr31_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// example data generated using a Thales payShield 10k HSM
static const uint8_t test1_kbpk[] = { 0xEF, 0xE0, 0x85, 0x3B, 0x25, 0x6B, 0x58, 0x3D, 0x86, 0x8F, 0x25, 0x1C, 0xE9, 0x9E, 0xA1, 0xD9 };
static const uint8_t test1_kbek_variant_verify[] = { 0xAA, 0xA5, 0xC0, 0x7E, 0x60, 0x2E, 0x1D, 0x78, 0xC3, 0xCA, 0x60, 0x59, 0xAC, 0xDB, 0xE4, 0x9C };
static const uint8_t test1_kbak_variant_verify[] = { 0xA2, 0xAD, 0xC8, 0x76, 0x68, 0x26, 0x15, 0x70, 0xCB, 0xC2, 0x68, 0x51, 0xA4, 0xD3, 0xEC, 0x94 };
static const uint8_t test1_kbek_derive_verify[] = { 0x60, 0xC1, 0x7C, 0x9B, 0x43, 0x02, 0x01, 0x23, 0xC1, 0x60, 0x40, 0xCC, 0xDC, 0xBC, 0x76, 0xF1 };
static const uint8_t test1_kbak_derive_verify[] = { 0x8A, 0x15, 0x42, 0xBD, 0x19, 0xE8, 0xC0, 0x81, 0x24, 0x2A, 0x14, 0x31, 0x76, 0xE7, 0x45, 0xB8 };

// TR-31:2018, A.7.2.1
static const uint8_t test2_kbpk[] = { 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C };
static const uint8_t test2_kbek_variant_verify[] = { 0xCC, 0xAD, 0xC9, 0xB2, 0xD6, 0x51, 0x01, 0xB6, 0x71, 0xF8, 0x30, 0x02, 0xB9, 0x7A, 0x7D, 0x49 };
static const uint8_t test2_kbak_variant_verify[] = { 0xC4, 0xA5, 0xC1, 0xBA, 0xDE, 0x59, 0x09, 0xBE, 0x79, 0xF0, 0x38, 0x0A, 0xB1, 0x72, 0x75, 0x41 };

// TR-31:2018, A.7.2.2
static const uint8_t test3_kbpk[] = { 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 };
static const uint8_t test3_kbek_derive_verify[] = { 0x69, 0x88, 0x32, 0xF8, 0x77, 0x8A, 0x7C, 0xFC, 0xBC, 0x79, 0x55, 0x9D, 0xAB, 0x07, 0xB8, 0x8A };
static const uint8_t test3_kbak_derive_verify[] = { 0xDD, 0x6C, 0xEE, 0xC1, 0x78, 0x2D, 0x84, 0x53, 0x67, 0x1B, 0xF8, 0x35, 0x8A, 0xF9, 0xDB, 0x47 };

// TR-31:2018, A.7.3.1
static const uint8_t test4_kbpk[] = { 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 };
static const uint8_t test4_kbek_variant_verify[] = { 0xFD, 0xA8, 0x1C, 0xA5, 0xE7, 0x3C, 0xE7, 0xD0, 0xAC, 0xB0, 0xA8, 0x3C, 0x01, 0xB8, 0x43, 0xFC };
static const uint8_t test4_kbak_variant_verify[] = { 0xF5, 0xA0, 0x14, 0xAD, 0xEF, 0x34, 0xEF, 0xD8, 0xA4, 0xB8, 0xA0, 0x34, 0x09, 0xB0, 0x4B, 0xF4 };

// TR-31:2018, A.7.3.2
static const uint8_t test5_kbpk[] = { 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC };
static const uint8_t test5_kbek_derive_verify[] = { 0xBC, 0xE8, 0xE2, 0xAD, 0x5D, 0x44, 0x89, 0xFD, 0x0E, 0xA5, 0x23, 0x6A, 0x88, 0x4D, 0xAC, 0x58 };
static const uint8_t test5_kbak_derive_verify[] = { 0x1F, 0x9B, 0x2B, 0xDA, 0xF9, 0x69, 0xC7, 0xB8, 0xB6, 0xC9, 0x33, 0xAC, 0x7B, 0x9C, 0x68, 0x94 };

int main(void)
{
	int r;
	uint8_t test_kbek[sizeof(test1_kbpk)];
	uint8_t test_kbak[sizeof(test1_kbpk)];

	r = tr31_tdes_kbpk_variant(test1_kbpk, sizeof(test1_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_variant() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test1_kbek_variant_verify, sizeof(test1_kbek_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test1_kbak_variant_verify, sizeof(test1_kbak_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block authentication key is invalid\n");
		return 1;
	}

	r = tr31_tdes_kbpk_derive(test1_kbpk, sizeof(test1_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_derive() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test1_kbek_derive_verify, sizeof(test1_kbek_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test1_kbak_derive_verify, sizeof(test1_kbak_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block authentication key is invalid\n");
		return 1;
	}

	// TR-31:2018, A.7.2.1
	r = tr31_tdes_kbpk_variant(test2_kbpk, sizeof(test2_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_variant() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test2_kbek_variant_verify, sizeof(test2_kbek_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test2_kbak_variant_verify, sizeof(test2_kbak_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block authentication key is invalid\n");
		return 1;
	}

	// TR-31:2018, A.7.2.2
	r = tr31_tdes_kbpk_derive(test3_kbpk, sizeof(test3_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_derive() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test3_kbek_derive_verify, sizeof(test3_kbek_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test3_kbak_derive_verify, sizeof(test3_kbak_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block authentication key is invalid\n");
		return 1;
	}

	// TR-31:2018, A.7.3.1
	r = tr31_tdes_kbpk_variant(test4_kbpk, sizeof(test4_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_variant() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test4_kbek_variant_verify, sizeof(test4_kbek_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test4_kbak_variant_verify, sizeof(test4_kbak_variant_verify)) != 0) {
		fprintf(stderr, "Variant key block authentication key is invalid\n");
		return 1;
	}

	// TR-31:2018, A.7.3.2
	r = tr31_tdes_kbpk_derive(test5_kbpk, sizeof(test5_kbpk), test_kbek, test_kbak);
	if (r) {
		fprintf(stderr, "tr31_tdes_kbpk_derive() failed; r=%d\n", r);
		return r;
	}
	if (memcmp(test_kbek, test5_kbek_derive_verify, sizeof(test5_kbek_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block encryption key is invalid\n");
		return 1;
	}
	if (memcmp(test_kbak, test5_kbak_derive_verify, sizeof(test5_kbak_derive_verify)) != 0) {
		fprintf(stderr, "Derived key block authentication key is invalid\n");
		return 1;
	}

	printf("All tests passed.\n");

	return 0;
}
