/**
 * @file tr31_export_test.c
 *
 * Copyright (c) 2021, 2022, 2023 Leon Lynch
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct test_t {
	const char* name;

	size_t kbpk_len;
	const uint8_t* kbpk_data;
	struct tr31_key_t kbpk;

	size_t key_len;
	const uint8_t* key_data;
	struct tr31_key_t key;

	enum tr31_version_t tr31_version;
	uint32_t export_flags;
	uint8_t opt_blk_HM;
	bool opt_blk_KC;
	bool opt_blk_KP;
	size_t ksn_len;
	const uint8_t* ksn;

	const char* tr31_header_verify;
	size_t tr31_length_verify;
};

static struct test_t test[] = {
	// TR-31:2018, A.7.2.1
	{
		.name = "TR-31:2018, A.7.2.1",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xF0, 0x39, 0x12, 0x1B, 0xEC, 0x83, 0xD2, 0x6B, 0x16, 0x9B, 0xDC, 0xD5, 0xB2, 0x2A, 0xAF, 0x8F },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_A,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,

		.tr31_header_verify = "A0072P0TE00E0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
			+ (4 /* authenticator */) * 2,
	},

	// TR-31:2018, A.7.2.2
	{
		.name = "TR-31:2018, A.7.2.2",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_B,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,

		.tr31_header_verify = "B0080P0TE00E000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
			+ (8 /* authenticator */) * 2,
	},

	// TR-31:2018, A.7.3.1
	{
		.name = "TR-31:2018, A.7.3.1",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 },
		.key = {
			.usage = TR31_KEY_USAGE_BDK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "12",
			.exportability = TR31_KEY_EXPORT_SENSITIVE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_C,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,
		.ksn_len = 10,
		.ksn = (uint8_t[]){ 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 },

		.tr31_header_verify = "C0096B0TX12S0100KS1800604B120F9292800000",
		.tr31_length_verify =
			16 /* header */
			+ 24 /* opt block KS */
			+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
			+ (4 /* authenticator */) * 2,
	},

	// TR-31:2018, A.7.3.2
	{
		.name = "TR-31:2018, A.7.3.2",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 },
		.key = {
			.usage = TR31_KEY_USAGE_BDK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "12",
			.exportability = TR31_KEY_EXPORT_SENSITIVE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_B,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,
		.ksn_len = 10,
		.ksn = (uint8_t[]){ 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 },

		.tr31_header_verify = "B0104B0TX12S0100KS1800604B120F9292800000",
		.tr31_length_verify =
			16 /* header */
			+ 24 /* opt block KS */
			+ (2 /* key length */ + 16 /* key */ + 6 /* padding */) * 2
			+ (8 /* authenticator */) * 2,
	},

	// TR-31:2018, A.7.4
	{
		.name = "TR-31:2018, A.7.4",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
			0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,

		.tr31_header_verify = "D0112P0AE00E0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// Test optional blocks KC and KP
	{
		.name = "Optional blocks KC and KP",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
			0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,
		.opt_blk_KC = true,
		.opt_blk_KP = true,

		.tr31_header_verify = "D0144P0TE00E0300KC0C0057C409KP10012331550BC9PB04",
		.tr31_length_verify =
			16 /* header */
			+ 12 /* opt block KC */ + 16 /* opt block KP */ + 4 /* opt block PB */
			+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// Test HMAC key wrapping
	// Unfortunately no official TR-31:2018 HMAC test vectors are available
	// so here is a hand crafted one (which may be wrong)
	{
		.name = "HMAC key wrapping",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
			0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_HMAC,
			.algorithm = TR31_KEY_ALGORITHM_HMAC,
			.mode_of_use = TR31_KEY_MODE_OF_USE_MAC,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "12",
			.exportability = TR31_KEY_EXPORT_NONE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,
		.opt_blk_HM = 0x21,

		.tr31_header_verify = "D0128M7HC12N0200HM0621PB0A",
		.tr31_length_verify =
			16 /* header */
			+ 6 /* opt block HM */ + 10 /* opt block PB */
			+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// ISO 20038:2017, B.2
	// Without padding, format version E is deterministic and the exported
	// key block can be verified using the sample from ISO 20038:2017
	{
		.name = "ISO 20038:2017, B.2",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
			0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79 },
		.key = {
			.usage = TR31_KEY_USAGE_BDK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_MAC_VERIFY,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "16",
			.exportability = TR31_KEY_EXPORT_NONE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_E,
		.export_flags = TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION,

		.tr31_header_verify = "E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A52DB52F0AEACB94C57547",
	},

	// ISO 20038:2017, B.3
	{
		.name = "ISO 20038:2017, B.3",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x32, 0x35, 0x36, 0x2D, 0x62, 0x69, 0x74, 0x20, 0x41, 0x45, 0x53, 0x20, 0x77, 0x72, 0x61, 0x70,
			0x70, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x49, 0x53, 0x4F, 0x20, 0x32, 0x30, 0x30, 0x33, 0x38, 0x29,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x76, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x33, 0x44, 0x45, 0x53, 0x20, 0x6B, 0x65, 0x79  },
		.key = {
			.usage = TR31_KEY_USAGE_ISO9797_1_MAC_3,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_MAC_VERIFY,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "16",
			.exportability = TR31_KEY_EXPORT_NONE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,

		.tr31_header_verify = "D0112M3TV16N0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 14 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.1
	{
		.name = "ANSI X9.143:2021, 8.1",

		.kbpk_len = 32,
		.kbpk_data = (uint8_t[]){
			0x88, 0xE1, 0xAB, 0x2A, 0x2E, 0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C, 0xC8,
			0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05, 0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6,
		},
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,

		.tr31_header_verify = "D0144P0AE00E0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 16 /* key length obfuscation */ + 14 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.2
	// Unfortunately optional block KS provided by ANSI X9.143:2021 for this
	// test is contains invalid characters

	// ANSI X9.143:2021, 8.3.2.1
	{
		.name = "ANSI X9.143:2021, 8.3.2.1",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0x89, 0xE8, 0x8C, 0xF7, 0x93, 0x14, 0x44, 0xF3, 0x34, 0xBD, 0x75, 0x47, 0xFC, 0x3F, 0x38, 0x0C },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xF0, 0x39, 0x12, 0x1B, 0xEC, 0x83, 0xD2, 0x6B, 0x16, 0x9B, 0xDC, 0xD5, 0xB2, 0x2A, 0xAF, 0x8F },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_A,

		.tr31_header_verify = "A0088P0TE00E0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 8 /* key length obfuscation */ + 6 /* padding */) * 2
			+ (4 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.3.2.2
	{
		.name = "ANSI X9.143:2021, 8.3.2.2",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0xDD, 0x75, 0x15, 0xF2, 0xBF, 0xC1, 0x7F, 0x85, 0xCE, 0x48, 0xF3, 0xCA, 0x25, 0xCB, 0x21, 0xF6 },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0x3F, 0x41, 0x9E, 0x1C, 0xB7, 0x07, 0x94, 0x42, 0xAA, 0x37, 0x47, 0x4C, 0x2E, 0xFB, 0xF8, 0xB8 },
		.key = {
			.usage = TR31_KEY_USAGE_PEK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_TRUSTED,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_B,

		.tr31_header_verify = "B0096P0TE00E0000",
		.tr31_length_verify =
			16 /* header */
			+ 0 /* opt block */
			+ (2 /* key length */ + 16 /* key */ + 8 /* key length obfuscation */ + 6 /* padding */) * 2
			+ (8 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.4.1
	{
		.name = "ANSI X9.143:2021, 8.4.1",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0xB8, 0xED, 0x59, 0xE0, 0xA2, 0x79, 0xA2, 0x95, 0xE9, 0xF5, 0xED, 0x79, 0x44, 0xFD, 0x06, 0xB9 },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xED, 0xB3, 0x80, 0xDD, 0x34, 0x0B, 0xC2, 0x62, 0x02, 0x47, 0xD4, 0x45, 0xF5, 0xB8, 0xD6, 0x78 },
		.key = {
			.usage = TR31_KEY_USAGE_BDK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "12",
			.exportability = TR31_KEY_EXPORT_SENSITIVE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_C,
		.ksn_len = 10,
		.ksn = (uint8_t[]){ 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 },

		.tr31_header_verify = "C0112B0TX12S0100KS1800604B120F9292800000",
		.tr31_length_verify =
			16 /* header */
			+ 24 /* opt block KS */
			+ (2 /* key length */ + 16 /* key */ + 8 /* key length obfuscation */ + 6 /* padding */) * 2
			+ (4 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.4.2
	{
		.name = "ANSI X9.143:2021, 8.4.2",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0x1D, 0x22, 0xBF, 0x32, 0x38, 0x7C, 0x60, 0x0A, 0xD9, 0x7F, 0x9B, 0x97, 0xA5, 0x13, 0x11, 0xAC },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 16,
		.key_data = (uint8_t[]){ 0xE8, 0xBC, 0x63, 0xE5, 0x47, 0x94, 0x55, 0xE2, 0x65, 0x77, 0xF7, 0x15, 0xD5, 0x87, 0xFE, 0x68 },
		.key = {
			.usage = TR31_KEY_USAGE_BDK,
			.algorithm = TR31_KEY_ALGORITHM_TDES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE,
			.key_version = TR31_KEY_VERSION_IS_VALID,
			.key_version_str = "12",
			.exportability = TR31_KEY_EXPORT_SENSITIVE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_B,
		.ksn_len = 10,
		.ksn = (uint8_t[]){ 0x00, 0x60, 0x4B, 0x12, 0x0F, 0x92, 0x92, 0x80, 0x00, 0x00 },

		.tr31_header_verify = "B0120B0TX12S0100KS1800604B120F9292800000",
		.tr31_length_verify =
			16 /* header */
			+ 24 /* opt block KS */
			+ (2 /* key length */ + 16 /* key */ + 8 /* key length obfuscation */ + 6 /* padding */) * 2
			+ (8 /* authenticator */) * 2,
	},
};

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

	for (size_t i = 0; i < sizeof(test) / sizeof(test[0]); ++i) {
		printf("Test %zu (%s)...\n", i + 1, test[i].name);

		// Prepare KBPK object
		print_buf("kbpk", test[i].kbpk_data, test[i].kbpk_len);
		r = tr31_key_set_data(&test[i].kbpk, test[i].kbpk_data, test[i].kbpk_len);
		if (r) {
			fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
			goto exit;
		}

		// Prepare key object
		print_buf("key", test[i].key_data, test[i].key_len);
		r = tr31_key_set_data(&test[i].key, test[i].key_data, test[i].key_len);
		if (r) {
			fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
			goto exit;
		}

		// Prepare TR-31 context
		r = tr31_init(test[i].tr31_version, &test[i].key, &test_tr31);
		if (r) {
			fprintf(stderr, "tr31_init() failed; r=%d\n", r);
			goto exit;
		}
		test_tr31.export_flags = test[i].export_flags;
		if (test[i].opt_blk_HM) {
			r = tr31_opt_block_add_HM(&test_tr31, test[i].opt_blk_HM);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_HM() failed; r=%d\n", r);
				return 1;
			}
		}
		if (test[i].opt_blk_KC) {
			r = tr31_opt_block_add_KC(&test_tr31);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_KC() failed; r=%d\n", r);
				goto exit;
			}
		}
		if (test[i].opt_blk_KP) {
			r = tr31_opt_block_add_KP(&test_tr31);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_KP() failed; r=%d\n", r);
				goto exit;
			}
		}
		if (test[i].ksn_len) {
			r = tr31_opt_block_add_KS(
				&test_tr31,
				test[i].ksn,
				test[i].ksn_len
			);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_KS() failed; r=%d\n", r);
				goto exit;
			}
		}

		// Export key block
		r = tr31_export(&test_tr31, &test[i].kbpk, key_block, sizeof(key_block));
		if (r) {
			fprintf(stderr, "tr31_export() failed; r=%d\n", r);
			goto exit;
		}
		printf("TR-31: %s\n", key_block);

		// Validate key block
		if (strncmp(key_block, test[i].tr31_header_verify, strlen(test[i].tr31_header_verify)) != 0) {
			fprintf(stderr, "TR-31 header encoding is incorrect\n");
			fprintf(stderr, "%s\n%s\n", key_block, test[i].tr31_header_verify);
			r = 1;
			goto exit;
		}
		if (test[i].tr31_length_verify) {
			if (strlen(key_block) != test[i].tr31_length_verify) {
				fprintf(stderr, "TR-31 length is incorrect\n");
				r = 1;
				goto exit;
			}
		} else {
			if (strlen(key_block) != strlen(test[i].tr31_header_verify)) {
				fprintf(stderr, "TR-31 length is incorrect\n");
				r = 1;
				goto exit;
			}
		}
		tr31_release(&test_tr31);

		// Import and decrypt key block
		r = tr31_import(key_block, &test[i].kbpk, &test_tr31);
		if (r) {
			fprintf(stderr, "tr31_import() failed; r=%d\n", r);
			goto exit;
		}
		if (test_tr31.key.length != test[i].key_len ||
			memcmp(test_tr31.key.data, test[i].key_data, test[i].key_len) != 0)
		{
			fprintf(stderr, "Key verification failed\n");
			print_buf("key.data", test_tr31.key.data, test_tr31.key.length);
			print_buf("expected", test[i].key_data, test[i].key_len);
			r = 1;
			goto exit;
		}
		tr31_release(&test_tr31);

		tr31_key_release(&test[i].kbpk);
		tr31_key_release(&test[i].key);

		printf("Test %zu (%s)...success\n\n", i + 1, test[i].name);
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	tr31_release(&test_tr31);
	return r;
}
