/**
 * @file tr31_export_test.c
 *
 * Copyright 2021-2025 Leon Lynch
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
	size_t cert_base64_count;
	const char** cert_base64;
	uint8_t opt_blk_HM;
	bool opt_blk_KC;
	bool opt_blk_KP;
	size_t ksn_len;
	const uint8_t* ksn;
	const char* timestamp;

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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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
			.key_context = TR31_KEY_CONTEXT_NONE,
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

	// ANSI X9.143:2021, 8.5
	{
		.name = "ANSI X9.143:2021, 8.5",

		.kbpk_len = 16,
		.kbpk_data = (uint8_t[]){ 0xFA, 0x36, 0xE4, 0x42, 0x78, 0xDB, 0x3A, 0xB5, 0xF2, 0x98, 0xF9, 0xF7, 0xDA, 0x8F, 0x1F, 0x88 },
		.kbpk = {
			.usage = TR31_KEY_USAGE_TR31_KBPK,
			.algorithm = TR31_KEY_ALGORITHM_AES,
			.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC,
			.length = 0,
			.data = NULL,
		},

		.key_len = 1192,
		.key_data = (uint8_t[]){
			0x30, 0x82, 0x04, 0xA4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xD6, 0xC4, 0x60, 0xFB,
			0x01, 0x2E, 0x8D, 0xED, 0xF2, 0xD7, 0x85, 0x74, 0xB4, 0x51, 0xE9, 0xBF, 0x1C, 0x69, 0x63, 0xF7,
			0xF2, 0xAE, 0x57, 0x41, 0xD2, 0x74, 0x5C, 0xB4, 0x10, 0xE7, 0xE0, 0x0B, 0xE4, 0x05, 0xFC, 0x89,
			0xB8, 0x32, 0xC6, 0xE7, 0xDB, 0xEA, 0x90, 0x65, 0xD5, 0x77, 0xC2, 0x7C, 0x61, 0x07, 0x70, 0x10,
			0x76, 0x49, 0xAD, 0x5A, 0xBE, 0xEC, 0x1F, 0x2B, 0x8E, 0xD3, 0x3A, 0x3C, 0xCA, 0x32, 0x1F, 0xFE,
			0xD0, 0x01, 0x96, 0x40, 0x0B, 0xBB, 0x70, 0xEF, 0x8D, 0x0F, 0xE1, 0xC7, 0xDE, 0x9F, 0x52, 0x2B,
			0xCA, 0xE6, 0xD9, 0x56, 0xF8, 0x95, 0xF5, 0x05, 0x29, 0xFA, 0x01, 0xD3, 0xA1, 0xE9, 0x59, 0x7E,
			0xBD, 0x6B, 0x7C, 0x8B, 0x2E, 0x10, 0x68, 0x73, 0xA3, 0xA5, 0x21, 0xC1, 0x8E, 0xF4, 0x92, 0x44,
			0xBC, 0xEF, 0xFA, 0xD8, 0x1C, 0x25, 0x5A, 0xB6, 0x16, 0x44, 0x8C, 0xC9, 0xAF, 0x50, 0x81, 0x1D,
			0xA7, 0x38, 0x34, 0x3D, 0x9D, 0xBE, 0x1D, 0xE8, 0x3A, 0x0F, 0x7E, 0x4E, 0x43, 0xBD, 0x08, 0xFA,
			0x7A, 0x7E, 0x06, 0xC1, 0x10, 0x7F, 0xBD, 0x59, 0xAF, 0xE7, 0x76, 0x88, 0xAA, 0x95, 0x18, 0x47,
			0x79, 0xD2, 0x5F, 0x2D, 0x6E, 0x7E, 0x16, 0xDC, 0x0E, 0x2B, 0x3B, 0x25, 0x04, 0x44, 0xF4, 0xDA,
			0x00, 0x2C, 0x12, 0xF6, 0xBB, 0xDD, 0x17, 0xB9, 0xE5, 0x99, 0x3A, 0x92, 0x23, 0x9C, 0x9B, 0x37,
			0xA9, 0x66, 0x9B, 0x7E, 0xDA, 0xEF, 0x58, 0x7B, 0xEE, 0x7E, 0x8C, 0xE7, 0x86, 0x9A, 0xC3, 0x62,
			0xA4, 0x25, 0x85, 0x95, 0xA3, 0xED, 0x6C, 0xB5, 0x44, 0xF2, 0x15, 0x5B, 0x2F, 0xFD, 0x80, 0x6C,
			0xF5, 0xAC, 0xA5, 0x6C, 0x11, 0xD0, 0x39, 0x8A, 0xA9, 0xFD, 0x4D, 0xAD, 0x07, 0x44, 0xF1, 0x33,
			0x9F, 0x10, 0x60, 0x6C, 0xF2, 0x69, 0x6B, 0xCD, 0xA9, 0xB1, 0x73, 0x39, 0x02, 0x03, 0x01, 0x00,
			0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0x9A, 0x61, 0x93, 0xED, 0x1A, 0xCE, 0x62, 0x4B, 0xF7, 0xD2,
			0xA1, 0x26, 0x61, 0x30, 0xB8, 0xBC, 0x1E, 0x2A, 0x4C, 0x28, 0x42, 0x14, 0xBC, 0xB8, 0x9E, 0x15,
			0xF3, 0x45, 0xA5, 0x19, 0x69, 0x5E, 0x62, 0xCD, 0x42, 0xD9, 0xA4, 0xC5, 0x2B, 0x62, 0x24, 0x1D,
			0x9B, 0x2A, 0xF8, 0xA6, 0x1B, 0xF1, 0xD8, 0xB5, 0xC6, 0x02, 0xAF, 0x65, 0x0A, 0xEE, 0x3E, 0x6B,
			0xF1, 0x84, 0x18, 0x29, 0x12, 0xA5, 0xFC, 0x1A, 0xC8, 0x11, 0x1D, 0x68, 0xE6, 0x9E, 0xA7, 0x50,
			0x58, 0x40, 0x7A, 0xC0, 0x3D, 0xE6, 0xB4, 0xCB, 0x06, 0x00, 0x60, 0xDC, 0x4C, 0xC3, 0x4D, 0xF2,
			0x4D, 0xAD, 0x26, 0x9D, 0x86, 0x8E, 0xA0, 0xC6, 0xE3, 0x04, 0x4E, 0x19, 0x63, 0xEF, 0x90, 0x6F,
			0x4F, 0x06, 0x41, 0x4E, 0x44, 0xD3, 0xA4, 0x75, 0x7E, 0x67, 0x57, 0x01, 0x92, 0xE9, 0xA2, 0x61,
			0xDF, 0xB1, 0x20, 0x94, 0xAA, 0x36, 0x47, 0x65, 0x82, 0x27, 0x2E, 0xDA, 0xB0, 0xF5, 0x6F, 0x81,
			0x6D, 0x9F, 0xA6, 0x95, 0x80, 0xB3, 0xAB, 0x05, 0x32, 0x37, 0x13, 0x5B, 0xD1, 0xDD, 0xDB, 0x42,
			0xAF, 0x77, 0xE1, 0x1E, 0x16, 0x29, 0xF5, 0xA1, 0x1B, 0x22, 0xC5, 0xE3, 0xE2, 0xDB, 0x3E, 0x87,
			0x67, 0xA9, 0x0B, 0x94, 0x41, 0x48, 0x98, 0xDC, 0xCB, 0xB4, 0x7E, 0xFE, 0x61, 0x9F, 0x06, 0x20,
			0xAC, 0x29, 0xC3, 0x89, 0xFB, 0x46, 0x4C, 0xE9, 0xC5, 0xE2, 0x43, 0x96, 0x3E, 0x13, 0xB6, 0xDA,
			0x38, 0xEF, 0xAE, 0x13, 0x30, 0xAE, 0xFB, 0x54, 0xC0, 0xD5, 0xE2, 0xE5, 0x9B, 0x6D, 0x7F, 0xBE,
			0x4B, 0x3A, 0x22, 0xEE, 0x48, 0x3F, 0x74, 0xE7, 0x4D, 0x4A, 0x4A, 0x25, 0x97, 0x8C, 0x65, 0xF4,
			0xAC, 0x58, 0x29, 0xC3, 0x42, 0x60, 0x93, 0x0C, 0x85, 0xEC, 0xEA, 0x1F, 0xB2, 0x4D, 0xB5, 0x2A,
			0x43, 0x8D, 0x4E, 0xB2, 0xCF, 0x61, 0x02, 0x81, 0x81, 0x00, 0xED, 0x00, 0x3D, 0xEE, 0xB8, 0x01,
			0x3A, 0xF4, 0xE4, 0xEB, 0xE1, 0x72, 0xFE, 0x47, 0x4B, 0x23, 0xFE, 0x20, 0x12, 0x88, 0x05, 0x84,
			0x0C, 0x2D, 0x27, 0x7E, 0x3E, 0x30, 0x8D, 0x5B, 0x44, 0x52, 0x7F, 0x1E, 0xD3, 0x3C, 0x07, 0xAF,
			0x35, 0x0D, 0x5B, 0x22, 0xB2, 0x7E, 0x08, 0x2C, 0xD1, 0x01, 0xDD, 0x2D, 0xE5, 0x4D, 0xC8, 0xDF,
			0x8F, 0x91, 0xD4, 0xBA, 0x57, 0x68, 0xEB, 0x9E, 0xC5, 0xF2, 0x7D, 0xB5, 0xD3, 0x58, 0xEA, 0x5E,
			0x0D, 0xEE, 0x08, 0xA5, 0x35, 0x67, 0x7C, 0xB3, 0xF7, 0x65, 0x78, 0x9C, 0x9D, 0xAE, 0x56, 0xB7,
			0x42, 0x1B, 0x9E, 0x54, 0x52, 0x5E, 0xF9, 0x28, 0xAB, 0x28, 0x85, 0xBF, 0x09, 0x8E, 0x83, 0x79,
			0x99, 0xAD, 0x0C, 0xA3, 0xCA, 0x6A, 0xC6, 0x42, 0xEA, 0x9A, 0xD1, 0x33, 0x18, 0x56, 0xB0, 0xCC,
			0xEE, 0x5D, 0xF0, 0x1F, 0xED, 0x1B, 0x2F, 0x63, 0xC3, 0xA5, 0x02, 0x81, 0x81, 0x00, 0xE7, 0xFB,
			0xDA, 0x0A, 0x71, 0xC9, 0x26, 0xDD, 0x51, 0xF0, 0x37, 0x20, 0x6D, 0x90, 0x1A, 0x29, 0x75, 0x54,
			0xA3, 0x9B, 0xBC, 0x92, 0x39, 0x79, 0x44, 0x21, 0xF1, 0xF5, 0x4D, 0x29, 0x76, 0x6E, 0x50, 0xE0,
			0x16, 0xCA, 0x57, 0x01, 0xBD, 0xA7, 0x9A, 0xEC, 0x54, 0x3F, 0x50, 0x66, 0xB3, 0x73, 0x0E, 0x05,
			0x3E, 0xA4, 0xB5, 0x87, 0x2D, 0x25, 0xC2, 0x96, 0x73, 0xCA, 0x84, 0x57, 0xB0, 0x73, 0x90, 0xD1,
			0x1A, 0xF2, 0x3F, 0x22, 0x47, 0xA1, 0x13, 0x3F, 0xC2, 0x52, 0x2B, 0x96, 0xCB, 0x02, 0xDA, 0x77,
			0xD9, 0x27, 0xFE, 0xE6, 0x66, 0x10, 0x66, 0x05, 0x8D, 0x1A, 0x4D, 0x85, 0xFE, 0x3C, 0x1D, 0x34,
			0x18, 0x54, 0x2F, 0x24, 0xB3, 0x98, 0x2B, 0x4D, 0xDF, 0xB4, 0x19, 0x2E, 0x51, 0x2E, 0xDA, 0x1B,
			0xAA, 0xAA, 0x59, 0x95, 0x5B, 0x50, 0x94, 0x5D, 0xD0, 0x83, 0xE2, 0x6E, 0x4D, 0x05, 0x02, 0x81,
			0x80, 0x02, 0xD4, 0xE0, 0xE8, 0x8C, 0x3C, 0x3F, 0x87, 0x13, 0x81, 0x19, 0xF5, 0x74, 0xC2, 0x47,
			0x4C, 0x8B, 0xC9, 0xB8, 0x4E, 0xF5, 0xB9, 0xE9, 0x27, 0x54, 0xF4, 0x76, 0x2B, 0xC0, 0x54, 0x99,
			0xD1, 0x5E, 0x81, 0x70, 0xC6, 0xA3, 0xD4, 0xDD, 0x0E, 0x66, 0xCB, 0x58, 0x54, 0x97, 0x26, 0x69,
			0xEC, 0xDA, 0xC6, 0xA4, 0x99, 0xB4, 0x4F, 0xAF, 0x78, 0x6F, 0x91, 0x36, 0x60, 0x23, 0x88, 0x87,
			0x16, 0xE9, 0x97, 0x95, 0x89, 0xD7, 0x6A, 0xFE, 0x41, 0x9C, 0xCA, 0xD4, 0x83, 0x83, 0x02, 0xE7,
			0x6E, 0xC7, 0xED, 0x1F, 0x19, 0x29, 0x22, 0x11, 0x61, 0x21, 0x18, 0x22, 0xCF, 0xCD, 0xAC, 0x45,
			0xB7, 0x3B, 0x39, 0xD8, 0x14, 0x62, 0xCF, 0xBE, 0x1D, 0x4A, 0x2C, 0x5E, 0xCB, 0xBD, 0xC8, 0xA8,
			0xE2, 0xE6, 0xA2, 0xF4, 0xA4, 0x7C, 0x82, 0x46, 0x4A, 0xCB, 0x06, 0xA6, 0x9F, 0x8F, 0x86, 0x62,
			0x9D, 0x02, 0x81, 0x80, 0x4E, 0x98, 0xA9, 0x9A, 0xF8, 0x4A, 0x2A, 0x7C, 0xB9, 0x92, 0x25, 0x5B,
			0x3B, 0x43, 0xA3, 0x59, 0x80, 0x83, 0x18, 0x9B, 0x5F, 0x1C, 0x3B, 0x94, 0xB6, 0x5C, 0xB9, 0xD9,
			0x5E, 0x37, 0x3A, 0x04, 0xCE, 0x29, 0xDE, 0x0E, 0xD7, 0xC3, 0xA3, 0x39, 0xF1, 0xE7, 0x37, 0xF3,
			0xEB, 0x8D, 0xA0, 0x26, 0xCF, 0x0D, 0x3F, 0xD8, 0x16, 0x18, 0xA2, 0x57, 0x34, 0xC2, 0x3C, 0xA0,
			0xD4, 0x8D, 0xD1, 0x1E, 0x96, 0x66, 0x02, 0x37, 0x28, 0xE4, 0xB8, 0x57, 0xFE, 0x69, 0x8F, 0xB0,
			0xBF, 0x4B, 0xEB, 0xA4, 0x1F, 0xD8, 0x93, 0x1E, 0x55, 0xE2, 0x41, 0x9A, 0x34, 0xB6, 0x94, 0xC3,
			0xE0, 0x98, 0x11, 0x36, 0xD4, 0xBE, 0x1D, 0xB0, 0x07, 0xF8, 0xEB, 0x50, 0x16, 0xFB, 0xDF, 0x5A,
			0xE9, 0x5D, 0x23, 0xEC, 0x37, 0xC1, 0x3F, 0xE5, 0x4F, 0x4C, 0xA7, 0x0F, 0x79, 0xF4, 0xFE, 0xFC,
			0x6F, 0xEE, 0xE6, 0xF1, 0x02, 0x81, 0x81, 0x00, 0x83, 0x21, 0xC2, 0xF1, 0xE8, 0x91, 0x4C, 0x0A,
			0xE0, 0x9C, 0x41, 0x8A, 0xCF, 0xEB, 0xB8, 0xA7, 0xB8, 0x6A, 0x1E, 0x71, 0x44, 0x18, 0x2F, 0x51,
			0x45, 0xFB, 0xA9, 0x0A, 0xF1, 0x04, 0xDE, 0x3B, 0xC7, 0x60, 0x4D, 0x86, 0xA8, 0x31, 0xAC, 0x2F,
			0x38, 0xDA, 0x35, 0x6C, 0x99, 0xBC, 0x60, 0xBE, 0xA8, 0x0E, 0x26, 0xEC, 0x8B, 0x7F, 0xAF, 0x8B,
			0xB8, 0x4A, 0x86, 0x61, 0xEF, 0x56, 0x4B, 0xDC, 0x65, 0xDA, 0x05, 0x19, 0xF5, 0xE3, 0xCE, 0x81,
			0xFF, 0x49, 0x1C, 0xC7, 0x1D, 0xA0, 0x81, 0x39, 0x60, 0x04, 0x8B, 0x22, 0x5E, 0x61, 0xC5, 0x66,
			0x84, 0xD3, 0xCE, 0x01, 0xAE, 0x28, 0xA2, 0x12, 0xC9, 0xAC, 0xCE, 0x94, 0x6E, 0x2A, 0xAB, 0x80,
			0xAD, 0xD5, 0x1B, 0x00, 0x09, 0x30, 0x29, 0xC5, 0xD5, 0x2E, 0x9A, 0xF6, 0xC8, 0xA3, 0xEB, 0x86,
			0x16, 0x41, 0xB0, 0x0E, 0x23, 0x63, 0x6A, 0x68,
		},
		.key = {
			.usage = TR31_KEY_USAGE_AKP_SIG,
			.algorithm = TR31_KEY_ALGORITHM_RSA,
			.mode_of_use = TR31_KEY_MODE_OF_USE_SIG,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_NONE,
			.key_context = TR31_KEY_CONTEXT_NONE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,
		.cert_base64_count = 1,
		.cert_base64 = (const char*[]){
			"MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7Z",
		},
		.opt_blk_KP = true,
		.timestamp = "20200818221218Z",

		.tr31_header_verify = "D3776S0RS00N0400CT0004050000MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7ZKP1001D77F007724TS1320200818221218ZPB0D",
		.tr31_length_verify =
			16 /* header */
			+ 0x500 /* opt block CT */
			+ 0x10 /* opt block KP */
			+ 0x13 /* opt block TS */
			+ 0x0D /* opt block PB */
			+ (2 /* key length */ + 1192 /* key */ + 6 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
	},

	// ANSI X9.143:2021, 8.6
	{
		.name = "ANSI X9.143:2021, 8.6",

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

		.key_len = 121,
		.key_data = (uint8_t[]){
			0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x2D, 0x49, 0x32, 0x57, 0xA4, 0x5B, 0x34, 0xC1, 0x1B,
			0x65, 0x26, 0xA0, 0x3D, 0xB4, 0xD8, 0xAE, 0x16, 0xEE, 0x87, 0xA0, 0xC1, 0x6B, 0xDF, 0x1B, 0xE2,
			0x3C, 0x2D, 0xD8, 0xB1, 0x64, 0xA2, 0xD3, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
			0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x42, 0x3F, 0x48, 0xBA, 0xC7, 0xE9, 0xF2,
			0x13, 0x03, 0xDC, 0xBA, 0x63, 0x70, 0x67, 0x7A, 0xEA, 0x13, 0xFF, 0x9F, 0x84, 0x1D, 0x27, 0xA9,
			0x67, 0x10, 0x98, 0x79, 0x2B, 0x2D, 0x1A, 0x59, 0x76, 0xB1, 0x5B, 0xE6, 0x48, 0x36, 0x56, 0x59,
			0x26, 0xCD, 0xEA, 0x58, 0x79, 0x15, 0xBF, 0xF3, 0x6A, 0x0A, 0xC3, 0x8E, 0x34, 0x3F, 0x81, 0x9B,
			0x56, 0x20, 0xE4, 0xDF, 0xDB, 0x02, 0xF5, 0xBD, 0x21,
		},
		.key = {
			.usage = TR31_KEY_USAGE_AKP_SIG,
			.algorithm = TR31_KEY_ALGORITHM_EC,
			.mode_of_use = TR31_KEY_MODE_OF_USE_SIG,
			.key_version = TR31_KEY_VERSION_IS_UNUSED,
			.exportability = TR31_KEY_EXPORT_NONE,
			.key_context = TR31_KEY_CONTEXT_NONE,
			.length = 0,
			.data = NULL,
		},

		.tr31_version = TR31_VERSION_D,
		.cert_base64_count = 2,
		.cert_base64 = (const char*[]){
			"MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVBAMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIxMDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZXJjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeSstGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOWF+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TYW1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDoTkvKYQ==",
			"MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EAwIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVBAMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMjEwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji+3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePHxwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwFoAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leGFtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZTHxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2LlUqpN/069y5s=",
		},
		.opt_blk_KP = true,
		.timestamp = "20200818004100Z",

		.tr31_header_verify = "D1840S0ES00N0400CT000405CC020002F0MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVBAMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIxMDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZXJjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeSstGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOWF+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TYW1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDoTkvKYQ==0002C4MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EAwIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVBAMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMjEwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji+3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePHxwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwFoAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leGFtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZTHxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2LlUqpN/069y5s=KP10012331550BC9TS1320200818004100ZPB11",
		.tr31_length_verify =
			16 /* header */
			+ 0x5CC /* opt block CT */
			+ 0x10 /* opt block KP */
			+ 0x13 /* opt block TS */
			+ 0x11 /* opt block PB */
			+ (2 /* key length */ + 121 /* key */ + 5 /* padding */) * 2
			+ (16 /* authenticator */) * 2,
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
	char key_block[4096];

	// Test error for missing key or KBPK data
	{
		struct tr31_key_t kbpk;
		struct tr31_key_t key;

		// Prepare KBPK object
		r = tr31_key_init(
			TR31_KEY_USAGE_TR31_KBPK,
			TR31_KEY_ALGORITHM_TDES,
			TR31_KEY_MODE_OF_USE_ENC_DEC,
			"00",
			TR31_KEY_EXPORT_NONE,
			TR31_KEY_CONTEXT_STORAGE,
			NULL,
			0,
			&kbpk
		);
		if (r) {
			fprintf(stderr, "tr31_key_init() error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}

		// Prepare key object
		r = tr31_key_init(
			TR31_KEY_USAGE_PEK,
			TR31_KEY_ALGORITHM_TDES,
			TR31_KEY_MODE_OF_USE_ENC_DEC,
			"00",
			TR31_KEY_EXPORT_NONE,
			TR31_KEY_CONTEXT_STORAGE,
			NULL,
			0,
			&key
		);
		if (r) {
			fprintf(stderr, "tr31_key_init() error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}

		// Prepare TR-31 context
		r = tr31_init(TR31_VERSION_B, &key, &test_tr31);
		if (r) {
			fprintf(stderr, "tr31_init() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}

		// Attempt key block export with invalid key
		r = tr31_export(&test_tr31, &kbpk, 0, key_block, sizeof(key_block));
		if (!r) {
			fprintf(stderr, "Unexpected tr31_export() success when KBPK is invalid\n");
			goto exit;
		}
		if (r != TR31_ERROR_INVALID_KEY_LENGTH) {
			fprintf(stderr, "tr31_export() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}

		// Populate key data
		r = tr31_key_set_data(
			&test_tr31.key,
			test[0].key_data,
			test[0].key_len
		);
		if (r) {
			fprintf(stderr, "tr31_key_set_data() error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}

		// Attempt key block export with invalid KBPK
		r = tr31_export(&test_tr31, &kbpk, 0, key_block, sizeof(key_block));
		if (!r) {
			fprintf(stderr, "Unexpected tr31_export() success when KBPK is invalid\n");
			goto exit;
		}
		if (r != TR31_ERROR_UNSUPPORTED_KBPK_LENGTH) {
			fprintf(stderr, "tr31_export() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}

		tr31_release(&test_tr31);
		tr31_key_release(&key);
		tr31_key_release(&kbpk);
	}

	for (size_t i = 0; i < sizeof(test) / sizeof(test[0]); ++i) {
		printf("Test %zu (%s)...\n", i + 1, test[i].name);

		// Prepare KBPK object
		print_buf("kbpk", test[i].kbpk_data, test[i].kbpk_len);
		r = tr31_key_set_data(&test[i].kbpk, test[i].kbpk_data, test[i].kbpk_len);
		if (r) {
			fprintf(stderr, "tr31_key_set_data() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}

		// Prepare key object
		print_buf("key", test[i].key_data, test[i].key_len);
		r = tr31_key_set_data(&test[i].key, test[i].key_data, test[i].key_len);
		if (r) {
			fprintf(stderr, "tr31_key_set_data() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}

		// Prepare TR-31 context
		r = tr31_init(test[i].tr31_version, &test[i].key, &test_tr31);
		if (r) {
			fprintf(stderr, "tr31_init() error %d: %s\n", r, tr31_get_error_string(r));
			goto exit;
		}
		if (test[i].cert_base64_count) {
			for (size_t cert_idx = 0; cert_idx < test[i].cert_base64_count; ++cert_idx) {
				r = tr31_opt_block_add_CT(
					&test_tr31,
					TR31_OPT_BLOCK_CT_X509,
					test[i].cert_base64[cert_idx],
					strlen(test[i].cert_base64[cert_idx])
				);
				if (r) {
					fprintf(stderr, "tr31_opt_block_add_CT() error %d: %s\n", r, tr31_get_error_string(r));
					goto exit;
				}
			}
		}
		if (test[i].opt_blk_HM) {
			r = tr31_opt_block_add_HM(&test_tr31, test[i].opt_blk_HM);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_HM() error %d: %s\n", r, tr31_get_error_string(r));
				goto exit;
			}
		}
		if (test[i].opt_blk_KC) {
			r = tr31_opt_block_add_KC(&test_tr31);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_KC() error %d: %s\n", r, tr31_get_error_string(r));
				goto exit;
			}
		}
		if (test[i].opt_blk_KP) {
			r = tr31_opt_block_add_KP(&test_tr31);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_KP() error %d: %s\n", r, tr31_get_error_string(r));
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
				fprintf(stderr, "tr31_opt_block_add_KS() error %d: %s\n", r, tr31_get_error_string(r));
				goto exit;
			}
		}
		if (test[i].timestamp) {
			r = tr31_opt_block_add_TS(&test_tr31, test[i].timestamp);
			if (r) {
				fprintf(stderr, "tr31_opt_block_add_TS() error %d: %s\n", r, tr31_get_error_string(r));
				goto exit;
			}
		}

		// Export key block
		r = tr31_export(&test_tr31, &test[i].kbpk, test[i].export_flags, key_block, sizeof(key_block));
		if (r) {
			fprintf(stderr, "tr31_export() error %d: %s\n", r, tr31_get_error_string(r));
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
		r = tr31_import(key_block, strlen(key_block), &test[i].kbpk, 0, &test_tr31);
		if (r) {
			fprintf(stderr, "tr31_import() error %d: %s\n", r, tr31_get_error_string(r));
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
