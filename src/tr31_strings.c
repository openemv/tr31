/**
 * @file tr31_strings.c
 * @brief TR-31 string helper functions
 *
 * Copyright (c) 2023 Leon Lynch
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

#include "tr31_strings.h"
#include "tr31.h"

#include <string.h>

// Helper functions
static const char* tr31_opt_block_hmac_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_kcv_get_string(const struct tr31_opt_ctx_t* opt_block);

int tr31_opt_block_data_get_desc(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len)
{
	const char* simple_str = NULL;

	if (!opt_block || !str || !str_len) {
		return -1;
	}
	str[0] = 0; // Default to empty string

	switch (opt_block->id) {
		case TR31_OPT_BLOCK_HM:
			simple_str = tr31_opt_block_hmac_get_string(opt_block);
			break;

		case TR31_OPT_BLOCK_KC:
		case TR31_OPT_BLOCK_KP:
			simple_str = tr31_opt_block_kcv_get_string(opt_block);
			break;
	}

	if (simple_str) {
		strncpy(str, simple_str, str_len - 1);
		str[str_len - 1] = 0;
	}

	return 0;
}

static const char* tr31_opt_block_hmac_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	const uint8_t* data;

	if (!opt_block ||
		opt_block->id != TR31_OPT_BLOCK_HM ||
		opt_block->data_length != 1
	) {
		return NULL;
	}
	data = opt_block->data;

	// See ANSI X9.143:2021, 6.3.6.5, table 13
	switch (data[0]) {
		case TR31_OPT_BLOCK_HM_SHA1:            return "SHA-1";
		case TR31_OPT_BLOCK_HM_SHA224:          return "SHA-224";
		case TR31_OPT_BLOCK_HM_SHA256:          return "SHA-256";
		case TR31_OPT_BLOCK_HM_SHA384:          return "SHA-384";
		case TR31_OPT_BLOCK_HM_SHA512:          return "SHA-512";
		case TR31_OPT_BLOCK_HM_SHA512_224:      return "SHA-512/224";
		case TR31_OPT_BLOCK_HM_SHA512_256:      return "SHA-512/256";
		case TR31_OPT_BLOCK_HM_SHA3_224:        return "SHA3-224";
		case TR31_OPT_BLOCK_HM_SHA3_256:        return "SHA3-256";
		case TR31_OPT_BLOCK_HM_SHA3_384:        return "SHA3-384";
		case TR31_OPT_BLOCK_HM_SHA3_512:        return "SHA3-512";
		case TR31_OPT_BLOCK_HM_SHAKE128:        return "SHAKE128";
		case TR31_OPT_BLOCK_HM_SHAKE256:        return "SHAKE256";
	}

	return "Unknown";
}

static const char* tr31_opt_block_kcv_get_string(const struct tr31_opt_ctx_t* opt_block)
{
	const uint8_t* data;

	if (!opt_block ||
		opt_block->data_length < 2
	) {
		return NULL;
	}
	if (opt_block->id != TR31_OPT_BLOCK_KC &&
		opt_block->id != TR31_OPT_BLOCK_KP
	) {
		return NULL;
	}
	data = opt_block->data;

	// See ANSI X9.143:2021, 6.3.6.7, table 15
	switch (data[0]) {
		case TR31_OPT_BLOCK_KCV_LEGACY: return "Legacy KCV algorithm";
		case TR31_OPT_BLOCK_KCV_CMAC: return "CMAC based KCV";
	}

	return "Unknown";
}
