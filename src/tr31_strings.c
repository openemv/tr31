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
#include "tr31_config.h"

#include <stdlib.h>
#include <string.h>

#ifdef TR31_ENABLE_DATETIME_CONVERSION
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifndef HAVE_STRPTIME
#include <stdio.h> // For sscanf()
#endif
#endif // TR31_ENABLE_DATETIME_CONVERSION

// Helper functions
static const char* tr31_opt_block_hmac_get_string(const struct tr31_opt_ctx_t* opt_block);
static const char* tr31_opt_block_kcv_get_string(const struct tr31_opt_ctx_t* opt_block);
static int tr31_opt_block_iso8601_get_string(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len);

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

		case TR31_OPT_BLOCK_TC:
		case TR31_OPT_BLOCK_TS:
			return tr31_opt_block_iso8601_get_string(opt_block, str, str_len);
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

static int tr31_opt_block_iso8601_get_string(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len)
{
#ifdef TR31_ENABLE_DATETIME_CONVERSION
	char* iso8601_str;
#ifdef HAVE_STRPTIME
	char* ptr;
#else
	int r;
#endif
	struct tm ztm; // Time structure in UTC
	time_t lt; // Calendar/Unix/POSIX time in local time
	struct tm* ltm; // Time structure in local time
	size_t ret;

	if (!opt_block->data_length) {
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}

	// Copy optional block data to NULL-terminated string
	iso8601_str = malloc(opt_block->data_length + 1);
	memcpy(iso8601_str, opt_block->data, opt_block->data_length);
	iso8601_str[opt_block->data_length] = 0;

	// Validate ISO 8601 format based on string length
	// NOTE: struct tm cannot hold sub-second values and they will be ignored
	// during parsing
	// See ANSI X9.143:2021, 6.3.6.13, table 21
	// See ANSI X9.143:2021, 6.3.6.14, table 22
	memset(&ztm, 0, sizeof(ztm));
#ifdef HAVE_STRPTIME
	switch (opt_block->data_length) {
		case 0x13 - 4: // YYYYMMDDhhmmssZ
			ptr = strptime(iso8601_str, "%Y%m%d%H%M%SZ", &ztm);
			break;

		case 0x15 - 4: // YYYYMMDDhhmmssssZ
			ptr = strptime(iso8601_str, "%Y%m%d%H%M%S", &ztm);
			if (ptr - iso8601_str == 0x15 - 4 - 3 && *(ptr + 2) == 'Z') {
				ptr += 3;
			}
			break;

		case 0x18 - 4: // YYYY-MM-DDThh:mm:ssZ
			ptr = strptime(iso8601_str, "%Y-%m-%dT%H:%M:%SZ", &ztm);
			break;

		case 0x1B - 4: // YYYY-MM-DDThh:mm:ss.ssZ
			ptr = strptime(iso8601_str, "%Y-%m-%dT%H:%M:%S", &ztm);
			if (ptr - iso8601_str == 0x1B - 4 - 4 && *ptr == '.' && *(ptr + 3) == 'Z') {
				ptr += 4;
			}
			break;

		default:
			ptr = NULL; // Don't return before free()'ing iso8601_str
	}
	// NOTE: strptime() returns NULL if it fails to match the format string or
	// returns a pointer to the first character after the matched format
	// string. Therefore iso8601_str may only be free()'d after evaluating *ptr
	if (!ptr || *ptr) {
		free(iso8601_str);
		iso8601_str = NULL;
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}
#else
	switch (opt_block->data_length) {
		case 0x13 - 4: // YYYYMMDDhhmmssZ
			r = sscanf(iso8601_str, "%4d%2d%2d%2d%2d%2dZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x15 - 4: // YYYYMMDDhhmmssssZ
			r = sscanf(iso8601_str, "%4d%2d%2d%2d%2d%2d%*c%*cZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x18 - 4: // YYYY-MM-DDThh:mm:ssZ
			r = sscanf(iso8601_str, "%4d-%2d-%2dT%2d:%2d:%2dZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		case 0x1B - 4: // YYYY-MM-DDThh:mm:ss.ssZ
			r = sscanf(iso8601_str, "%4d-%2d-%2dT%2d:%2d:%2d*c%*cZ", &ztm.tm_year, &ztm.tm_mon, &ztm.tm_mday, &ztm.tm_hour, &ztm.tm_min, &ztm.tm_sec);
			break;

		default:
			r = 0; // Don't return before free()'ing iso8601_str
	}
	// Fix year and month in time structure
	ztm.tm_year -= 1900;
	ztm.tm_min -= 1;
	// NOTE: sscanf() returns number of matched input items
	if (r != 6) {
		free(iso8601_str);
		iso8601_str = NULL;
		return TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA;
	}
#endif
	free(iso8601_str);
	iso8601_str = NULL;

	// Convert UTC time to local time
	lt = timegm(&ztm);
	ltm = localtime(&lt);
	ztm = *ltm;

	// Set time locale according to environment variable
	setlocale(LC_TIME, "");

	// Provide time according to locale
	ret = strftime(str, str_len, "%c", &ztm);
	if (!ret) {
		// Unexpected failure
		return -1;
	}

	return 0;
#else
	str[0] = 0;
	return 0;
#endif
}
