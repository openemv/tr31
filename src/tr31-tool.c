/**
 * @file tr31-tool.c
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
#include "tr31_strings.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>

#include <ctype.h> // for isalnum and friends
#include <time.h> // for time, gmtime and strftime

// command line options
struct tr31_tool_options_t {
	bool found_stdin_arg;
	bool import;
	bool export;
	bool kbpk;

	// import parameters
	// valid if import is true
	size_t key_block_len;
	char* key_block;

	// export parameters
	// valid if export is true
	size_t export_key_buf_len;
	uint8_t export_key_buf[32]; // max 256-bit wrapped key
	const char* export_key_algorithm;
	unsigned int export_format_version;
	const char* export_template;
	const char* export_header;
	bool export_opt_block_AL;
	uint8_t export_opt_block_AL_akl;
	size_t export_opt_block_BI_buf_len;
	uint8_t export_opt_block_BI_buf[5];
	size_t export_opt_block_IK_buf_len;
	uint8_t export_opt_block_IK_buf[8];
	size_t export_opt_block_KS_buf_len;
	uint8_t export_opt_block_KS_buf[24];
	bool export_opt_block_KC;
	bool export_opt_block_KP;
	const char* export_opt_block_TC_str;
	const char* export_opt_block_TS_str;

	// kbpk parameters
	// valid if kbpk is true
	size_t kbpk_buf_len;
	uint8_t kbpk_buf[32]; // max 256-bit KBPK
};

// helper functions
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state);
static void* read_file(FILE* file, size_t* len);
static int parse_hex(const char* hex, void* bin, size_t bin_len);
static void print_hex(const void* buf, size_t length);
static void print_str_with_quotes(const void* buf, size_t length);

// argp option keys
enum tr31_tool_option_keys_t {
	TR31_TOOL_OPTION_IMPORT = 1,
	TR31_TOOL_OPTION_EXPORT,
	TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM,
	TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION,
	TR31_TOOL_OPTION_EXPORT_TEMPLATE,
	TR31_TOOL_OPTION_EXPORT_HEADER,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_AL,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_BI,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_IK,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS,
	TR31_TOOL_OPTION_KBPK,
	TR31_TOOL_OPTION_VERSION,
};

// argp option structure
static struct argp_option argp_options[] = {
	{ NULL, 0, NULL, 0, "Options for decoding/decrypting TR-31 key blocks:", 1 },
	{ "import", TR31_TOOL_OPTION_IMPORT, "KEYBLOCK", 0, "Import TR-31 key block to decode/decrypt. Use - to read raw bytes from stdin. Optionally specify KBPK (--kbpk) to decrypt." },

	{ NULL, 0, NULL, 0, "Options for encoding/encrypting TR-31 key blocks:", 2 },
	{ "export", TR31_TOOL_OPTION_EXPORT, "KEY", 0, "Export TR-31 key block containing KEY. Use - to read raw bytes from stdin. Requires KBPK (--kbpk). Requires either --export-key-algorithm, --export-format-version and --export-template, or only --export-header" },
	{ "export-key-algorithm", TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM, "TDES|AES", 0, "Algorithm of key to be exported." },
	{ "export-format-version", TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION, "A|B|C|D|E", 0, "TR-31 format version to use for export." },
	{ "export-template", TR31_TOOL_OPTION_EXPORT_TEMPLATE, "KEK|BDK|IK", 0, "TR-31 key block template to use for export." },
	{ "export-header", TR31_TOOL_OPTION_EXPORT_HEADER, "KEYBLOCK-HEADER", 0, "TR-31 key block header to use for export. Key block length field in the header will be ignored." },
	{ "export-opt-block-AL", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_AL, "Ephemeral|Static", 0, "Add optional block AL (Asymmetric Key Life) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-BI", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_BI, "BDK-ID", 0, "Add optional block BI (Base Derivation Key Identifier) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-IK", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_IK, "IKID", 0, "Add optional block IK (Initial Key Identifier) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KS", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS, "IKSN", 0, "Add optional block KS (Initial Key Serial Number) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KP", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP, NULL, 0, "Add optional block KP (KCV of KBPK) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KC", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC, NULL, 0, "Add optional block KC (KCV of wrapped key) during TR-31 export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-TC", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC, "ISO8601", 0, "Add optional block TC (Time of Creation in ISO 8601 UTC format) during TR-31 export. May be used with either --export-template or --export-header. Specify \"now\" for current date/time." },
	{ "export-opt-block-TS", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS, "ISO8601", 0, "Add optional block TS (Time Stamp in ISO 8601 UTC format) during TR-31 export. May be used with either --export-template or --export-header. Specify \"now\" for current date/time." },

	{ NULL, 0, NULL, 0, "Options for decrypting/encrypting TR-31 key blocks:", 3 },
	{ "kbpk", TR31_TOOL_OPTION_KBPK, "KEY", 0, "TR-31 key block protection key. Use - to read raw bytes from stdin." },
	{ "version", TR31_TOOL_OPTION_VERSION, NULL, 0, "Display TR-31 library version" },

	{ 0 },
};

// argp configuration
static struct argp argp_config = {
	argp_options,
	argp_parser_helper,
	NULL,
	" \v" // force the text to be after the options in the help message
	"The import (decoding/decrypting) and export (encoding/encrypting) options cannot be specified simultaneously.\n\n"
	"NOTE:\nAll KEY values are strings of hex digits representing binary data, or - to read raw bytes from stdin. "
	"All ISO8601 values are in UTC and must end with 'Z'.",
};

// argp parser helper function
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state)
{
	int r;
	struct tr31_tool_options_t* options;
	void* buf = NULL;
	size_t buf_len = 0;

	options = state->input;
	if (!options) {
		return ARGP_ERR_UNKNOWN;
	}

	if (arg) {
		// Process KEYBLOCK and KEY arguments
		switch (key) {
			case TR31_TOOL_OPTION_IMPORT: {
				// If argument is "-", read from stdin
				if (strcmp(arg, "-") == 0) {
					if (options->found_stdin_arg) {
						argp_error(state, "Only one option may be read from stdin");
					}
					options->found_stdin_arg = true;

					buf = read_file(stdin, &buf_len);
					if (!buf) {
						argp_error(state, "Failed to read data from stdin");
					}

				} else {
					// Copy argument
					buf_len = strlen(arg) + 1;
					buf = malloc(buf_len);
					memcpy(buf, arg, buf_len);
				}

				// Trim KEYBLOCK argument
				for (char* str = buf; buf_len; --buf_len) {
					if (!isalnum(str[buf_len - 1])) {
						str[buf_len - 1] = 0;
					} else {
						break;
					}
				}

				break;
			}

			case TR31_TOOL_OPTION_EXPORT:
			case TR31_TOOL_OPTION_KBPK: {
				// If argument is "-", read from stdin
				if (strcmp(arg, "-") == 0) {
					if (options->found_stdin_arg) {
						argp_error(state, "Only one option may be read from stdin");
					}
					options->found_stdin_arg = true;

					buf = read_file(stdin, &buf_len);
					if (!buf) {
						argp_error(state, "Failed to read data from stdin");
					}

				} else {
					// Parse KEY argument as hex data
					size_t arg_len = strlen(arg);
					if (arg_len % 2 != 0) {
						argp_error(state, "KEY string must have even number of digits");
					}
					buf_len = arg_len / 2;
					buf = malloc(buf_len);

					r = parse_hex(arg, buf, buf_len);
					if (r) {
						argp_error(state, "KEY string must consist of hex digits");
					}
				}

				break;
			}
		}
	}

	switch (key) {
		case TR31_TOOL_OPTION_IMPORT:
			options->key_block = buf;
			options->key_block_len = buf_len;
			options->import = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT:
			if (buf_len > sizeof(options->export_key_buf)) {
				argp_error(state, "KEY string may not have more than %zu digits (thus %zu bytes)",
					sizeof(options->export_key_buf) * 2,
					sizeof(options->export_key_buf)
				);
			}
			memcpy(options->export_key_buf, buf, buf_len);
			options->export_key_buf_len = buf_len;
			options->export = true;

			free(buf);
			buf = NULL;

			return 0;

		case TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM:
			options->export_key_algorithm = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION:
			if (strlen(arg) != 1) {
				argp_error(state, "Export format version must be a single digit");
			}
			options->export_format_version = *arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_TEMPLATE:
			options->export_template = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_HEADER:
			if (strlen(arg) < 16) {
				argp_error(state, "Export header must be at least 16 characters/bytes");
			}
			for (size_t i = 0; i < strlen(arg); ++i) {
				if (!isalnum(arg[i])) {
					argp_error(state, "Export header must consist of alphanumeric characters (invalid character '%c' is not allowed)", arg[i]);
				}
			}
			options->export_header = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_AL:
			if (strcmp(arg, "Ephemeral") == 0) {
				options->export_opt_block_AL = true;
				options->export_opt_block_AL_akl = TR31_OPT_BLOCK_AL_AKL_EPHEMERAL;
			} else if (strcmp(arg, "Static") == 0) {
				options->export_opt_block_AL = true;
				options->export_opt_block_AL_akl = TR31_OPT_BLOCK_AL_AKL_STATIC;
			} else {
				argp_error(state, "Export optional block AL must be either \"Ephemeral\" or \"Static\"");
			}
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_BI: {
			size_t arg_len = strlen(arg);
			if (arg_len % 2 != 0) {
				argp_error(state, "Export optional block BI must have even number of digits");
			}
			if ((arg_len != 10 && arg_len != 8) ||
				arg_len / 2 > sizeof(options->export_opt_block_BI_buf)
			) {
				argp_error(state, "Export optional block BI must be either 10 digits (thus 5 bytes) for Key set ID (KSI) or 8 digits (thus 4 bytes) for Base Derivation Key ID (BDK ID)");
			}
			options->export_opt_block_BI_buf_len = arg_len / 2;

			r = parse_hex(arg, options->export_opt_block_BI_buf, options->export_opt_block_BI_buf_len);
			if (r) {
				argp_error(state, "Export optional block BI must consist of hex digits");
			}
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_IK: {
			size_t arg_len = strlen(arg);
			if (arg_len % 2 != 0) {
				argp_error(state, "Export optional block IK must have even number of digits");
			}
			if (arg_len != 16 ||
				arg_len / 2 > sizeof(options->export_opt_block_IK_buf)
			) {
				argp_error(state, "Export optional block IK must be 16 digits (thus 8 bytes)");
			}
			options->export_opt_block_IK_buf_len = arg_len / 2;

			r = parse_hex(arg, options->export_opt_block_IK_buf, options->export_opt_block_IK_buf_len);
			if (r) {
				argp_error(state, "Export optional block IK must consist of hex digits");
			}
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS:
			if (strlen(arg) < 16) {
				argp_error(state, "Export optional block KS must be at least 16 digits (thus 8 bytes)");
			}
			if (strlen(arg) % 2 != 0) {
				argp_error(state, "Export optional block KS must have even number of digits");
			}
			options->export_opt_block_KS_buf_len = strlen(arg) / 2;

			r = parse_hex(arg, options->export_opt_block_KS_buf, options->export_opt_block_KS_buf_len);
			if (r) {
				argp_error(state, "Export optional block KS must consist of hex digits");
			}
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC:
			options->export_opt_block_KC = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP:
			options->export_opt_block_KP = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC:
			options->export_opt_block_TC_str = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS:
			options->export_opt_block_TS_str = arg;
			return 0;

		case TR31_TOOL_OPTION_KBPK:
			if (buf_len > sizeof(options->kbpk_buf)) {
				argp_error(state, "KEY string may not have more than %zu digits (thus %zu bytes)",
					sizeof(options->kbpk_buf) * 2,
					sizeof(options->kbpk_buf)
				);
			}
			memcpy(options->kbpk_buf, buf, buf_len);
			options->kbpk_buf_len = buf_len;
			options->kbpk = true;

			free(buf);
			buf = NULL;

			return 0;

		case TR31_TOOL_OPTION_VERSION: {
			const char* version;

			version = tr31_lib_version_string();
			if (version) {
				printf("%s\n", version);
			} else {
				printf("Unknown\n");
			}
			exit(EXIT_SUCCESS);
			return 0;
		}

		case ARGP_KEY_END: {
			// check for required options
			if (!options->import && !options->export) {
				argp_error(state, "Either --import option or --export option is required");
			}

			// check for conflicting options
			if (options->import && options->export) {
				argp_error(state, "The --import option and --export option cannot be specified simultaneously");
			}

			// check for required --export options
			if (options->export &&
				(!options->export_key_algorithm || !options->export_format_version || !options->export_template) &&
				!options->export_header
			) {
				argp_error(state, "The --export option requires either --export-key-algorithm, --export-format-version and --export-template, or only --export-header");
			}
			if (options->export &&
				options->export_template &&
				strcmp(options->export_template, "IK") == 0 &&
				!options->export_opt_block_IK_buf_len &&
				!options->export_opt_block_KS_buf_len
			) {
				argp_error(state, "The --export-template option for Initial key (\"IK\") requires either --export-opt-block-IK or --export-opt-block-KS");
			}

			// check for conflicting --export options
			if (options->export && options->export_template && options->export_header) {
				argp_error(state, "The --export-template option and --export-header option cannot be specified simultaneously");
			}

			return 0;
		}

		default:
			return ARGP_ERR_UNKNOWN;
	}
}

// File/stdin read helper function
static void* read_file(FILE* file, size_t* len)
{
	const size_t block_size = 4096; // Use common page size
	void* buf = NULL;
	size_t buf_len = 0;
	size_t total_len = 0;

	if (!file) {
		*len = 0;
		return NULL;
	}

	do {
		// Grow buffer
		buf_len += block_size;
		buf = realloc(buf, buf_len);

		// Read next block
		total_len += fread(buf + total_len, 1, block_size, file);
		if (ferror(file)) {
			free(buf);
			*len = 0;
			return NULL;
		}
	} while (!feof(file));

	*len = total_len;
	return buf;
}

// hex parser helper function
static int parse_hex(const char* hex, void* bin, size_t bin_len)
{
	size_t hex_len = bin_len * 2;

	for (size_t i = 0; i < hex_len; ++i) {
		if (!isxdigit(hex[i])) {
			return -1;
		}
	}

	while (*hex && bin_len--) {
		uint8_t* ptr = bin;

		char str[3];
		strncpy(str, hex, 2);
		str[2] = 0;

		*ptr = strtoul(str, NULL, 16);

		hex += 2;
		++bin;
	}

	return 0;
}

// hex output helper function
static void print_hex(const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
}

static void print_str_with_quotes(const void* buf, size_t length)
{
	char* str;

	if (!length) {
		return;
	}

	str = malloc(length + 1);
	memcpy(str, buf, length);
	str[length] = 0;
	printf("\"%s\"", str);
	free(str);
}

// TR-31 KBPK populating helper function
static int populate_kbpk(const struct tr31_tool_options_t* options, unsigned int format_version, struct tr31_key_t* kbpk)
{
	int r;
	unsigned int algorithm;

	// determine key block protection key algorithm from keyblock format version
	switch (format_version) {
		case TR31_VERSION_A:
		case TR31_VERSION_B:
		case TR31_VERSION_C:
			algorithm = TR31_KEY_ALGORITHM_TDES;
			break;

		case TR31_VERSION_D:
		case TR31_VERSION_E:
			algorithm = TR31_KEY_ALGORITHM_AES;
			break;

		default:
			fprintf(stderr, "%s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_VERSION));
			return 1;
	}

	// populate key block protection key
	r = tr31_key_init(
		TR31_KEY_USAGE_TR31_KBPK,
		algorithm,
		TR31_KEY_MODE_OF_USE_ENC_DEC,
		"00",
		TR31_KEY_EXPORT_NONE,
		options->kbpk_buf,
		options->kbpk_buf_len,
		kbpk
	);
	if (r) {
		fprintf(stderr, "KBPK error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	return 0;
}

// TR-31 import helper function
static int do_tr31_import(const struct tr31_tool_options_t* options)
{
	int r;
	struct tr31_key_t kbpk;
	struct tr31_ctx_t tr31_ctx;

	// populate key block protection key
	r = populate_kbpk(options, options->key_block[0], &kbpk);
	if (r) {
		return r;
	}

	if (options->kbpk) { // if key block protection key was provided
		// parse and decrypt TR-31 key block
		r = tr31_import(options->key_block, &kbpk, &tr31_ctx);
	} else { // else if no key block protection key was provided
		// parse TR-31 key block
		r = tr31_import(options->key_block, NULL, &tr31_ctx);
	}
	// check for errors
	if (r) {
		fprintf(stderr, "TR-31 import error %d: %s\n", r, tr31_get_error_string(r));
		// continue to print key block details
	}

	// print key block details
	char ascii_buf[3]; // temporary ascii buffer
	printf("Key block format version: %c\n", tr31_ctx.version);
	printf("Key block length: %zu bytes\n", tr31_ctx.length);
	printf("Key usage: [%s] %s\n",
		tr31_get_key_usage_ascii(tr31_ctx.key.usage, ascii_buf, sizeof(ascii_buf)),
		tr31_get_key_usage_string(tr31_ctx.key.usage)
	);
	printf("Key algorithm: [%c] %s\n",
		tr31_ctx.key.algorithm,
		tr31_get_key_algorithm_string(tr31_ctx.key.algorithm)
	);
	printf("Key mode of use: [%c] %s\n",
		tr31_ctx.key.mode_of_use,
		tr31_get_key_mode_of_use_string(tr31_ctx.key.mode_of_use)
	);
	switch (tr31_ctx.key.key_version) {
		case TR31_KEY_VERSION_IS_UNUSED: printf("Key version: Unused\n"); break;
		case TR31_KEY_VERSION_IS_VALID: printf("Key version: %u\n", tr31_ctx.key.key_version_value); break;
		case TR31_KEY_VERSION_IS_COMPONENT: printf("Key component: %u\n", tr31_ctx.key.key_component_number); break;
	}
	printf("Key exportability: [%c] %s\n",
		tr31_ctx.key.exportability,
		tr31_get_key_exportability_string(tr31_ctx.key.exportability)
	);

	// print optional blocks, if available
	if (tr31_ctx.opt_blocks_count) {
		printf("Optional blocks [%zu]:\n", tr31_ctx.opt_blocks_count);
	}
	if (tr31_ctx.opt_blocks) { // might be NULL when tr31_import() fails
		for (size_t i = 0; i < tr31_ctx.opt_blocks_count; ++i) {
			char opt_block_data_str[128];

			printf("\t[%s] %s: ",
				tr31_get_opt_block_id_ascii(tr31_ctx.opt_blocks[i].id, ascii_buf, sizeof(ascii_buf)),
				tr31_get_opt_block_id_string(tr31_ctx.opt_blocks[i].id)
			);

			switch (tr31_ctx.opt_blocks[i].id) {
				case TR31_OPT_BLOCK_BI:
				case TR31_OPT_BLOCK_KC:
				case TR31_OPT_BLOCK_KP:
					// for some optional blocks, skip the first byte
					// the first byte will be decoded by tr31_get_opt_block_data_string()
					if (tr31_ctx.opt_blocks[i].data_length > 1) {
						print_hex(tr31_ctx.opt_blocks[i].data + 1, tr31_ctx.opt_blocks[i].data_length - 1);
					}
					break;

				case TR31_OPT_BLOCK_PB:
				case TR31_OPT_BLOCK_TC:
				case TR31_OPT_BLOCK_TS:
					print_str_with_quotes(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
					break;

				// print all other optional blocks, including proprietary ones, as hex
				default:
					print_hex(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
			}

			r = tr31_opt_block_data_get_desc(&tr31_ctx.opt_blocks[i], opt_block_data_str, sizeof(opt_block_data_str));
			if (r == TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA) {
				printf(" (Invalid)");
			} else if (r == 0 && opt_block_data_str[0]) {
				printf(" (%s)", opt_block_data_str);
			}

			printf("\n");
		}
	}

	// if available, print decrypted key
	if (tr31_ctx.key.length) {
		if (tr31_ctx.key.data) {
			printf("Key length: %zu\n", tr31_ctx.key.length);
			printf("Key value: ");
			print_hex(tr31_ctx.key.data, tr31_ctx.key.length);
			if (tr31_ctx.key.kcv_len) {
				printf(" (KCV: ");
				print_hex(tr31_ctx.key.kcv, tr31_ctx.key.kcv_len);
				printf(")");
			}
			printf("\n");
		} else {
			printf("Key decryption failed\n");
		}
	} else {
		printf("Key not decrypted\n");
	}

	// cleanup
	tr31_key_release(&kbpk);
	tr31_release(&tr31_ctx);

	return 0;
}

// TR-31 export template helper function
static int populate_tr31_from_template(const struct tr31_tool_options_t* options, struct tr31_ctx_t* tr31_ctx)
{
	int r;
	struct tr31_key_t key;

	// populate key algorithm
	if (strcmp(options->export_key_algorithm, "TDES") == 0) {
		key.algorithm = TR31_KEY_ALGORITHM_TDES;
	} else if (strcmp(options->export_key_algorithm, "AES") == 0) {
		key.algorithm = TR31_KEY_ALGORITHM_AES;
	} else {
		fprintf(stderr, "%s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_ALGORITHM));
		return 1;
	}

	// populate key attributes from template
	if (strcmp(options->export_template, "KEK") == 0) {
		key.usage = TR31_KEY_USAGE_KEK;
		key.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
		key.key_version = TR31_KEY_VERSION_IS_UNUSED;
		key.exportability = TR31_KEY_EXPORT_TRUSTED;

	} else if (strcmp(options->export_template, "BDK") == 0) {
		key.usage = TR31_KEY_USAGE_BDK;
		key.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
		key.key_version = TR31_KEY_VERSION_IS_UNUSED;
		key.exportability = TR31_KEY_EXPORT_TRUSTED;

	} else if (strcmp(options->export_template, "IK") == 0 ||
		strcmp(options->export_template, "IPEK") == 0
	) {
		// see ANSI X9.24-3:2017, 6.5.3 "Update Initial Key"
		key.usage = TR31_KEY_USAGE_DUKPT_IK;
		key.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
		key.key_version = TR31_KEY_VERSION_IS_UNUSED;
		key.exportability = TR31_KEY_EXPORT_NONE;

	} else {
		fprintf(stderr, "Unsupported template \"%s\"\n", options->export_template);
		return 1;
	}

	// populate key data
	// avoid tr31_key_set_data() here to avoid tr31_key_release() later
	key.length = options->export_key_buf_len;
	key.data = (void*)options->export_key_buf;

	// populate TR-31 context object
	r = tr31_init(options->export_format_version, &key, tr31_ctx);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		return 1;
	}

	return 0;
}

// TR-31 export header helper function
static int populate_tr31_from_header(const struct tr31_tool_options_t* options, struct tr31_ctx_t* tr31_ctx)
{
	int r;

	size_t export_header_len = strlen(options->export_header);
	size_t tmp_key_block_len = export_header_len + 16 + 1;
	if (tmp_key_block_len > 9999) {
		fprintf(stderr, "Export header too large\n");
		return 1;
	}

	// build fake key block to allow parsing of header
	char tmp_keyblock[tmp_key_block_len];
	memcpy(tmp_keyblock, options->export_header, export_header_len);
	memset(tmp_keyblock + export_header_len, '0', sizeof(tmp_keyblock) - export_header_len - 1);
	tmp_keyblock[sizeof(tmp_keyblock) - 1] = 0;

	// fix length field to allow parsing of header
	char tmp[5];
	snprintf(tmp, sizeof(tmp), "%04zu", tmp_key_block_len - 1);
	memcpy(tmp_keyblock + 1, tmp, 4);

	// misuse TR-31 import function to parse header into TR-31 context object
	r = tr31_import(tmp_keyblock, NULL, tr31_ctx);
	// attempt to report only header parsing errors
	if (r &&
		r != TR31_ERROR_INVALID_LENGTH &&
		r < TR31_ERROR_INVALID_OPTIONAL_BLOCK_DATA
	) {
		fprintf(stderr, "Error while parsing export header; error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	// populate key data
	r = tr31_key_set_data(&tr31_ctx->key, options->export_key_buf, options->export_key_buf_len);
	if (r) {
		fprintf(stderr, "tr31_key_set_data() failed; r=%d\n", r);
		return 1;
	}

	return 0;
}

// TR-31 export optional block helper function
static int populate_opt_blocks(const struct tr31_tool_options_t* options, struct tr31_ctx_t* tr31_ctx)
{
	int r;

	if (options->export_opt_block_AL) {
		r = tr31_opt_block_add_AL(tr31_ctx, options->export_opt_block_AL_akl);
		if (r) {
			fprintf(stderr, "Failed to add optional block AL; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_BI_buf_len) {
		uint8_t BI_key_type;
		switch (tr31_ctx->key.algorithm) {
			case TR31_KEY_ALGORITHM_TDES:
				if (options->export_opt_block_BI_buf_len != 5) {
					fprintf(stderr, "Export optional block BI must be 10 digits (thus 5 bytes) for Key set ID (KSI) when the wrapped key algorithm is TDES\n");
					return 1;
				}
				BI_key_type = TR31_OPT_BLOCK_BI_TDES_DUKPT;
				break;

			case TR31_KEY_ALGORITHM_AES:
				if (options->export_opt_block_BI_buf_len != 4) {
					fprintf(stderr, "Export optional block BI must be 8 digits (thus 4 bytes) for Base Derivation Key ID (BDK ID) when the wrapped key algorithm is AES\n");
					return 1;
				}
				BI_key_type = TR31_OPT_BLOCK_BI_AES_DUKPT;
				break;

			default:
				fprintf(stderr, "Export optional block BI is only allowed for TDES or AES wrapped key\n");
				return 1;
		}

		r = tr31_opt_block_add_BI(
			tr31_ctx,
			BI_key_type,
			options->export_opt_block_BI_buf,
			options->export_opt_block_BI_buf_len
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block BI; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_IK_buf_len) {
		if (tr31_ctx->key.algorithm != TR31_KEY_ALGORITHM_AES) {
			fprintf(stderr, "Export optional block IK is only allowed for AES DUKPT\n");
			return 1;
		}

		r = tr31_opt_block_add_IK(
			tr31_ctx,
			options->export_opt_block_IK_buf,
			options->export_opt_block_IK_buf_len
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block IK; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_KS_buf_len) {
		r = tr31_opt_block_add(
			tr31_ctx,
			TR31_OPT_BLOCK_KS,
			options->export_opt_block_KS_buf,
			options->export_opt_block_KS_buf_len
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block KS; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_KC) {
		r = tr31_opt_block_add_KC(tr31_ctx);
		if (r) {
			fprintf(stderr, "Failed to add optional block KC; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_KP) {
		r = tr31_opt_block_add_KP(tr31_ctx);
		if (r) {
			fprintf(stderr, "Failed to add optional block KP; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_TC_str) {
		const char* export_opt_block_TC_str = options->export_opt_block_TC_str;
		char iso8601_now[16]; // YYYYMMDDhhmmssZ + \0

		if (strcmp(options->export_opt_block_TC_str, "now") == 0) {
			time_t lt; // Calendar/Unix/POSIX time in local time
			struct tm* ztm; // Time structure in UTC
			size_t ret;

			lt = time(NULL);
			if (lt == (time_t)-1) {
				fprintf(stderr, "Failed to obtain current date/time: %s\n", strerror(errno));
				return 1;
			}
			ztm = gmtime(&lt);
			if (ztm == NULL) {
				fprintf(stderr, "Failed to convert current date/time to UTC\n");
				return 1;
			}
			ret = strftime(iso8601_now, sizeof(iso8601_now), "%Y%m%d%H%M%SZ", ztm);
			if (!ret) {
				fprintf(stderr, "Failed to convert current date/time to ISO 8601\n");
				return 1;
			}

			export_opt_block_TC_str = iso8601_now;
		}

		r = tr31_opt_block_add_TC(tr31_ctx, export_opt_block_TC_str);
		if (r) {
			fprintf(stderr, "Failed to add optional block TC; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_TS_str) {
		const char* export_opt_block_TS_str = options->export_opt_block_TS_str;
		char iso8601_now[16]; // YYYYMMDDhhmmssZ + \0

		if (strcmp(options->export_opt_block_TS_str, "now") == 0) {
			time_t lt; // Calendar/Unix/POSIX time in local time
			struct tm* ztm; // Time structure in UTC
			size_t ret;

			lt = time(NULL);
			if (lt == (time_t)-1) {
				fprintf(stderr, "Failed to obtain current date/time: %s\n", strerror(errno));
				return 1;
			}
			ztm = gmtime(&lt);
			if (ztm == NULL) {
				fprintf(stderr, "Failed to convert current date/time to UTC\n");
				return 1;
			}
			ret = strftime(iso8601_now, sizeof(iso8601_now), "%Y%m%d%H%M%SZ", ztm);
			if (!ret) {
				fprintf(stderr, "Failed to convert current date/time to ISO 8601\n");
				return 1;
			}

			export_opt_block_TS_str = iso8601_now;
		}

		r = tr31_opt_block_add_TS(tr31_ctx, export_opt_block_TS_str);
		if (r) {
			fprintf(stderr, "Failed to add optional block TS; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	return 0;
}

// TR-31 export helper function
static int do_tr31_export(const struct tr31_tool_options_t* options)
{
	int r;
	unsigned int export_format_version;
	struct tr31_ctx_t tr31_ctx;
	struct tr31_key_t kbpk;
	char key_block[1024];

	// populate TR-31 context object
	if (options->export_template) {
		// options determine the TR-31 format version to use
		export_format_version = options->export_format_version;

		// populate key from template
		r = populate_tr31_from_template(options, &tr31_ctx);

	} else if (options->export_header) {
		// header determines the TR-31 format version to use
		export_format_version = options->export_header[0];

		// populate key from TR-31 header
		r = populate_tr31_from_header(options, &tr31_ctx);

	} else {
		// Internal error
		fprintf(stderr, "%s\n", tr31_get_error_string(-1));
		return 1;
	}
	if (r) {
		return r;
	}

	// populate additional optional blocks
	r = populate_opt_blocks(options, &tr31_ctx);
	if (r) {
		return r;
	}

	// populate key block protection key
	r = populate_kbpk(options, export_format_version, &kbpk);
	if (r) {
		return r;
	}

	// export TR-31 key block
	r = tr31_export(&tr31_ctx, &kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "TR-31 export error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}
	printf("%s\n", key_block);

	// cleanup
	tr31_key_release(&kbpk);
	tr31_release(&tr31_ctx);

	return 0;
}

int main(int argc, char** argv)
{
	int r;
	struct tr31_tool_options_t options;

	memset(&options, 0, sizeof(options));

	if (argc == 1) {
		// No command line options
		argp_help(&argp_config, stdout, ARGP_HELP_STD_HELP, argv[0]);
		return 1;
	}

	// parse command line options
	r = argp_parse(&argp_config, argc, argv, 0, 0, &options);
	if (r) {
		fprintf(stderr, "Failed to parse command line\n");
		goto exit;
	}

	if (options.import) {
		r = do_tr31_import(&options);
		goto exit;
	}

	if (options.export) {
		r = do_tr31_export(&options);
		goto exit;
	}

	// Unknown error
	r = -1;
	goto exit;

exit:
	// Cleanup
	if (options.key_block) {
		free(options.key_block);
		options.key_block = NULL;
		options.key_block_len = 0;
	}

	return r;
}
