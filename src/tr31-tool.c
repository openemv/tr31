/**
 * @file tr31-tool.c
 *
 * Copyright 2020-2025 Leon Lynch
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

#include "crypto_mem.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>

#include <ctype.h> // for isalnum and friends
#include <time.h> // for time, gmtime and strftime

#ifdef _WIN32
// for _setmode
#include <fcntl.h>
#include <io.h>
#endif

// optional block CT parameters
struct tr31_opt_block_CT {
	uint8_t cert_format;
	const void* cert_base64;
	size_t cert_base64_len;
};

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
	uint32_t import_flags;

	// export parameters
	// valid if export is true
	size_t export_key_buf_len;
	uint8_t* export_key_buf;
	const char* export_key_algorithm;
	unsigned int export_format_version;
	const char* export_template;
	const char* export_header;
	struct tr31_ctx_t export_opt_block_list;
	bool export_opt_block_AL;
	uint8_t export_opt_block_AL_akl;
	size_t export_opt_block_BI_buf_len;
	uint8_t export_opt_block_BI_buf[5];
	size_t export_opt_block_CT_count;
	struct tr31_opt_block_CT* export_opt_block_CT;
	const char* export_opt_block_DA;
	uint8_t export_opt_block_HM;
	size_t export_opt_block_IK_buf_len;
	uint8_t export_opt_block_IK_buf[8];
	bool export_opt_block_KC;
	bool export_opt_block_KP;
	size_t export_opt_block_KS_buf_len;
	uint8_t export_opt_block_KS_buf[10];
	const char* export_opt_block_LB_str;
	size_t export_opt_block_PK_buf_len;
	uint8_t export_opt_block_PK_buf[5];
	const char* export_opt_block_TC_str;
	const char* export_opt_block_TS_str;
	bool export_opt_block_WP;
	uint8_t export_opt_block_WP_value;
	uint32_t export_flags;

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
static void print_str(const void* buf, size_t length);
static void print_str_with_quotes(const void* buf, size_t length);

// argp option keys
enum tr31_tool_option_keys_t {
	TR31_TOOL_OPTION_IMPORT = -255, // negative value to avoid short options
	TR31_TOOL_OPTION_IMPORT_NO_STRICT_VALIDATION,
	TR31_TOOL_OPTION_EXPORT,
	TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM,
	TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION,
	TR31_TOOL_OPTION_EXPORT_TEMPLATE,
	TR31_TOOL_OPTION_EXPORT_HEADER,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_VERBATIM,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_AL,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_BI,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_X509,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_EMV,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_DA,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_HM,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_IK,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_LB,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_PK,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS,
	TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_WP,
	TR31_TOOL_OPTION_EXPORT_NO_KEY_LENGTH_OBFUSCATION,
	TR31_TOOL_OPTION_EXPORT_ZERO_OPT_BLOCK_PB,
	TR31_TOOL_OPTION_KBPK,
	TR31_TOOL_OPTION_VERSION,
};

// argp option structure
static struct argp_option argp_options[] = {
	{ NULL, 0, NULL, 0, "Options for decoding/decrypting key blocks:", 1 },
	{ "import", TR31_TOOL_OPTION_IMPORT, "KEYBLOCK", 0, "Import key block to decode/decrypt. Use - to read raw bytes from stdin. Optionally specify KBPK (--kbpk) to decrypt." },
	{ "import-no-strict-validation", TR31_TOOL_OPTION_IMPORT_NO_STRICT_VALIDATION, NULL, 0, "Disable strict validation during key block import" },

	{ NULL, 0, NULL, 0, "Options for encoding/encrypting key blocks:", 2 },
	{ "export", TR31_TOOL_OPTION_EXPORT, "KEY", 0, "Export key block containing KEY. Use - to read raw bytes from stdin. Requires KBPK (--kbpk). Requires either --export-key-algorithm, --export-format-version and --export-template, or only --export-header" },
	{ "export-key-algorithm", TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM, "TDES|AES", 0, "Algorithm of key to be exported." },
	{ "export-format-version", TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION, "A|B|C|D|E", 0, "Key block format version to use for export." },
	{ "export-template", TR31_TOOL_OPTION_EXPORT_TEMPLATE, "KEK|BDK|IK", 0, "Key block template to use for export." },
	{ "export-header", TR31_TOOL_OPTION_EXPORT_HEADER, "KEYBLOCK-HEADER", 0, "Key block header to use for export. Key block length field in the header will be ignored." },
	{ "export-opt-block", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_VERBATIM, "ASCII", 0, "Add verbatim optional block, including ID and length (for example \"KS10DE#GBIC#OPT1\") during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-AL", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_AL, "Ephemeral|Static", 0, "Add optional block AL (Asymmetric Key Life) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-BI", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_BI, "BDK-ID", 0, "Add optional block BI (Base Derivation Key Identifier) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-CT-X509", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_X509, "base64", 0, "Add optional block CT (X.509 Public Key Certificate) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-CT-EMV", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_EMV, "base64", 0, "Add optional block CT (EMV Public Key Certificate) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-DA", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_DA, "DA-sets", 0, "Add optional block DA (Derivations Allowed) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-HM", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_HM, "Hash-ID", 0, "Add optional block HM (HMAC algorithm) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-IK", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_IK, "IKID", 0, "Add optional block IK (Initial Key Identifier) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KC", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC, NULL, 0, "Add optional block KC (KCV of wrapped key) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KP", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP, NULL, 0, "Add optional block KP (KCV of KBPK) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-KS", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS, "IKSN", 0, "Add optional block KS (Initial Key Serial Number) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-LB", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_LB, "ASCII", 0, "Add optinal block LB (Label) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-PK", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_PK, "KCV", 0, "Add optional block PK (Protection Key Check Value) during key block export. May be used with either --export-template or --export-header." },
	{ "export-opt-block-TC", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC, "ISO8601", 0, "Add optional block TC (Time of Creation in ISO 8601 UTC format) during key block export. May be used with either --export-template or --export-header. Specify \"now\" for current date/time." },
	{ "export-opt-block-TS", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS, "ISO8601", 0, "Add optional block TS (Time Stamp in ISO 8601 UTC format) during key block export. May be used with either --export-template or --export-header. Specify \"now\" for current date/time." },
	{ "export-opt-block-WP", TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_WP, "0-3", 0, "Add optional block WP (Wrapping Pedigree) during key block export. May be used with either --export-template or --export-header." },
	{ "export-no-key-length-obfuscation", TR31_TOOL_OPTION_EXPORT_NO_KEY_LENGTH_OBFUSCATION, NULL, 0, "Disable ANSI X9.143 key length obfuscation during key block export." },
	{ "export-zero-opt-block-PB", TR31_TOOL_OPTION_EXPORT_ZERO_OPT_BLOCK_PB, NULL, 0, "Fill optional block PB (Padding Block) using zeros instead of random characters during key block export." },

	{ NULL, 0, NULL, 0, "Options for decrypting/encrypting key blocks:", 3 },
	{ "kbpk", TR31_TOOL_OPTION_KBPK, "KEY", 0, "Key block protection key. Use - to read raw bytes from stdin." },

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
					buf_len = strlen(arg);
					buf = malloc(buf_len);
					if (!buf) {
						argp_error(state, "Memory allocation failed");
					}
					memcpy(buf, arg, buf_len);
				}

				// Trim KEYBLOCK argument
				for (char* str = buf; buf_len; --buf_len) {
					if (!isgraph(str[buf_len - 1])) {
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
					if (!buf) {
						argp_error(state, "Memory allocation failed");
					}

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

		case TR31_TOOL_OPTION_IMPORT_NO_STRICT_VALIDATION:
			options->import_flags |= TR31_IMPORT_NO_STRICT_VALIDATION;
			return 0;

		case TR31_TOOL_OPTION_EXPORT:
			options->export_key_buf = buf;
			options->export_key_buf_len = buf_len;
			options->export = true;
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
				if (!isprint(arg[i])) {
					argp_error(state, "Export header must consist of printable characters (invalid character '%c' is not allowed)", arg[i]);
				}
			}
			options->export_header = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_VERBATIM: {
			int r;
			size_t arg_len = strlen(arg);
			size_t fake_header_len;
			char* fake_header;
			struct tr31_ctx_t tmp_tr31;

			// instead of re-implementing optional block parsing, misuse the
			// existing key block parsing using a fake header
			fake_header_len = 16 + arg_len;
			fake_header = malloc(fake_header_len);
			if (!fake_header) {
				argp_error(state, "Memory allocation failed");
			}
			memcpy(fake_header, "D0000D0TB00N0100", 16);
			memcpy(fake_header + 16, arg, arg_len);
			r = tr31_init_from_header(
				fake_header,
				fake_header_len,
				TR31_IMPORT_NO_STRICT_VALIDATION,
				&tmp_tr31
			);
			free(fake_header);
			if (r) {
				argp_error(state, "Error while parsing verbatim optional block (%s): %s", arg, tr31_get_error_string(r));
			}

			// add verbatim optional block to list and cleanup temporary key block context object
			r = tr31_opt_block_add(
				&options->export_opt_block_list,
				tmp_tr31.opt_blocks[0].id,
				tmp_tr31.opt_blocks[0].data,
				tmp_tr31.opt_blocks[0].data_length
			);
			tr31_release(&tmp_tr31);
			if (r) {
				argp_error(state, "Failed to add verbatim optional block %c%c; error %d: %s\n",
					arg[0],
					arg[1],
					r,
					tr31_get_error_string(r)
				);
			}
			return 0;
		}

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

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_X509: {
			size_t arg_len = strlen(arg);
			if (arg_len % 4 != 0) {
				argp_error(state, "Export optional block CT base64 string must be a multiple of 4 bytes");
			}
			for (size_t i = 0; i < strlen(arg); ++i) {
				if (!isalnum(arg[i]) && arg[i] != '+' && arg[i] != '/' && arg[i] != '=') {
					argp_error(state, "Export optional block CT base64 string contains invalid character '%c')", arg[i]);
				}
			}
			struct tr31_opt_block_CT ct = {
				.cert_format = TR31_OPT_BLOCK_CT_X509,
				.cert_base64 = arg,
				.cert_base64_len = arg_len
			};

			options->export_opt_block_CT_count++;
			options->export_opt_block_CT = realloc(
				options->export_opt_block_CT,
				options->export_opt_block_CT_count * sizeof(*options->export_opt_block_CT)
			);
			options->export_opt_block_CT[options->export_opt_block_CT_count-1] = ct;
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_CT_EMV: {
			size_t arg_len = strlen(arg);
			if (arg_len % 4 != 0) {
				argp_error(state, "Export optional block CT base64 string must be a multiple of 4 bytes");
			}
			for (size_t i = 0; i < strlen(arg); ++i) {
				if (!isalnum(arg[i]) && arg[i] != '+' && arg[i] != '/' && arg[i] != '=') {
					argp_error(state, "Export optional block CT base64 string contains invalid character '%c')", arg[i]);
				}
			}
			struct tr31_opt_block_CT ct = {
				.cert_format = TR31_OPT_BLOCK_CT_EMV,
				.cert_base64 = arg,
				.cert_base64_len = arg_len
			};

			options->export_opt_block_CT_count++;
			options->export_opt_block_CT = realloc(
				options->export_opt_block_CT,
				options->export_opt_block_CT_count * sizeof(*options->export_opt_block_CT)
			);
			options->export_opt_block_CT[options->export_opt_block_CT_count-1] = ct;
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_DA: {
			size_t arg_len = strlen(arg);
			if (arg_len % 5 != 0) {
				argp_error(state, "Export optional block DA must be a multiple of 5 bytes");
			}
			for (size_t i = 0; i < strlen(arg); ++i) {
				if (!isalnum(arg[i])) {
					argp_error(state, "Export optional block DA consist of alphanumeric characters (invalid character '%c' is not allowed)", arg[i]);
				}
			}
			options->export_opt_block_DA = arg;
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_HM: {
			if (strlen(arg) != 2) {
				argp_error(state, "Export optional block HM must be 2 digits (thus 1 byte)");
			}

			r = parse_hex(arg, &options->export_opt_block_HM, sizeof(options->export_opt_block_HM));
			if (r) {
				argp_error(state, "Export optional block HM must consist of hex digits");
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

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KC:
			options->export_opt_block_KC = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KP:
			options->export_opt_block_KP = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_KS: {
			size_t arg_len = strlen(arg);
			if (arg_len % 2 != 0) {
				argp_error(state, "Export optional block KS must have even number of digits");
			}
			if ((arg_len != 20 && arg_len != 16) ||
				arg_len / 2 > sizeof(options->export_opt_block_KS_buf)
			) {
				argp_error(state, "Export optional block KS must be either 20 digits (thus 10 bytes, according to ANSI X9.143) or 16 digits (thus 8 bytes, for legacy implementations)");
			}
			options->export_opt_block_KS_buf_len = arg_len / 2;

			r = parse_hex(arg, options->export_opt_block_KS_buf, options->export_opt_block_KS_buf_len);
			if (r) {
				argp_error(state, "Export optional block KS must consist of hex digits");
			}
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_LB:
			options->export_opt_block_LB_str = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_PK: {
			size_t arg_len = strlen(arg);
			if (arg_len % 2 != 0) {
				argp_error(state, "Export optional block PK must have even number of digits");
			}
			if ((arg_len != 4 && arg_len != 6 && arg_len != 10) ||
				arg_len / 2 > sizeof(options->export_opt_block_PK_buf)
			) {
				argp_error(state, "Export optional block PK must be 4 or 6 digits (thus 2 or 3 bytes) for TDES legacy KCV or 10 digits (thus 5 bytes) for AES CMAC KCV");
			}
			options->export_opt_block_PK_buf_len = arg_len / 2;

			r = parse_hex(arg, options->export_opt_block_PK_buf, options->export_opt_block_PK_buf_len);
			if (r) {
				argp_error(state, "Export optional block PK must consist of hex digits");
			}
			return 0;
		}

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TC:
			options->export_opt_block_TC_str = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_TS:
			options->export_opt_block_TS_str = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_OPT_BLOCK_WP:
			if (strlen(arg) != 1) {
				argp_error(state, "Export optional block WP must be a single digit");
			}
			if (arg[0] < 0x30 || arg[0] > 0x33) {
				argp_error(state, "Export optional block WP must be a value from 0 to 3");
			}
			options->export_opt_block_WP = true;
			options->export_opt_block_WP_value = arg[0] - 0x30; // convert ASCII number to integer
			return 0;

		case TR31_TOOL_OPTION_EXPORT_NO_KEY_LENGTH_OBFUSCATION:
			options->export_flags |= TR31_EXPORT_NO_KEY_LENGTH_OBFUSCATION;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_ZERO_OPT_BLOCK_PB:
			options->export_flags |= TR31_EXPORT_ZERO_OPT_BLOCK_PB;
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
			if (options->export && !options->kbpk) {
				argp_error(state, "The --export option requires --kbpk");
			}
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

#ifdef _WIN32
	_setmode(_fileno(file), _O_BINARY);
#endif

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

static void print_str(const void* buf, size_t length)
{
	char* str;

	if (!length) {
		return;
	}

	str = malloc(length + 1);
	if (!str) {
		return;
	}
	memcpy(str, buf, length);
	str[length] = 0;
	printf("%s", str);
	free(str);
}

static void print_str_with_quotes(const void* buf, size_t length)
{
	printf("\"");
	print_str(buf, length);
	printf("\"");
}

// KBPK populating helper function
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
		TR31_KEY_CONTEXT_STORAGE,
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

// key block import helper function
static int do_tr31_import(const struct tr31_tool_options_t* options)
{
	int ret = 0;
	int r;
	struct tr31_key_t kbpk;
	struct tr31_ctx_t tr31_ctx;

	// populate key block protection key
	r = populate_kbpk(options, options->key_block[0], &kbpk);
	if (r) {
		return r;
	}

	if (options->kbpk) { // if key block protection key was provided
		// parse and decrypt key block
		r = tr31_import(options->key_block, options->key_block_len, &kbpk, options->import_flags, &tr31_ctx);
	} else { // else if no key block protection key was provided
		// parse key block without decryption
		r = tr31_import(options->key_block, options->key_block_len, NULL, options->import_flags, &tr31_ctx);
	}
	// check for errors
	if (r) {
		fprintf(stderr, "TR-31 import error %d: %s\n", r, tr31_get_error_string(r));
		// continue to print key block details, but remember import error
		ret = r;
	}

	// print key block details
	char ascii_buf[3]; // temporary ascii buffer
	printf("Key block format version: %c\n", tr31_ctx.version);
	printf("Key block length: %zu bytes\n", tr31_ctx.length);
	printf("Key usage: [%s] %s\n",
		tr31_key_usage_get_ascii(tr31_ctx.key.usage, ascii_buf, sizeof(ascii_buf)),
		tr31_key_usage_get_desc(&tr31_ctx)
	);
	printf("Key algorithm: [%c] %s\n",
		tr31_ctx.key.algorithm,
		tr31_key_algorithm_get_desc(&tr31_ctx)
	);
	printf("Key mode of use: [%c] %s\n",
		tr31_ctx.key.mode_of_use,
		tr31_key_mode_of_use_get_desc(&tr31_ctx)
	);
	switch (tr31_ctx.key.key_version) {
		case TR31_KEY_VERSION_IS_UNUSED: printf("Key version: Unused\n"); break;
		case TR31_KEY_VERSION_IS_VALID: printf("Key version: %s\n", tr31_ctx.key.key_version_str); break;
		case TR31_KEY_VERSION_IS_COMPONENT: printf("Key component: %c\n", tr31_ctx.key.key_version_str[1]); break;
	}
	printf("Key exportability: [%c] %s\n",
		tr31_ctx.key.exportability,
		tr31_key_exportability_get_desc(&tr31_ctx)
	);
	printf("Key context: [%c] %s\n",
		tr31_ctx.key.key_context,
		tr31_key_context_get_desc(&tr31_ctx)
	);

	// print optional blocks, if available
	if (tr31_ctx.opt_blocks_count) {
		printf("Optional blocks [%zu]:\n", tr31_ctx.opt_blocks_count);
	}
	if (tr31_ctx.opt_blocks) { // might be NULL when tr31_import() fails
		for (size_t i = 0; i < tr31_ctx.opt_blocks_count; ++i) {
			char opt_block_data_str[128];

			printf("\t[%s] %s: ",
				tr31_opt_block_id_get_ascii(tr31_ctx.opt_blocks[i].id, ascii_buf, sizeof(ascii_buf)),
				tr31_opt_block_id_get_desc(&tr31_ctx.opt_blocks[i])
			);

			switch (tr31_ctx.opt_blocks[i].id) {
				case TR31_OPT_BLOCK_AL: {
					struct tr31_opt_blk_akl_data_t akl_data;
					r = tr31_opt_block_decode_AL(&tr31_ctx.opt_blocks[i], &akl_data);
					if (r || akl_data.version != TR31_OPT_BLOCK_AL_VERSION_1) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; assume version 1 and print AKL as hex
					printf("v1, ");
					print_hex(&akl_data.v1.akl, sizeof(akl_data.v1.akl));
					break;
				}

				case TR31_OPT_BLOCK_BI: {
					struct tr31_opt_blk_bdkid_data_t bdkid_data;
					r = tr31_opt_block_decode_BI(&tr31_ctx.opt_blocks[i], &bdkid_data);
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; print as hex
					print_hex(bdkid_data.bdkid, bdkid_data.bdkid_len);
					break;
				}

				case TR31_OPT_BLOCK_DA: {
					size_t da_attr_count;
					size_t da_data_len;
					struct tr31_opt_blk_da_data_t* da_data;
					if (tr31_ctx.opt_blocks[i].data_length < 2) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					da_attr_count = (tr31_ctx.opt_blocks[i].data_length - 2) / 5;
					da_data_len = sizeof(struct tr31_opt_blk_da_attr_t)
						* da_attr_count
						+ sizeof(struct tr31_opt_blk_da_data_t);
					da_data = malloc(da_data_len);
					if (!da_data) {
						// fallback; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					r = tr31_opt_block_decode_DA(&tr31_ctx.opt_blocks[i], da_data, da_data_len);
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						free(da_data);
						break;
					}
					for (size_t i = 0; i < da_attr_count; ++i) {
						printf("%s%s%c%c%c",
							i == 0 ? "" : ",",
							tr31_key_usage_get_ascii(da_data->attr[i].key_usage, ascii_buf, sizeof(ascii_buf)),
							da_data->attr[i].algorithm,
							da_data->attr[i].mode_of_use,
							da_data->attr[i].exportability
						);
					}
					free(da_data);
					break;
				}

				case TR31_OPT_BLOCK_HM: {
					uint8_t hash_algorithm;
					r = tr31_opt_block_decode_HM(&tr31_ctx.opt_blocks[i], &hash_algorithm);
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; print as hex
					print_hex(&hash_algorithm, sizeof(hash_algorithm));
					break;
				}

				case TR31_OPT_BLOCK_IK: {
					uint8_t ikid[8];
					r = tr31_opt_block_decode_IK(&tr31_ctx.opt_blocks[i], ikid, sizeof(ikid));
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; print as hex
					print_hex(ikid, sizeof(ikid));
					break;
				}

				case TR31_OPT_BLOCK_KS: {
					uint8_t iksn[10];
					r = tr31_opt_block_decode_KS(&tr31_ctx.opt_blocks[i], iksn, sizeof(iksn));
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; print as hex
					print_hex(iksn, sizeof(iksn));
					break;
				}

				case TR31_OPT_BLOCK_KC:
				case TR31_OPT_BLOCK_KP:
				case TR31_OPT_BLOCK_PK: {
					struct tr31_opt_blk_kcv_data_t kcv_data;
					r = tr31_opt_block_decode_kcv(&tr31_ctx.opt_blocks[i], &kcv_data);
					if (r) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; print as hex
					print_hex(kcv_data.kcv, kcv_data.kcv_len);
					break;
				}

				case TR31_OPT_BLOCK_WP: {
					struct tr31_opt_blk_wp_data_t wp_data;
					r = tr31_opt_block_decode_WP(&tr31_ctx.opt_blocks[i], &wp_data);
					if (r || wp_data.version != TR31_OPT_BLOCK_WP_VERSION_0) {
						// invalid; print as string
						print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
						break;
					}
					// valid; assume version 00 and print wrapping pedigree digit
					print_str(tr31_ctx.opt_blocks[i].data + 2, 1);
					break;
				}

				case TR31_OPT_BLOCK_CT:
					// for certificates and certificate chains, skip the first two bytes and use quotes
					// the first byte will be decoded by tr31_get_opt_block_data_string()
					print_str_with_quotes(tr31_ctx.opt_blocks[i].data + 2, tr31_ctx.opt_blocks[i].data_length - 2);
					break;

				case TR31_OPT_BLOCK_KV:
				case TR31_OPT_BLOCK_LB:
				case TR31_OPT_BLOCK_PB:
				case TR31_OPT_BLOCK_TC:
				case TR31_OPT_BLOCK_TS:
					print_str_with_quotes(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
					break;

				// print all other optional blocks, including proprietary ones, verbatim
				default:
					print_str(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);
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
	if (!ret) {
		// only cleanup key block context object if tr31_import() was successful
		tr31_release(&tr31_ctx);
	}

	return ret;
}

// key block export template helper function
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
		key.key_context = TR31_KEY_CONTEXT_NONE;

	} else if (strcmp(options->export_template, "BDK") == 0) {
		key.usage = TR31_KEY_USAGE_BDK;
		key.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
		key.key_version = TR31_KEY_VERSION_IS_UNUSED;
		key.exportability = TR31_KEY_EXPORT_TRUSTED;
		key.key_context = TR31_KEY_CONTEXT_NONE;

	} else if (strcmp(options->export_template, "IK") == 0 ||
		strcmp(options->export_template, "IPEK") == 0
	) {
		// see ANSI X9.24-3:2017, 6.5.3 "Update Initial Key"
		key.usage = TR31_KEY_USAGE_DUKPT_IK;
		key.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
		key.key_version = TR31_KEY_VERSION_IS_UNUSED;
		key.exportability = TR31_KEY_EXPORT_NONE;
		key.key_context = TR31_KEY_CONTEXT_NONE;

	} else {
		fprintf(stderr, "Unsupported template \"%s\"\n", options->export_template);
		return 1;
	}

	// populate key data
	// avoid tr31_key_set_data() here to avoid tr31_key_release() later
	key.length = options->export_key_buf_len;
	key.data = (void*)options->export_key_buf;

	// populate key block context object
	r = tr31_init(options->export_format_version, &key, tr31_ctx);
	if (r) {
		fprintf(stderr, "tr31_init() error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	return 0;
}

// export header helper function
static int populate_tr31_from_header(const struct tr31_tool_options_t* options, struct tr31_ctx_t* tr31_ctx)
{
	int r;

	// parse export header
	r = tr31_init_from_header(
		options->export_header,
		strlen(options->export_header),
		TR31_IMPORT_NO_STRICT_VALIDATION,
		tr31_ctx
	);
	if (r) {
		fprintf(stderr, "Error while parsing export header; error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	// populate key data
	r = tr31_key_set_data(&tr31_ctx->key, options->export_key_buf, options->export_key_buf_len);
	if (r) {
		fprintf(stderr, "tr31_key_set_data() error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	return 0;
}

// export optional block helper function
static int populate_opt_blocks(const struct tr31_tool_options_t* options, struct tr31_ctx_t* tr31_ctx)
{
	int r;

	// populate verbatim optional blocks from list
	// - the opt_blocks field cannot be copied directly to tr31_ctx because an
	//   export header may already have provided some optional blocks and this
	//   list should be appended to those
	// - these optional blocks will not follow the alphabetic ordering of the
	//   standardised optional blocks that are added later in this function
	for (size_t i = 0; i < options->export_opt_block_list.opt_blocks_count; ++i) {
		struct tr31_opt_ctx_t* opt_block = &options->export_opt_block_list.opt_blocks[i];

		r = tr31_opt_block_add(
			tr31_ctx,
			opt_block->id,
			opt_block->data,
			opt_block->data_length
		);
		if (r) {
			char ascii_buf[3];
			fprintf(stderr, "Failed to add optional block %s; error %d: %s\n",
				tr31_opt_block_id_get_ascii(opt_block->id, ascii_buf, sizeof(ascii_buf)),
				r,
				tr31_get_error_string(r)
			);
			return 1;
		}
	}

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

	if (options->export_opt_block_CT_count) {
		for (size_t i = 0; i < options->export_opt_block_CT_count; ++i) {
			r = tr31_opt_block_add_CT(
				tr31_ctx,
				options->export_opt_block_CT[i].cert_format,
				options->export_opt_block_CT[i].cert_base64,
				options->export_opt_block_CT[i].cert_base64_len
			);
			if (r) {
				fprintf(stderr, "Failed to add optional block CT; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
		}
	}

	if (options->export_opt_block_DA) {
		if (tr31_ctx->key.usage != TR31_KEY_USAGE_KDK) {
			fprintf(stderr, "Export optional block DA is only allowed for Key Derivation Keys (key usage B3)\n");
			return 1;
		}

		r = tr31_opt_block_add_DA(
			tr31_ctx,
			options->export_opt_block_DA,
			strlen(options->export_opt_block_DA)
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block DA; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_HM) {
		if (tr31_ctx->key.usage != TR31_KEY_USAGE_HMAC ||
			tr31_ctx->key.algorithm != TR31_KEY_ALGORITHM_HMAC
		) {
			fprintf(stderr, "Export optional block HM is only allowed for ANSI X9.143 HMAC keys (key usage M7, algorithm H)\n");
			return 1;
		}

		r = tr31_opt_block_add_HM(tr31_ctx, options->export_opt_block_HM);
		if (r) {
			fprintf(stderr, "Failed to add optional block HM; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	// look for existing optional block HM because it may have been
	// provided by --export-header
	if (tr31_opt_block_find(tr31_ctx, TR31_OPT_BLOCK_HM)) {
		// disallow usage of optional block HM for non-HMAC key usage as well
		// as for key algorithms I and J (because ISO 20038)
		if (tr31_ctx->key.usage != TR31_KEY_USAGE_HMAC ||
			tr31_ctx->key.algorithm != TR31_KEY_ALGORITHM_HMAC
		) {
			fprintf(stderr, "Export optional block HM is only allowed for ANSI X9.143 HMAC keys (key usage M7, algorithm H)\n");
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

	if (options->export_opt_block_KS_buf_len) {
		if (tr31_ctx->key.algorithm != TR31_KEY_ALGORITHM_TDES) {
			fprintf(stderr, "Export optional block KS is only allowed for TDES DUKPT\n");
			return 1;
		}

		r = tr31_opt_block_add_KS(
			tr31_ctx,
			options->export_opt_block_KS_buf,
			options->export_opt_block_KS_buf_len
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block KS; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_LB_str) {
		r = tr31_opt_block_add_LB(tr31_ctx, options->export_opt_block_LB_str);
		if (r) {
			fprintf(stderr, "Failed to add optional block LB; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	if (options->export_opt_block_PK_buf_len) {
		uint8_t kcv_algorithm;

		switch (options->export_opt_block_PK_buf_len) {
			case 2:
			case 3:
				kcv_algorithm = TR31_OPT_BLOCK_KCV_LEGACY;
				break;

			case 5:
				kcv_algorithm = TR31_OPT_BLOCK_KCV_CMAC;
				break;

			default:
				fprintf(stderr, "Export optional block PK must be 4 or 6 digits (thus 2 or 3 bytes) for TDES legacy KCV or 10 digits (thus 5 bytes) for AES CMAC KCV\n");
				return 1;
		}

		r = tr31_opt_block_add_PK(
			tr31_ctx,
			kcv_algorithm,
			options->export_opt_block_PK_buf,
			options->export_opt_block_PK_buf_len
		);
		if (r) {
			fprintf(stderr, "Failed to add optional block PK; error %d: %s\n", r, tr31_get_error_string(r));
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

	if (options->export_opt_block_WP) {
		if (options->export_opt_block_WP_value > 3) {
			fprintf(stderr, "Export optional block WP must be a value from 0 to 3\n");
			return 1;
		}

		r = tr31_opt_block_add_WP(tr31_ctx, options->export_opt_block_WP_value);
		if (r) {
			fprintf(stderr, "Failed to add optional block WP; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}
	}

	return 0;
}

// key block export helper function
static int do_tr31_export(const struct tr31_tool_options_t* options)
{
	int r;
	unsigned int export_format_version;
	struct tr31_ctx_t tr31_ctx;
	struct tr31_key_t kbpk;
	size_t key_block_len;
	char* key_block;

	// populate key block context object
	if (options->export_template) {
		// options determine the key block format version to use
		export_format_version = options->export_format_version;

		// populate key from template
		r = populate_tr31_from_template(options, &tr31_ctx);

	} else if (options->export_header) {
		// header determines the key block format version to use
		export_format_version = options->export_header[0];

		// populate key from export header
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

	// export key block
	key_block_len = 16384;
	key_block = malloc(key_block_len);
	if (!key_block) {
		fprintf(stderr, "Memory allocation failed\n");
		return 1;
	}
	r = tr31_export(&tr31_ctx, &kbpk, options->export_flags, key_block, key_block_len);
	if (r) {
		fprintf(stderr, "TR-31 export error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}
	printf("%s\n", key_block);

	// cleanup
	free(key_block);
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
	if (options.export_key_buf) {
		free(options.export_key_buf);
		options.export_key_buf = NULL;
		options.export_key_buf_len = 0;
	}
	if (options.export_opt_block_list.opt_blocks) {
		tr31_release(&options.export_opt_block_list);
	}
	if (options.export_opt_block_CT) {
		free(options.export_opt_block_CT);
		options.export_opt_block_CT = NULL;
		options.export_opt_block_CT_count = 0;
	}
	if (options.kbpk) {
		crypto_cleanse(options.kbpk_buf, sizeof(options.kbpk_buf));
	}

	return r;
}
