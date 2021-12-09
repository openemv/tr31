/**
 * @file tr31-tool.c
 *
 * Copyright (c) 2020, 2021 ono//connect
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

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>

#include <arpa/inet.h> // for ntohs and friends

// TR-31 header
// see TR-31:2018, A.2, table 4
// TODO: refactor this to use a helper function
struct tr31_header_t {
	uint8_t version_id;
	char length[4];
	uint16_t key_usage;
	uint8_t algorithm;
	uint8_t mode_of_use;
	char key_version[2];
	uint8_t exportability;
	char opt_blocks_count[2];
	char reserved[2];
} __attribute__((packed));

// command line options
struct tr31_tool_options_t {
	bool import;
	bool export;
	bool kbpk;

	// import parameters
	// valid if import is true
	size_t key_block_len;
	const char* key_block;

	// export parameters
	// valid if export is true
	size_t export_key_buf_len;
	uint8_t export_key_buf[32]; // max 256-bit wrapped key
	const char* export_key_algorithm;
	unsigned int export_format_version;
	const char* export_template;
	const char* export_header;

	// kbpk parameters
	// valid if kbpk is true
	size_t kbpk_buf_len;
	uint8_t kbpk_buf[32]; // max 256-bit KBPK
};

// helper functions
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state);
static int parse_hex(const char* hex, void* bin, size_t bin_len);
static void print_hex(const void* buf, size_t length);

// argp option keys
enum tr31_tool_option_keys_t {
	TR31_TOOL_OPTION_IMPORT,
	TR31_TOOL_OPTION_EXPORT,
	TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM,
	TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION,
	TR31_TOOL_OPTION_EXPORT_TEMPLATE,
	TR31_TOOL_OPTION_EXPORT_HEADER,
	TR31_TOOL_OPTION_KBPK,
	TR31_TOOL_OPTION_VERSION,
};

// argp option structure
static struct argp_option argp_options[] = {
	{ NULL, 0, NULL, 0, "Options for decoding/decrypting TR-31 key blocks:", 1 },
	{ "import", TR31_TOOL_OPTION_IMPORT, "KEYBLOCK", 0, "Import TR-31 key block to decode/decrypt. Optionally specify KBPK (--kbpk) to decrypt." },

	{ NULL, 0, NULL, 0, "Options for encoding/encrypting TR-31 key blocks:", 2 },
	{ "export", TR31_TOOL_OPTION_EXPORT, "KEY", 0, "Export TR-31 key block containing KEY. Requires KBPK (--kbpk). Requires either --export-key-algorithm, --export-format-version and --export-template, or only --export-header" },
	{ "export-key-algorithm", TR31_TOOL_OPTION_EXPORT_KEY_ALGORITHM, "TDES|AES", 0, "Algorithm of key to be exported." },
	{ "export-format-version", TR31_TOOL_OPTION_EXPORT_FORMAT_VERSION, "A|B|C|D", 0, "TR-31 format version to use for export." },
	{ "export-template", TR31_TOOL_OPTION_EXPORT_TEMPLATE, "KEK|BDK|IK", 0, "TR-31 key block template to use for export." },
	{ "export-header", TR31_TOOL_OPTION_EXPORT_HEADER, "KEYBLOCK-HEADER", 0, "TR-31 key block header to use for export. Key block length field in the header will be ignored." },

	{ NULL, 0, NULL, 0, "Options for decrypting/encrypting TR-31 key blocks:", 3 },
	{ "kbpk", TR31_TOOL_OPTION_KBPK, "KEY", 0, "TR-31 key block protection key value (hex encoded)" },
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
	"NOTE: All KEY values are strings of hex digits representing binary data.",
};

// argp parser helper function
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state)
{
	int r;
	struct tr31_tool_options_t* options;

	options = state->input;
	if (!options) {
		return ARGP_ERR_UNKNOWN;
	}

	switch (key) {
		case TR31_TOOL_OPTION_IMPORT:
			options->key_block = arg;
			options->key_block_len = strlen(arg);
			options->import = true;
			return 0;

		case TR31_TOOL_OPTION_EXPORT:
			if (strlen(arg) > sizeof(options->export_key_buf) * 2) {
				argp_error(state, "KEY string may not have more than %zu digits (thus %zu bytes)",
					sizeof(options->export_key_buf) * 2,
					sizeof(options->export_key_buf)
				);
			}
			if (strlen(arg) % 2 != 0) {
				argp_error(state, "KEY string must have even number of digits");
			}
			options->export_key_buf_len = strlen(arg) / 2;

			r = parse_hex(arg, options->export_key_buf, options->export_key_buf_len);
			if (r) {
				argp_error(state, "KEY string must consist of hex digits");
			}

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

		case TR31_TOOL_OPTION_EXPORT_HEADER:
			if (strlen(arg) < 16) {
				argp_error(state, "Export header must be at least 16 characters/bytes");
			}
			if (strlen(arg) % 8) {
				argp_error(state, "Export header must be a multiple of 8 characters/bytes");
			}
			options->export_header = arg;
			return 0;

		case TR31_TOOL_OPTION_EXPORT_TEMPLATE:
			options->export_template = arg;
			return 0;

		case TR31_TOOL_OPTION_KBPK:
			if (strlen(arg) > sizeof(options->kbpk_buf) * 2) {
				argp_error(state, "KEY string may not have more than %zu digits (thus %zu bytes)",
					sizeof(options->kbpk_buf) * 2,
					sizeof(options->kbpk_buf)
				);
			}
			if (strlen(arg) % 2 != 0) {
				argp_error(state, "KEY string must have even number of digits");
			}
			options->kbpk_buf_len = strlen(arg) / 2;

			r = parse_hex(arg, options->kbpk_buf, options->kbpk_buf_len);
			if (r) {
				argp_error(state, "KEY string must consist of hex digits");
			}

			options->kbpk = true;
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

// TR-31 KBPK populating helper function
static int populate_kbpk(const struct tr31_tool_options_t* options, unsigned int format_version, struct tr31_key_t* kbpk)
{
	// populate key block protection key
	memset(kbpk, 0, sizeof(*kbpk));
	kbpk->usage = TR31_KEY_USAGE_TR31_KBPK;
	kbpk->mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
	kbpk->length = options->kbpk_buf_len;
	kbpk->data = (void*)options->kbpk_buf;

	// determine key block protection key algorithm from keyblock format version
	switch (format_version) {
		case TR31_VERSION_A:
		case TR31_VERSION_B:
		case TR31_VERSION_C:
			kbpk->algorithm = TR31_KEY_ALGORITHM_TDES;
			break;

		case TR31_VERSION_D:
			kbpk->algorithm = TR31_KEY_ALGORITHM_AES;
			break;

		default:
			fprintf(stderr, "%s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_VERSION));
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
			const char* opt_block_data_str;

			printf("\t[%s] %s: ",
				tr31_get_opt_block_id_ascii(tr31_ctx.opt_blocks[i].id, ascii_buf, sizeof(ascii_buf)),
				tr31_get_opt_block_id_string(tr31_ctx.opt_blocks[i].id)
			);
			print_hex(tr31_ctx.opt_blocks[i].data, tr31_ctx.opt_blocks[i].data_length);

			opt_block_data_str = tr31_get_opt_block_data_string(&tr31_ctx.opt_blocks[i]);
			if (opt_block_data_str) {
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
			printf(" (KCV: ");
			print_hex(tr31_ctx.key.kcv, sizeof(tr31_ctx.key.kcv));
			printf(")\n");
		} else {
			printf("Key decryption failed\n");
		}
	} else {
		printf("Key not decrypted\n");
	}

	// cleanup
	tr31_release(&tr31_ctx);

	return 0;
}

// TR-31 key populating helper function
static int populate_export_key(const struct tr31_tool_options_t* options, struct tr31_key_t* key)
{
	int r;

	if (options->export_template) { // populate key from template

		// populate key algorithm
		if (strcmp(options->export_key_algorithm, "TDES") == 0) {
			key->algorithm = TR31_KEY_ALGORITHM_TDES;
		} else if (strcmp(options->export_key_algorithm, "AES") == 0) {
			key->algorithm = TR31_KEY_ALGORITHM_AES;
		} else {
			fprintf(stderr, "%s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_ALGORITHM));
			return 1;
		}

		// populate key attributes from template
		if (strcmp(options->export_template, "KEK") == 0) {
			key->usage = TR31_KEY_USAGE_KEK;
			key->mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
			key->key_version = TR31_KEY_VERSION_IS_UNUSED;
			key->exportability = TR31_KEY_EXPORT_TRUSTED;

		} else if (strcmp(options->export_template, "BDK") == 0) {
			key->usage = TR31_KEY_USAGE_BDK;
			key->mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
			key->key_version = TR31_KEY_VERSION_IS_UNUSED;
			key->exportability = TR31_KEY_EXPORT_TRUSTED;

		} else if (strcmp(options->export_template, "IK") == 0 ||
			strcmp(options->export_template, "IPEK") == 0
		) {
			// see ANSI X9.24-3:2017, 6.5.3 "Update Initial Key"
			key->usage = TR31_KEY_USAGE_DUKPT_IPEK;
			key->mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
			key->key_version = TR31_KEY_VERSION_IS_UNUSED;
			key->exportability = TR31_KEY_EXPORT_NONE;
			// TODO: IK (or legacy KS) optional block is required

		} else {
			fprintf(stderr, "Unsupported template \"%s\"\n", options->export_template);
			return 1;
		}

	} else if (options->export_header) { // populate key from TR-31 header

		const struct tr31_header_t* header = (const struct tr31_header_t*)options->export_header;
		key->usage = ntohs(header->key_usage);
		key->algorithm = header->algorithm;
		key->mode_of_use = header->mode_of_use;

		r = tr31_key_set_key_version(key, header->key_version);
		if (r) {
			fprintf(stderr, "Failed to extract key version field from TR-31 export header; error %d: %s\n", r, tr31_get_error_string(r));
			return 1;
		}

		key->exportability = header->exportability;

	} else {
		// Internal error
		fprintf(stderr, "%s\n", tr31_get_error_string(-1));
		return 1;
	}

	// populate key data
	key->length = options->export_key_buf_len;
	key->data = (void*)options->export_key_buf;
	return 0;
}

// TR-31 export helper function
static int do_tr31_export(const struct tr31_tool_options_t* options)
{
	int r;
	unsigned int export_format_version;
	struct tr31_key_t kbpk;
	struct tr31_key_t key;
	struct tr31_ctx_t tr31_ctx;
	char key_block[1024];

	// determine the TR-31 format version to use
	if (options->export_header) {
		export_format_version = options->export_header[0];
	} else {
		export_format_version = options->export_format_version;
	}

	// populate key block protection key
	r = populate_kbpk(options, export_format_version, &kbpk);
	if (r) {
		return r;
	}

	// populate key to be exported
	r = populate_export_key(options, &key);
	if (r) {
		return 1;
	}

	// populate TR-31 context object
	r = tr31_init(export_format_version, &key, &tr31_ctx);
	if (r) {
		fprintf(stderr, "tr31_init() failed; r=%d\n", r);
		return 1;
	}

	// export TR-31 key block
	r = tr31_export(&tr31_ctx, &kbpk, key_block, sizeof(key_block));
	if (r) {
		fprintf(stderr, "TR-31 export error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}
	printf("%s\n", key_block);

	// cleanup
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
		return 1;
	}

	if (options.import) {
		return do_tr31_import(&options);
	}

	if (options.export) {
		return do_tr31_export(&options);
	}
}
