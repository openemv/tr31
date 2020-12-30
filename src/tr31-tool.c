/**
 * @file tr31-tool.c
 *
 * Copyright (c) 2020 ono//connect
 *
 * This file is licensed under the terms of the LGPL v2.1 license.
 * See LICENSE file.
 */

#include "tr31.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <argp.h>

// global parameters
static size_t key_block_len = 0;
static const char* key_block = NULL;
static size_t kbpk_buf_len = 0;
static uint8_t kbpk_buf[32]; // max 256-bit KBPK

// helper functions
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state);
static int parse_hex(const char* hex, void* bin, size_t bin_len);

// argp option structure
static struct argp_option argp_options[] = {
	{ "key-block", 'i', "asdf", 0, "TR-31 key block input" },
	{ "kbpk", 'k', "key", 0, "TR-31 key block protection key value (hex encoded)" },
	{ 0 },
};

// argp configuration
static struct argp argp_config = {
	argp_options,
	argp_parser_helper,
	NULL,
	NULL,
};

// argp parser helper function
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state)
{
	int r;

	switch (key) {
		case 'i':
			key_block = arg;
			key_block_len = strlen(arg);
			return 0;

		case 'k':
			if (strlen(arg) > sizeof(kbpk_buf) * 2) {
				argp_error(state, "kbpk string may not have more than %zu digits (thus %zu bytes)", sizeof(kbpk_buf) * 2, sizeof(kbpk_buf));
			}
			if (strlen(arg) % 2 != 0) {
				argp_error(state, "kbpk string must have even number of digits");
			}
			kbpk_buf_len = strlen(arg) / 2;

			r = parse_hex(arg, kbpk_buf, kbpk_buf_len);
			if (r) {
				argp_error(state, "kbpk string must must consist of hex digits");
			}

			return 0;

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

// buffer output helper function
static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(int argc, char** argv)
{
	int r;
	struct tr31_ctx_t tr31_ctx;

	r = argp_parse(&argp_config, argc, argv, 0, 0, 0);
	if (r) {
		fprintf(stderr, "Failed to parse command line\n");
		return 1;
	}

	if (kbpk_buf_len) { // if key block protection key was provided
		// populate key block protection key as a key wrapping key
		struct tr31_key_t kbpk;
		memset(&kbpk, 0, sizeof(kbpk));
		kbpk.usage = TR31_KEY_USAGE_KEY;
		kbpk.algorithm = TR31_KEY_ALGORITHM_TDES;
		kbpk.mode_of_use = TR31_KEY_MODE_OF_USE_ENC_DEC;
		kbpk.length = kbpk_buf_len;
		kbpk.data = kbpk_buf;

		// parse and decrypt TR-31 key block
		r = tr31_import(key_block, &kbpk, &tr31_ctx);
	} else { // else if no key block protection key was provided
		// parse TR-31 key block
		r = tr31_import(key_block, NULL, &tr31_ctx);
	}
	// check for errors
	if (r) {
		fprintf(stderr, "TR-31 import error %d: %s\n", r, tr31_get_error_string(r));
		return 1;
	}

	// print key block details
	printf("Key block format version: %c\n", tr31_ctx.version);
	printf("Key block length: %zu bytes\n", tr31_ctx.length);
	printf("Key usage: 0x%02x\n", tr31_ctx.key.usage); // TODO: prettify
	printf("Key algorithm: %c\n", tr31_ctx.key.algorithm);
	printf("Key mode of use: %c\n", tr31_ctx.key.mode_of_use);
	switch (tr31_ctx.key.key_version) {
		case TR31_KEY_VERSION_IS_UNUSED: printf("Key version: Unused\n"); break;
		case TR31_KEY_VERSION_IS_VALID: printf("Key version: %u\n", tr31_ctx.key.key_version_value); break;
		case TR31_KEY_VERSION_IS_COMPONENT: printf("Key component: %u\n", tr31_ctx.key.key_component_number); break;
	}
	printf("Key exportability: %c\n", tr31_ctx.key.exportability);
	if (tr31_ctx.key.length) {
		printf("Key length: %zu\n", tr31_ctx.key.length);
		print_buf("Key value", tr31_ctx.key.data, tr31_ctx.key.length);
	} else {
		printf("Key not decrypted\n");
	}

	// cleanup
	tr31_release(&tr31_ctx);
}
