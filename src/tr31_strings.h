/**
 * @file tr31_strings.h
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

#ifndef TR31_STRINGS_H
#define TR31_STRINGS_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

// Forward declarations
struct tr31_opt_ctx_t;

/**
 * Create ASCII string associated with key usage value
 *
 * @param usage Key usage value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_get_key_usage_ascii(unsigned int usage, char* ascii, size_t ascii_len);

/**
 * Retrieve string associated with key usage value
 *
 * @param usage Key usage value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_usage_string(unsigned int usage);

/**
 * Retrieve string associated with key algorithm value
 *
 * @param algorithm Key algorithm value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_algorithm_string(unsigned int algorithm);

/**
 * Retrieve string associated with key mode of use value
 *
 * @param mode_of_use Key mode of use value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_mode_of_use_string(unsigned int mode_of_use);

/**
 * Retrieve string associated with key exportability value
 *
 * @param exportability Key exportability value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_exportability_string(unsigned int exportability);

/**
 * Retrieve string associated with key context value
 *
 * @param key_context Key context value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_key_context_string(unsigned int key_context);

/**
 * Create ASCII string associated with optional block ID value
 *
 * @param opt_block_id Optional block ID value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_get_opt_block_id_ascii(unsigned int opt_block_id, char* ascii, size_t ascii_len);

/**
 * Retrieve string associated with optional block ID value
 *
 * @param opt_block_id Optional block ID value
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_get_opt_block_id_string(unsigned int opt_block_id);

/**
 * Provide human readable description of optional block data, if available. The
 * description is derived from the optional block data but does not contain the
 * verbatim optional block data. The output string will be empty (and NULL
 * terminated) if no description is available for the optional block data or if
 * the optional block ID is unknown.
 *
 * @param opt_block Optional block
 * @param str String buffer output
 * @param str_len Length of string buffer in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for parse error. See @ref tr31_error_t
 */
int tr31_opt_block_data_get_desc(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len);

__END_DECLS

#endif
