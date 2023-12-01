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
struct tr31_ctx_t;
struct tr31_opt_ctx_t;

/**
 * Create ASCII string associated with key usage value
 *
 * @param usage Key usage value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_key_usage_get_ascii(unsigned int usage, char* ascii, size_t ascii_len);

/**
 * Retrieve human readable description associated with key usage.
 *
 * This function may consider the available optional blocks when determining
 * the description.
 *
 * @param ctx TR-31 context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_key_usage_get_desc(const struct tr31_ctx_t* ctx);

/**
 * Retrieve human readable description associated with key algorithm.
 *
 * This function may consider the available optional blocks when determining
 * the description.
 *
 * @param ctx TR-31 context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_key_algorithm_get_desc(const struct tr31_ctx_t* ctx);

/**
 * Retrieve human readable description associated with key mode of use.
 *
 * This function may consider the available optional blocks when determining
 * the description.
 *
 * @param ctx TR-31 context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_key_mode_of_use_get_desc(const struct tr31_ctx_t* ctx);

/**
 * Retrieve human readable description associated with key exportability.
 *
 * This function may consider the available optional blocks when determining
 * the description.
 *
 * @param ctx TR-31 context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_key_exportability_get_desc(const struct tr31_ctx_t* ctx);

/**
 * Retrieve human readable description associated with key context.
 *
 * This function may consider the available optional blocks when determining
 * the description.
 *
 * @param ctx TR-31 context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_key_context_get_desc(const struct tr31_ctx_t* ctx);

/**
 * Create ASCII string associated with optional block ID value
 *
 * @param opt_block_id Optional block ID value
 * @param ascii ASCII output buffer
 * @param ascii_len ASCII output buffer length
 * @return Pointer to output buffer for success. NULL for error.
 */
const char* tr31_opt_block_id_get_ascii(unsigned int opt_block_id, char* ascii, size_t ascii_len);

/**
 * Retrieve human readable description associated with optional block ID value.
 *
 * This function may also consider the optional block length and optional block
 * data when determining the description of the optional block ID.
 *
 * @param opt_block Optional block context object
 * @return Pointer to null-terminated string. Do not free.
 */
const char* tr31_opt_block_id_get_desc(const struct tr31_opt_ctx_t* opt_block);

/**
 * Provide human readable description of optional block data, if available. The
 * description is derived from the optional block data but does not contain the
 * verbatim optional block data. The output string will be empty (and NULL
 * terminated) if no description is available for the optional block data or if
 * the optional block ID is unknown.
 *
 * @param opt_block Optional block context object
 * @param str String buffer output
 * @param str_len Length of string buffer in bytes
 * @return Zero for success. Less than zero for internal error. Greater than zero for parse error. See @ref tr31_error_t
 */
int tr31_opt_block_data_get_desc(const struct tr31_opt_ctx_t* opt_block, char* str, size_t str_len);

__END_DECLS

#endif
