##############################################################################
# Copyright 2020-2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

if(BUILD_TESTING)
	add_executable(tr31_decode_test tr31_decode_test.c)
	target_link_libraries(tr31_decode_test tr31)
	add_test(tr31_decode_test tr31_decode_test)

	add_executable(tr31_crypto_test tr31_crypto_test.c)
	target_link_libraries(tr31_crypto_test tr31)
	add_test(tr31_crypto_test tr31_crypto_test)

	add_executable(tr31_decrypt_test tr31_decrypt_test.c)
	target_link_libraries(tr31_decrypt_test tr31)
	add_test(tr31_decrypt_test tr31_decrypt_test)

	add_executable(tr31_export_test tr31_export_test.c)
	target_link_libraries(tr31_export_test tr31)
	add_test(tr31_export_test tr31_export_test)

	if(WIN32)
		# Ensure that tests can find required DLLs (if any)
		# Assume that the PATH already contains the compiler runtime DLLs
		set(TR31_TEST_PATH "${CMAKE_CURRENT_BINARY_DIR}/../src/;$ENV{PATH}")
		cmake_path(NATIVE_PATH TR31_TEST_PATH NORMALIZE TR31_TEST_PATH)
		get_property(TR31_TEST_TARGETS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY TESTS)
		set_property(TEST ${TR31_TEST_TARGETS}
			PROPERTY
				ENVIRONMENT "PATH=${TR31_TEST_PATH}"
		)
	endif()
endif()
