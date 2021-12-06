##############################################################################
# Copyright (c) 2020, 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

if (BUILD_TESTING)
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
endif()
