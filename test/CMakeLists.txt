##############################################################################
# Copyright (c) 2020 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.11)

include_directories(${LIBTR31_INCLUDE_DIR})

add_executable(tr31_decode_test tr31_decode_test.c)
target_link_libraries(tr31_decode_test tr31)

add_executable(tr31_decrypt_test tr31_decrypt_test.c)
target_link_libraries(tr31_decrypt_test tr31)
