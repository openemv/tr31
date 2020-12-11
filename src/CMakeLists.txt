##############################################################################
# Copyright (c) 2020 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.11)

set(LIBTR31_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE PATH "libtr31 include path")

add_library(tr31 tr31.c tr31_crypto.c)
target_link_libraries(tr31 OpenSSL::Crypto)
