##############################################################################
# Copyright (c) 2020 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.11)

project(tr31)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	add_compile_options(-Wall -Werror)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
endif()

find_package(OpenSSL 1.1 REQUIRED)

add_subdirectory(src)
add_subdirectory(test)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_DEPENDS libssl1.1)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TR-31 library")
set(CPACK_PACKAGE_VENDOR "ono//connect")
set(CPACK_PACKAGE_CONTACT "leon@onoconnect.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")
include(CPack)
