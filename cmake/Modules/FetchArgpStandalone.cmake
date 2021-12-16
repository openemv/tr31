##############################################################################
# Copyright (c) 2021 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

# This module will define:
#
# argp_FOUND
# argp_INCLUDE_DIRS
# argp_LIBRARIES

# This module also provides the following imported targets:
# - argp::argp (library)

include(FetchContent)

message(CHECK_START "Downloading argp-standalone...")

# Patch #1 required for Clang
FetchContent_Declare(
	argp-patch1
	URL https://raw.githubusercontent.com/Homebrew/formula-patches/b5f0ad3/argp-standalone/patch-argp-fmtstream.h
	URL_HASH SHA256=5656273f622fdb7ca7cf1f98c0c9529bed461d23718bc2a6a85986e4f8ed1cb8
	DOWNLOAD_NO_EXTRACT TRUE
	DOWNLOAD_NAME argp-standalone-fmtstream.patch
)
FetchContent_MakeAvailable(argp-patch1)

# Patch #2 required for GCC
FetchContent_Declare(
	argp-patch2
	URL https://git.yoctoproject.org/poky/plain/meta/recipes-support/argp-standalone/files/0001-throw-in-funcdef.patch
	URL_HASH SHA256=5dade630242a436fd3693c8deea2dc97e03d59097b735b45199d5d43adbdfbcb
	DOWNLOAD_NO_EXTRACT TRUE
	DOWNLOAD_NAME argp-standalone-throw-in-funcdef.patch
)
FetchContent_MakeAvailable(argp-patch2)

# Download argp-standalone
FetchContent_Declare(
	argp
	URL "https://www.lysator.liu.se/~nisse/misc/argp-standalone-1.3.tar.gz"
	URL_HASH SHA256=dec79694da1319acd2238ce95df57f3680fea2482096e483323fddf3d818d8be
	PATCH_COMMAND patch -p0 < ${argp-patch1_SOURCE_DIR}/argp-standalone-fmtstream.patch && patch -p1 < ${argp-patch2_SOURCE_DIR}/argp-standalone-throw-in-funcdef.patch
)
FetchContent_MakeAvailable(argp)
message(CHECK_PASS "done")

message(CHECK_START "Configuring argp-standalone...")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	# GCC requires -fgnu89-inline to successfully build argp-standalone
	execute_process(
		COMMAND ./configure CFLAGS="-O2 -fgnu89-inline"
		WORKING_DIRECTORY ${argp_SOURCE_DIR}
	)
elseif(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
	# The GCC flavour of AppleClang is required to build argp-standalone
	execute_process(
		COMMAND ./configure CC=/usr/bin/gcc
		WORKING_DIRECTORY ${argp_SOURCE_DIR}
	)
else()
	execute_process(
		COMMAND ./configure
		WORKING_DIRECTORY ${argp_SOURCE_DIR}
	)
endif()
if(NOT EXISTS ${argp_SOURCE_DIR}/Makefile)
	message(FATAL_ERROR "Error during argp-standalone configuration")
endif()
message(CHECK_PASS "done")

# Prepare argp-standalone build
set(argp_INCLUDE_DIR "${argp_SOURCE_DIR}")
set(argp_LIBRARY "${argp_SOURCE_DIR}/libargp.a")
add_custom_command(
	OUTPUT ${argp_LIBRARY}
	COMMAND make
	WORKING_DIRECTORY ${argp_SOURCE_DIR}
)
add_custom_target(argp-target DEPENDS ${argp_LIBRARY})

# Add library import and let it depend on the custom command above
add_library(argp::argp STATIC IMPORTED GLOBAL)
add_dependencies(argp::argp argp-target)
set_target_properties(argp::argp
	PROPERTIES
		IMPORTED_LOCATION "${argp_LIBRARY}"
		INTERFACE_INCLUDE_DIRECTORIES "${argp_INCLUDE_DIR}"
)

# argp is now ready to use
set(argp_FOUND TRUE)
set(argp_INCLUDE_DIRS "${argp_INCLUDE_DIR}")
set(argp_LIBRARIES "${argp_LIBRARY}")

mark_as_advanced(
	argp_INCLUDE_DIR
	argp_LIBRARY
)
