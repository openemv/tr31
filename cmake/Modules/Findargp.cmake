##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

# This module will define:
#
# argp_FOUND
# argp_INCLUDE_DIRS
# argp_LIBRARIES

# This module also provides the following imported targets, if found:
# - libargp::argp (library)

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(FindPackageHandleStandardArgs)

# Check whether libc provides argp_parse
check_function_exists("argp_parse" argp_parse_FOUND)

# Check for argp.h header
CHECK_INCLUDE_FILE(
	argp.h
	argp_header_FOUND
)

if(argp_header_FOUND)
	find_path(argp_INCLUDE_DIR
		NAMES argp.h
	)

	find_library(argp_LIBRARY
		NAMES argp
	)

	if(argp_LIBRARY AND NOT argp_parse_FOUND)
		set(CMAKE_REQUIRED_LIBRARIES ${argp_LIBRARY})
		check_symbol_exists("argp_parse" "argp.h" argp_parse_FOUND)
	endif()

	if(argp_parse_FOUND)
		if(argp_LIBRARY)
			set(argp_FOUND_MSG ${argp_LIBRARY})
		else()
			set(argp_FOUND_MSG "provided by libc")
		endif()
	endif()
endif()

find_package_handle_standard_args(argp
	REQUIRED_VARS
		argp_FOUND_MSG # NOTE: argp_LIBRARY is not required
		argp_parse_FOUND
		argp_header_FOUND
		argp_INCLUDE_DIR
)

if(argp_FOUND)
	set(argp_INCLUDE_DIRS ${argp_INCLUDE_DIR})
	set(argp_LIBRARIES ${argp_LIBRARY})

	if(NOT TARGET libargp::argp)
		if(argp_LIBRARY)
			add_library(libargp::argp UNKNOWN IMPORTED)
			set_target_properties(libargp::argp
				PROPERTIES
					IMPORTED_LOCATION "${argp_LIBRARY}"
					INTERFACE_INCLUDE_DIRECTORIES "${argp_INCLUDE_DIR}"
			)
		endif()
	endif()
endif()

mark_as_advanced(
	argp_parse_FOUND
	argp_header_FOUND
	argp_INCLUDE_DIR
	argp_LIBRARY
	argp_FOUND_MSG
)
