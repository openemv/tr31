##############################################################################
# Copyright (c) 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

# This module will define:
#
# rpm_FOUND
# rpm_VERSION
# rpm_EXECUTABLE

find_program(rpm_EXECUTABLE rpm)
if(rpm_EXECUTABLE)
	execute_process(
		COMMAND ${rpm_EXECUTABLE} --version
		OUTPUT_VARIABLE rpm_VERSION
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)

	string(REGEX MATCH "RPM version ([0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)"
		rpm_VERSION "${rpm_VERSION}"
	)
	set(rpm_VERSION "${CMAKE_MATCH_1}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(rpm
	REQUIRED_VARS
		rpm_EXECUTABLE
	VERSION_VAR rpm_VERSION
)

mark_as_advanced(rpm_EXECUTABLE)
