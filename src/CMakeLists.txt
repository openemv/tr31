##############################################################################
# Copyright (c) 2020, 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.14)

include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables and good defaults for install()

# generate config file for internal use only
# this file should NOT be installed or used by an installed header
configure_file(
	tr31_config.h.in
	tr31_config.h
)

add_library(tr31 tr31.c tr31_crypto.c)
set_target_properties(tr31
	PROPERTIES
		PUBLIC_HEADER tr31.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_include_directories(tr31 PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # for generated config file
target_include_directories(tr31 INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(tr31 OpenSSL::Crypto)
install(TARGETS tr31
	EXPORT tr31Targets # for use by install(EXPORT) command
	PUBLIC_HEADER
		DESTINATION "include/${PROJECT_NAME}"
		COMPONENT tr31_development
	RUNTIME
		COMPONENT tr31_runtime
	LIBRARY
		COMPONENT tr31_runtime
		NAMELINK_COMPONENT tr31_development
	ARCHIVE
		COMPONENT tr31_development
)

add_executable(tr31-tool tr31-tool.c)
target_link_libraries(tr31-tool tr31)
install(TARGETS tr31-tool
	RUNTIME
		COMPONENT tr31_runtime
)
