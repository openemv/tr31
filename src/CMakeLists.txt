##############################################################################
# Copyright (c) 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.11)

include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables

add_library(tr31 tr31.c tr31_crypto.c)
set_target_properties(tr31 PROPERTIES PUBLIC_HEADER tr31.h)
target_include_directories(tr31 INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(tr31 OpenSSL::Crypto)
install(TARGETS tr31
	EXPORT tr31Targets # for use by install(EXPORT) command
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)

add_executable(tr31-tool tr31-tool.c)
target_link_libraries(tr31-tool tr31)
install(TARGETS tr31-tool)
