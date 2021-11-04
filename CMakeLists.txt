##############################################################################
# Copyright (c) 2020, 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.14)

project(tr31
	VERSION 0.2.0
	DESCRIPTION "TR-31 library and tools"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	add_compile_options(-Wall -Werror)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(OpenSSL 1.1 REQUIRED)
find_package(bash-completion) # optional for providing bash-completion files
find_package(Doxygen) # optional for generating doxygen files
find_package(dpkg) # optional for building Debian/Ubuntu packages
find_package(rpmbuild) # optional for building RedHat/Fedora packages

include(CTest)

add_subdirectory(src)
add_subdirectory(test)

include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables

# install README and LICENSE files to runtime component
install(FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/README.md"
	"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
	TYPE DOC
	COMPONENT tr31_runtime
)

# generate and install basic CMake config files
include(CMakePackageConfigHelpers) # provides CMake config generator macros
set(TR31_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} CACHE STRING "Installation location for tr31 CMake config files")
message(STATUS "Using Cmake config install location \"${TR31_INSTALL_CMAKEDIR}\"")
configure_package_config_file(cmake/tr31Config.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31Config.cmake"
	INSTALL_DESTINATION "${TR31_INSTALL_CMAKEDIR}"
)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31ConfigVersion.cmake"
	COMPATIBILITY AnyNewerVersion
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31Config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31ConfigVersion.cmake"
	DESTINATION "${TR31_INSTALL_CMAKEDIR}"
	COMPONENT tr31_development
)
install(EXPORT tr31Targets
	FILE tr31Targets.cmake
	DESTINATION "${TR31_INSTALL_CMAKEDIR}"
	COMPONENT tr31_development
)

# generate and install pkgconfig file
set(TR31_INSTALL_PKGCONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig CACHE STRING "Installation location for tr31 pkgconfig files")
message(STATUS "Using pkgconfig install location \"${TR31_INSTALL_PKGCONFIG_DIR}\"")
set(TR31_PKGCONFIG_LIB_NAME ${CMAKE_PROJECT_NAME})
set(TR31_PKGCONFIG_PKG_DEPS "libcrypto")
set(TR31_PKGCONFIG_LIBS_PRIV "-lcrypto")
configure_file(pkgconfig/libtr31.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	@ONLY
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	DESTINATION "${TR31_INSTALL_PKGCONFIG_DIR}"
	COMPONENT tr31_development
)

if(BASH_COMPLETION_FOUND)
	set(TR31_INSTALL_BASH_COMPLETION_DIR ${CMAKE_INSTALL_DATADIR}/bash-completion/completions CACHE STRING "Installation location for tr31 bash-completion files")
	message(STATUS "Using bash-completion install location \"${TR31_INSTALL_BASH_COMPLETION_DIR}\"")

	# install bash completion file
	install(FILES
		"${CMAKE_CURRENT_SOURCE_DIR}/bash-completion/tr31-tool"
		DESTINATION "${TR31_INSTALL_BASH_COMPLETION_DIR}"
		COMPONENT tr31_runtime
	)
endif()

option(BUILD_DOCS "Build documentation")
if(Doxygen_FOUND)
	# use doxygen to generate HTML
	set(DOXYGEN_GENERATE_HTML YES)

	# generate docs for public header
	if(BUILD_DOCS)
		doxygen_add_docs(docs
			tr31.h
			ALL # build by default
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
		)

		# install generated docs by default
		install(
			DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
			TYPE DOC
			COMPONENT tr31_docs
		)
	else()
		doxygen_add_docs(docs
			tr31.h
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
		)
	endif()
endif()

# configure CPack to generate .tgz package
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_VENDOR "ono//connect")
set(CPACK_PACKAGE_CONTACT "leon@onoconnect.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if(dpkg_FOUND)
	# configure CPack to generate .deb package
	list(APPEND CPACK_GENERATOR "DEB")
	set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT") # use default debian package naming
	set(CPACK_DEBIAN_PACKAGE_DEPENDS libssl1.1)
endif()

if(rpmbuild_FOUND)
	list(APPEND CPACK_GENERATOR "RPM")
	set(CPACK_RPM_FILE_NAME "RPM-DEFAULT") # use default rpm package naming
	set(CPACK_RPM_PACKAGE_LICENSE "LGPLv2+")
	set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm_changelog.txt")
	# NOTE: RPM generator automatically detects dependencies
endif()

include(CPack)
