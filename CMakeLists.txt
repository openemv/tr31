##############################################################################
# Copyright (c) 2020, 2021 ono//connect
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.11)

project(tr31
	VERSION 0.1.2
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
find_package(dpkg) # optional for building Debian/Ubuntu packages
find_package(rpmbuild) # optional for building RedHat/Fedora packages

include(CTest)

add_subdirectory(src)
add_subdirectory(test)

# generate and install basic CMake config files
include(CMakePackageConfigHelpers) # provides CMake config generator macros
include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables
set(CONFIG_PACKAGE_LOCATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} CACHE STRING "Installation location for CMake config files")
configure_package_config_file(cmake/tr31Config.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31Config.cmake"
	INSTALL_DESTINATION "${CONFIG_PACKAGE_LOCATION}"
)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31ConfigVersion.cmake"
	COMPATIBILITY AnyNewerVersion
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31Config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31ConfigVersion.cmake"
	DESTINATION "${CONFIG_PACKAGE_LOCATION}"
)
install(EXPORT tr31Targets
	FILE tr31Targets.cmake
	DESTINATION "${CONFIG_PACKAGE_LOCATION}"
)

# generate and install pkgconfig file
set(PKGCONFIG_LOCATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig CACHE STRING "Installation location for pkgconfig files")
set(PKGCONFIG_LIB_NAME ${CMAKE_PROJECT_NAME})
set(PKGCONFIG_PKG_DEPS "libcrypto")
set(PKGCONFIG_LIBS_PRIV "-lcrypto")
configure_file(pkgconfig/libtr31.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	@ONLY
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	DESTINATION "${PKGCONFIG_LOCATION}"
)

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
