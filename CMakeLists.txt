##############################################################################
# Copyright (c) 2020, 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(tr31
	VERSION 0.3.0
	DESCRIPTION "TR-31 library and tools"
	HOMEPAGE_URL "https://github.com/ono-connect/tr31"
	LANGUAGES C
)

# Determine whether this project is the top-level project
if(${CMAKE_VERSION} VERSION_LESS "3.21")
	get_directory_property(TR31_HAS_PARENT PARENT_DIRECTORY)
	if(NOT TR31_HAS_PARENT)
		set(TR31_IS_TOP_LEVEL True)
	endif()
else()
	# CMake >=3.21 provides <PROJECT-NAME>_IS_TOP_LEVEL
	set(TR31_IS_TOP_LEVEL ${tr31_IS_TOP_LEVEL})
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	add_compile_options(-Wall -Werror)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

include(CTest)

# Allow parent scope to provide crypto targets when not building shared libs
if(TR31_IS_TOP_LEVEL OR BUILD_SHARED_LIBS)
	add_subdirectory(crypto EXCLUDE_FROM_ALL)
	add_subdirectory(crypto/test)
elseif (NOT TARGET crypto_tdes OR
	NOT TARGET crypto_aes OR
	NOT TARGET crypto_mem OR
	NOT TARGET crypto_rand)
	message(FATAL_ERROR "Parent project must provide crypto libraries for static builds")
endif()

add_subdirectory(src)
add_subdirectory(test)

include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables and good defaults for install()

# install README and LICENSE files to runtime component
install(FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/README.md"
	"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
	TYPE DOC
	COMPONENT tr31_runtime
)

# generate and install basic CMake config files
include(CMakePackageConfigHelpers) # provides CMake config generator macros
# NOTE: crypto subdirectory provides CRYPTO_PACKAGE_DEPENDENCIES
foreach(pkg IN LISTS CRYPTO_PACKAGE_DEPENDENCIES)
	# build dependency string for use in CMake config file
	string(APPEND TR31_CONFIG_PACKAGE_DEPENDENCIES "find_dependency(${pkg})\n")
endforeach()
set(TR31_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} CACHE STRING "Installation location for tr31 CMake config files")
message(STATUS "Using CMake config install location \"${TR31_INSTALL_CMAKEDIR}\"")
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
	NAMESPACE tr31::
	COMPONENT tr31_development
)
export(EXPORT tr31Targets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/tr31Targets.cmake"
	NAMESPACE tr31::
)

# generate and install pkgconfig file
set(TR31_INSTALL_PKGCONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig CACHE STRING "Installation location for tr31 pkgconfig files")
message(STATUS "Using pkgconfig install location \"${TR31_INSTALL_PKGCONFIG_DIR}\"")
set(TR31_PKGCONFIG_LIB_NAME ${CMAKE_PROJECT_NAME})
# NOTE: crypto subdirectory provides CRYPTO_PKGCONFIG_REQ_PRIV and CRYPTO_PKGCONFIG_LIBS_PRIV
set(TR31_PKGCONFIG_REQ_PRIV ${CRYPTO_PKGCONFIG_REQ_PRIV})
set(TR31_PKGCONFIG_LIBS_PRIV ${CRYPTO_PKGCONFIG_LIBS_PRIV})
configure_file(pkgconfig/libtr31.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	@ONLY
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libtr31.pc"
	DESTINATION "${TR31_INSTALL_PKGCONFIG_DIR}"
	COMPONENT tr31_development
)

# install bash-completion file
find_package(bash-completion) # optional for providing bash-completion files
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

# generate and install doxygen documentation
option(BUILD_DOCS "Build documentation")
find_package(Doxygen) # optional for generating doxygen files
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
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# configure generic component packaging attributes
set(CPACK_COMPONENT_TR31_DEVELOPMENT_DESCRIPTION "Development files for TR-31 library")
set(CPACK_COMPONENT_TR31_DOCS_DESCRIPTION "Documentation for TR-31 library")
set(CPACK_COMPONENT_TR31_DEVELOPMENT_DEPENDS tr31_runtime)

# NOTE: for monolithic packages, uncomment the line below or specify it when
# invoking CMake
#set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

find_package(dpkg) # optional for building Debian/Ubuntu packages
if(dpkg_FOUND)
	# configure CPack to generate .deb package
	list(APPEND CPACK_GENERATOR "DEB")
	# generate component packages
	# NOTE: this is overridden by CPACK_COMPONENTS_GROUPING above
	set(CPACK_DEB_COMPONENT_INSTALL ON)
	set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
	# use default debian package naming
	set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
	# assign package names to components
	set(CPACK_DEBIAN_TR31_RUNTIME_PACKAGE_NAME "tr31-runtime")
	set(CPACK_DEBIAN_TR31_DEVELOPMENT_PACKAGE_NAME "tr31-dev")
	set(CPACK_DEBIAN_TR31_DOCS_PACKAGE_NAME "tr31-doc")
	# assign package architecture to documentation component
	set(CPACK_DEBIAN_TR31_DOCS_PACKAGE_ARCHITECTURE "all")
	# assign package sections to components
	set(CPACK_DEBIAN_TR31_RUNTIME_PACKAGE_SECTION "utils")
	set(CPACK_DEBIAN_TR31_DEVELOPMENT_PACKAGE_SECTION "devel")
	set(CPACK_DEBIAN_TR31_DOCS_PACKAGE_SECTION "doc")
	# assign package suggestions
	set(CPACK_DEBIAN_TR31_DOCS_PACKAGE_SUGGESTS "tr31-dev")
	# generate package dependency list
	set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()

find_package(rpmbuild) # optional for building RedHat/Fedora packages
if(rpmbuild_FOUND)
	list(APPEND CPACK_GENERATOR "RPM")
	# generate component packages
	# NOTE: this is overridden by CPACK_COMPONENTS_GROUPING above
	set(CPACK_RPM_COMPONENT_INSTALL ON)
	# use default rpm package naming
	set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
	# configure license and changelog
	set(CPACK_RPM_PACKAGE_LICENSE "LGPLv2+")
	set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm_changelog.txt")
	# assign package names to components
	set(CPACK_RPM_TR31_RUNTIME_PACKAGE_NAME "tr31-runtime")
	set(CPACK_RPM_TR31_DEVELOPMENT_PACKAGE_NAME "tr31-devel")
	set(CPACK_RPM_TR31_DOCS_PACKAGE_NAME "tr31-doc")
	# assign package architecture to documentation component
	set(CPACK_RPM_TR31_DOCS_PACKAGE_ARCHITECTURE "noarch")
	# assign package suggestions
	set(CPACK_RPM_TR31_DOCS_PACKAGE_SUGGESTS "tr31-devel")
	# NOTE: RPM generator automatically detects dependencies
endif()

include(CPack)
