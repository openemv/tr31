##############################################################################
# Copyright (c) 2021 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

# This module will define:
#
# MbedTLS_FOUND
# MbedTLS_VERSION
# MbedTLS_INCLUDE_DIRS
# MbedTLS_LIBRARIES

# This module also provides the following imported targets, if found:
# - MbedTLS::mbedcrypto (Crypto library)
# - MbedTLS::mbedtls (TLS library)
# - MbedTLS::mbedx509 (X509 library)

find_path(MbedTLS_INCLUDE_DIR
	NAMES mbedtls/version.h
)

find_library(MbedTLS_mbedcrypto_LIBRARY
	NAMES mbedcrypto
)

find_library(MbedTLS_mbedtls_LIBRARY
	NAMES mbedtls
)

find_library(MbedTLS_mbedx509_LIBRARY
	NAMES mbedx509
)

if(EXISTS "${MbedTLS_INCLUDE_DIR}/mbedtls/version.h")
	file(STRINGS "${MbedTLS_INCLUDE_DIR}/mbedtls/version.h" MbedTLS_VERSION_STRING REGEX "^#define MBEDTLS_VERSION_STRING[ \\t]+\".*\"$")
	string(REGEX REPLACE "^#define MBEDTLS_VERSION_STRING[ \\t]+\"([0-9\\.]+)\"$" "\\1"
		MbedTLS_VERSION_STRING "${MbedTLS_VERSION_STRING}"
	)
	set(MbedTLS_VERSION "${MbedTLS_VERSION_STRING}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
	REQUIRED_VARS
		MbedTLS_mbedtls_LIBRARY
		MbedTLS_mbedcrypto_LIBRARY
		MbedTLS_mbedx509_LIBRARY
		MbedTLS_INCLUDE_DIR
	VERSION_VAR
		MbedTLS_VERSION
)

if(MbedTLS_FOUND)
	set(MbedTLS_INCLUDE_DIRS ${MbedTLS_INCLUDE_DIR})
	set(MbedTLS_LIBRARIES ${MbedTLS_mbedcrypto_LIBRARY} ${MbedTLS_mbedtls_LIBRARY} ${MbedTLS_mbedx509_LIBRARY})

	if(NOT TARGET MbedTLS::mbedcrypto)
		add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
		set_target_properties(MbedTLS::mbedcrypto
			PROPERTIES
				IMPORTED_LOCATION "${MbedTLS_mbedcrypto_LIBRARY}"
				INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
		)
	endif()

	if(NOT TARGET MbedTLS::mbedtls)
		add_library(MbedTLS::mbedtls UNKNOWN IMPORTED)
		set_target_properties(MbedTLS::mbedtls
			PROPERTIES
				IMPORTED_LOCATION "${MbedTLS_mbedtls_LIBRARY}"
				INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
		)
	endif()

	if(NOT TARGET MbedTLS::mbedx509)
		add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
		set_target_properties(MbedTLS::mbedx509
			PROPERTIES
				IMPORTED_LOCATION "${MbedTLS_mbedx509_LIBRARY}"
				INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
		)
	endif()
endif()

mark_as_advanced(
	MbedTLS_INCLUDE_DIR
	MbedTLS_mbedcrypto_LIBRARY
	MbedTLS_mbedtls_LIBRARY
	MbedTLS_mbedx509_LIBRARY
	MbedTLS_VERSION_STRING
)
