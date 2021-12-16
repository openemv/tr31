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

# This module also provides the following alias targets:
# - MbedTLS::mbedcrypto (Crypto library)
# - MbedTLS::mbedtls (TLS library)
# - MbedTLS::mbedx509 (X509 library)

include(FetchContent)

message(CHECK_START "Downloading and configuring MbedTLS...")
FetchContent_Declare(
	MbedTLS
	URL "https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.0.0.tar.gz"
	URL_HASH SHA256=525bfde06e024c1218047dee1c8b4c89312df1a4b5658711009086cda5dfaa55
)

if (BUILD_TESTING)
	FetchContent_MakeAvailable(MbedTLS)
else()
	# Manually populate content to add EXCLUDE_FROM_ALL
	# and ignore testing (faster builds)
	FetchContent_GetProperties(MbedTLS)
	if(NOT depname_POPULATED)
		FetchContent_Populate(MbedTLS)
		add_subdirectory(${mbedtls_SOURCE_DIR} ${mbedtls_BINARY_DIR} EXCLUDE_FROM_ALL)
	endif()
endif()
message(CHECK_PASS "done")

# Add library aliases according to the names in _deps/mbedtls-src/library/CMakeLists.txt
add_library(MbedTLS::mbedcrypto ALIAS mbedcrypto)
add_library(MbedTLS::mbedtls ALIAS mbedtls)
add_library(MbedTLS::mbedx509 ALIAS mbedx509)

# MbedTLS is now ready to use
set(MbedTLS_FOUND True)
set(MbedTLS_VERSION 3.0.0)
