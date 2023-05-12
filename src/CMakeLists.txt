##############################################################################
# Copyright (c) 2020, 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

# check for headers that provide ntohs/htons and friends
include(CheckIncludeFile)
CHECK_INCLUDE_FILE(
	arpa/inet.h
	HAVE_ARPA_INET_H
)
CHECK_INCLUDE_FILE(
	winsock.h
	HAVE_WINSOCK_H
)
if(NOT HAVE_ARPA_INET_H AND NOT HAVE_WINSOCK_H)
	message(FATAL_ERROR "Failed to find either arpa/inet.h or winsock.h")
endif()

# build TR-31 tool by default
option(BUILD_TR31_TOOL "Build tr31-tool" ON)

# check for argp or allow the FETCH_ARGP option to download and build a local
# copy of libargp for monolithic builds on platforms without package managers
# like MacOS and Windows.
option(FETCH_ARGP "Download and build libargp")
if(FETCH_ARGP)
	set(ARGP_OSX_ARCHITECTURES ${CMAKE_OSX_ARCHITECTURES})
	include(FetchLibArgp)
else()
	find_package(argp)
endif()
if(NOT argp_FOUND)
	if(BUILD_TR31_TOOL)
		message(FATAL_ERROR "Could NOT find argp. Enable FETCH_ARGP to download and build libargp. This is required to build tr31-tool.")
	endif()
endif()

# check for features required for date/time conversion:
# locale.h, time.h, setlocale(), strptime() and timegm()
include(CheckIncludeFile)
include(CheckSymbolExists)
CHECK_INCLUDE_FILE(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILE(time.h HAVE_TIME_H)
check_symbol_exists(setlocale locale.h HAVE_SETLOCALE)
check_symbol_exists(strptime time.h HAVE_STRPTIME)
set(TIME_H_DEFINITIONS_TRY _GNU_SOURCE) # Retry using _GNU_SOURCE
if(NOT HAVE_STRPTIME)
	unset(HAVE_STRPTIME CACHE)
	list(APPEND CMAKE_REQUIRED_DEFINITIONS -D${TIME_H_DEFINITIONS_TRY})
	check_symbol_exists(strptime time.h HAVE_STRPTIME)
	list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D${TIME_H_DEFINITIONS_TRY})
	if(HAVE_STRPTIME)
		set(TIME_H_DEFINITIONS ${TIME_H_DEFINITIONS_TRY})
	endif()
endif()
check_symbol_exists(timegm time.h HAVE_TIMEGM)
if(NOT HAVE_TIMEGM)
	unset(HAVE_TIMEGM CACHE)
	list(APPEND CMAKE_REQUIRED_DEFINITIONS -D${TIME_H_DEFINITIONS_TRY})
	check_symbol_exists(timegm time.h HAVE_TIMEGM)
	list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D${TIME_H_DEFINITIONS_TRY})
	if(HAVE_TIMEGM)
		set(TIME_H_DEFINITIONS ${TIME_H_DEFINITIONS_TRY})
	endif()
endif()
if(HAVE_SETLOCALE AND HAVE_STRPTIME AND HAVE_TIMEGM)
	message(STATUS "Enabling date/time conversion")
	set(TR31_ENABLE_DATETIME_CONVERSION ON)
else()
	message(STATUS "Disabling date/time conversion; some tests may fail")
	set(TR31_ENABLE_DATETIME_CONVERSION OFF)
endif()

include(GNUInstallDirs) # provides CMAKE_INSTALL_* variables and good defaults for install()

# generate config file for internal use only
# this file should NOT be installed or used by an installed header
configure_file(
	tr31_config.h.in
	tr31_config.h
)

# TR-31 library
add_library(tr31
	tr31.c
	tr31_crypto.c
	tr31_strings.c
)
if(TIME_H_DEFINITIONS)
	set_source_files_properties(tr31_strings.c
		PROPERTIES
			COMPILE_DEFINITIONS ${TIME_H_DEFINITIONS}
	)
endif()
set_target_properties(tr31
	PROPERTIES
		PUBLIC_HEADER tr31.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}
)
target_include_directories(tr31 PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # for generated config file
target_include_directories(tr31 INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(tr31 PRIVATE crypto_tdes crypto_aes crypto_mem crypto_rand)
if(HAVE_WINSOCK_H AND NOT HAVE_ARPA_INET_H)
	target_link_libraries(tr31 PRIVATE ws2_32)
endif()

install(
	TARGETS
		crypto_tdes
		crypto_aes
		crypto_mem
		crypto_rand
		tr31
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

# TR-31 command line tool
if(BUILD_TR31_TOOL)
	add_executable(tr31-tool tr31-tool.c)
	target_link_libraries(tr31-tool PRIVATE tr31)
	if(TARGET libargp::argp)
		target_link_libraries(tr31-tool PRIVATE libargp::argp)
	endif()

	install(
		TARGETS
			tr31-tool
		EXPORT tr31Targets # for use by install(EXPORT) command
		RUNTIME
			COMPONENT tr31_runtime
	)
endif()

if(TARGET tr31-tool AND BUILD_TESTING)
	add_test(NAME tr31_tool_test1
		COMMAND tr31-tool --import B0128B1TX00N0300KS18FFFF00A0200001E00000KC0C000169E3KP0C00ECAD626F9F1A826814AA066D86C8C18BD0E14033E1EBEC75BEDF586E6E325F3AA8C0E5 --kbpk AB2E09DB3EF0BA71E0CE6CD755C23A3B
	)
	set_tests_properties(tr31_tool_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "Key value: BF82DAC6A33DF92CE66E15B70E5DCEB6 \\(KCV: 0169E3\\)"
	)

	add_test(NAME tr31_tool_test2
		COMMAND tr31-tool --import D0112B0TN00N000037DB9B046B7B0048785690759580ABC3B9842AB4BB7717B49E92528E575785D8123559376A2553B27BE94F054F4E971C --kbpk 4141414141414141414141414141414141414141414141414141414141414141
	)
	set_tests_properties(tr31_tool_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "Key value: 1FA1F7CEC798D91545DA8AE0C7796BD9 \\(KCV: FF5087\\)"
	)

	add_test(NAME tr31_tool_test3
		COMMAND tr31-tool --import D0144B0AN00N0000DCD6D7E8108277E3304831A744F741A51A30695A2F764C6E42A1F54086FF0C3F5F9BEC889F20C6F613EF790A09381A5855B9464E598CBE24E537B6FE0F602297 --kbpk 4141414141414141414141414141414141414141414141414141414141414141
	)
	set_tests_properties(tr31_tool_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "Key value: 6189A1111AAB43DC8BEAEEAE29799C4212070D66F8933EFACE8879C7DB609DEA \\(KCV: 69EBA40B13\\)"
	)

	add_test(NAME tr31_tool_test4
		COMMAND tr31-tool --import D0144B0AN00N000004E08A6000D7B21A5CFFE0F24E449A21D9BE3F975D33DB02D50CF9A6CCD2F6B6DB375CBCCCA648E0FB991432CA3957E810B087CDA7FA44538CC94C97FFF6D696 --kbpk 4141414141414141414141414141414141414141414141414141414141414141
	)
	set_tests_properties(tr31_tool_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "Key value: 6189A1111AAB43DC8BEAEEAE29799C4212070D66F8933EFACE8879C7DB609DEA \\(KCV: 69EBA40B13\\)"
	)

	add_test(NAME tr31_tool_test5
		COMMAND tr31-tool --import D0144D0AN00N0000127862F945C2DED04530FAF7CDBC8B0BA10C7AA79BD5E0C2C5D6AC173BF588E4B19ACF1357178D50EA0AB193228E13958304FC6149632DFDCADF3A5B3D57E814 --kbpk 4141414141414141414141414141414141414141414141414141414141414141
	)
	set_tests_properties(tr31_tool_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "Key value: BE19E6A07A760F10EF8E83A226B63AAD141F463FDDD4F47DB244B4023EC3CACC \\(KCV: 0A00E31EEB\\)"
	)

	add_test(NAME tr31_tool_test6
		COMMAND tr31-tool --kbpk 1D22BF32387C600AD97F9B97A51311AC --export E8BC63E5479455E26577F715D587FE68 --export-key-algorithm TDES --export-format-version B --export-template IK
	)
	set_tests_properties(tr31_tool_test6
		PROPERTIES
			WILL_FAIL TRUE # because --export-opt-block-KS is absent
	)

	add_test(NAME tr31_tool_test7
		COMMAND tr31-tool --kbpk B8ED59E0A279A295E9F5ED7944FD06B9 --export EDB380DD340BC2620247D445F5B8D678 --export-key-algorithm TDES --export-format-version C --export-template BDK
	)
	set_tests_properties(tr31_tool_test7
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^C0072B0TX00E0000"
	)

	add_test(NAME tr31_tool_test8
		COMMAND tr31-tool --kbpk 88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6 --export 3F419E1CB7079442AA37474C2EFBF8B8 --export-key-algorithm AES --export-format-version D --export-template KEK
	)
	set_tests_properties(tr31_tool_test8
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0112K0AB00E0000"
	)

	add_test(NAME tr31_tool_test9
		COMMAND tr31-tool --kbpk 1D22BF32387C600AD97F9B97A51311AC --export E8BC63E5479455E26577F715D587FE68 --export-header B0080B1TX00N0000
	)
	set_tests_properties(tr31_tool_test9
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^B0080B1TX00N0000"
	)

	add_test(NAME tr31_tool_test10
		COMMAND tr31-tool --kbpk B8ED59E0A279A295E9F5ED7944FD06B9 --export EDB380DD340BC2620247D445F5B8D678 --export-header C0072B0TX00E0000
	)
	set_tests_properties(tr31_tool_test10
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^C0072B0TX00E0000"
	)

	add_test(NAME tr31_tool_test11
		COMMAND tr31-tool --kbpk 88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6 --export 3F419E1CB7079442AA37474C2EFBF8B8 --export-header D0112K0AB00E0000
	)
	set_tests_properties(tr31_tool_test11
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0112K0AB00E0000"
	)

	add_test(NAME tr31_tool_test12
		COMMAND tr31-tool --kbpk 1D22BF32387C600AD97F9B97A51311AC --export E8BC63E5479455E26577F715D587FE68 --export-key-algorithm TDES --export-format-version B --export-template IK --export-opt-block-KS FFFF00A0200001E00000
	)
	set_tests_properties(tr31_tool_test12
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^B0104B1TX00N0100KS18FFFF00A0200001E00000"
	)

	add_test(NAME tr31_tool_test13
		COMMAND tr31-tool --kbpk 1D22BF32387C600AD97F9B97A51311AC --export E8BC63E5479455E26577F715D587FE68 --export-header B0000B1TX00N0000 --export-opt-block-KS FFFF00A0200001E00000
	)
	set_tests_properties(tr31_tool_test13
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^B0104B1TX00N0100KS18FFFF00A0200001E00000"
	)

	add_test(NAME tr31_tool_test14
		COMMAND tr31-tool --kbpk B8ED59E0A279A295E9F5ED7944FD06B9 --export EDB380DD340BC2620247D445F5B8D678 --export-key-algorithm TDES --export-format-version C --export-template BDK --export-opt-block-KC --export-opt-block-KP
	)
	set_tests_properties(tr31_tool_test14
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^C0096B0TX00E0200KC0C00F4B08DKP0C002F0EEA"
	)

	add_test(NAME tr31_tool_test15
		COMMAND tr31-tool --kbpk 88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6 --export 3F419E1CB7079442AA37474C2EFBF8B8 --export-key-algorithm AES --export-format-version D --export-template KEK --export-opt-block-KC --export-opt-block-KP
	)
	set_tests_properties(tr31_tool_test15
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0144K0AB00E0200KC100108793E25ABKP10012331550BC9"
	)

	add_test(NAME tr31_tool_test16
		COMMAND tr31-tool --kbpk 4141414141414141414141414141414141414141414141414141414141414141 --export 1273671EA26AC29AFA4D1084127652A1 --export-key-algorithm AES --export-format-version D --export-template IK --export-opt-block-IK 1234567890123456
	)
	set_tests_properties(tr31_tool_test16
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0144B1AX00N0200IK141234567890123456PB0C" # omit random optional block padding digits
	)

	add_test(NAME tr31_tool_test17
		COMMAND tr31-tool --kbpk 4141414141414141414141414141414141414141414141414141414141414141 --export 1273671EA26AC29AFA4D1084127652A1 --export-header D0000B1AX00N0000 --export-opt-block-IK 1234567890123456
	)
	set_tests_properties(tr31_tool_test17
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0144B1AX00N0200IK141234567890123456PB0C" # omit random optional block padding digits
	)

	add_test(NAME tr31_tool_test18
		COMMAND tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 777261707065642033444553206B6579 --export-header E0084B0TV16N0000
	)
	set_tests_properties(tr31_tool_test18
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A52DB52F0AEACB94C57547"
	)

	add_test(NAME tr31_tool_test19
		COMMAND tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 777261707065642033444553206B6579 --export-key-algorithm TDES --export-format-version E --export-template BDK
	)
	set_tests_properties(tr31_tool_test19
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^E0084B0TX00E000091549081F898337CE9C68236C1349B6151AB4B48F77C61348C94CD65537306BEE1C5"
	)

	add_test(NAME tr31_tool_test20
		COMMAND tr31-tool --import D0144B1TX00S0200KS181ED9D500000001200000PB08nD8U3CAC6F42EF3E1711310E8BC2738E30211D3A1AB6EA61254CE37B5C162C743D1DAB6C866E69354E0276D7E744AAFB3425 --kbpk 0123456789ABCDEFFEDCBA9876543210
	)
	string(CONCAT tr31_tool_test20_regex
		"^Key block format version: D[\r\n]"
		"Key block length: 144 bytes[\r\n]"
		".*"
		"Optional blocks \\[2\\]:[\r\n]"
		"\t\\[KS\\] Initial Key Serial Number \\(KSN\\): 1ED9D500000001200000[\r\n]"
		"\t\\[PB\\] Padding Block: \"nD8U\"[\r\n]"
		"Key length: 16[\r\n]"
		"Key value: 4AC3A7637268E618C52C97CE7766F26A \\(KCV: 72098B\\)[\r\n]"
	)
	set_tests_properties(tr31_tool_test20
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${tr31_tool_test20_regex}
	)

	add_test(NAME tr31_tool_test21
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --export 4AC3A7637268E618C52C97CE7766F26A --export-header D0000D0TB00S0000 --export-opt-block-TC 20190717181929Z --export-opt-block-TS 20200818192030Z
	)
	set_tests_properties(tr31_tool_test21
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0160D0TB00S0300TC1320190717181929ZTS1320200818192030ZPB0A"
	)

	add_test(NAME tr31_tool_test22
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --export 4AC3A7637268E618C52C97CE7766F26A --export-header D0000D0TB00S0000 --export-opt-block-TC 2019071718192921Z --export-opt-block-TS 2020081819203022Z
	)
	set_tests_properties(tr31_tool_test22
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0160D0TB00S0300TC152019071718192921ZTS152020081819203022ZPB06"
	)

	add_test(NAME tr31_tool_test23
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --export 4AC3A7637268E618C52C97CE7766F26A --export-header D0000D0TB00S0000 --export-opt-block-TC 2017-05-17T19:41:38Z --export-opt-block-TS 2018-06-18T20:42:39Z
	)
	set_tests_properties(tr31_tool_test23
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0160D0TB00S0200TC182017-05-17T19:41:38ZTS182018-06-18T20:42:39"
	)

	add_test(NAME tr31_tool_test24
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --export 4AC3A7637268E618C52C97CE7766F26A --export-header D0000D0TB00S0000 --export-opt-block-TC 2017-05-17T19:41:38.21Z --export-opt-block-TS 2018-06-18T20:42:39.22Z
	)
	set_tests_properties(tr31_tool_test24
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^D0176D0TB00S0300TC1B2017-05-17T19:41:38.21ZTS1B2018-06-18T20:42:39.22ZPB0A"
	)

	add_test(NAME tr31_tool_test25
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --import D0160D0TB00S0300TC1320190717181929ZTS1320200818192030ZPB0AMn6Rg3B31D549F386D00422AA0C5BA5DAF057C1AA495ACC79AF92500D381AD3F3462F927DDA9DCFB6158C33B5D63CA08791F76
	)
	string(CONCAT tr31_tool_test25_regex
		"^Key block format version: D[\r\n]"
		"Key block length: 160 bytes[\r\n]"
		".*"
		"Optional blocks \\[3\\]:[\r\n]"
		"\t\\[TC\\] Time of Creation: \"20190717181929Z\" \\(.*\\)[\r\n]"
		"\t\\[TS\\] Time Stamp: \"20200818192030Z\" \\(.*\\)[\r\n]"
		"\t\\[PB\\] Padding Block: \"Mn6Rg3\"[\r\n]"
		"Key length: 16[\r\n]"
		"Key value: 4AC3A7637268E618C52C97CE7766F26A \\(KCV: 72098B\\)[\r\n]"
	)
	set_tests_properties(tr31_tool_test25
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${tr31_tool_test25_regex}
	)

	add_test(NAME tr31_tool_test26
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --import D0160D0TB00S0300TC152019071718192921ZTS152020081819203022ZPB063r3AFB97760D5C46D3EE774A00FA8C1393F259B5862F89AC477F66560B593A2CE20EE5638FE26717B7DB067D508B2C3A98
	)
	string(CONCAT tr31_tool_test26_regex
		"^Key block format version: D[\r\n]"
		"Key block length: 160 bytes[\r\n]"
		".*"
		"Optional blocks \\[3\\]:[\r\n]"
		"\t\\[TC\\] Time of Creation: \"2019071718192921Z\" \\(.*\\)[\r\n]"
		"\t\\[TS\\] Time Stamp: \"2020081819203022Z\" \\(.*\\)[\r\n]"
		"\t\\[PB\\] Padding Block: \"3r\"[\r\n]"
		"Key length: 16[\r\n]"
		"Key value: 4AC3A7637268E618C52C97CE7766F26A \\(KCV: 72098B\\)[\r\n]"
	)
	set_tests_properties(tr31_tool_test26
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${tr31_tool_test26_regex}
	)

	add_test(NAME tr31_tool_test27
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --import D0160D0TB00S0200TC182017-05-17T19:41:38ZTS182018-06-18T20:42:39Z8334D53013CF72F36AC047C75ADDB106075ACD7F179C07D21D0DCE06D2F507BC16FA0E3C2C2A5266A55D220F35A3C920
	)
	string(CONCAT tr31_tool_test27_regex
		"^Key block format version: D[\r\n]"
		"Key block length: 160 bytes[\r\n]"
		".*"
		"Optional blocks \\[2\\]:[\r\n]"
		"\t\\[TC\\] Time of Creation: \"2017-05-17T19:41:38Z\" \\(.*\\)[\r\n]"
		"\t\\[TS\\] Time Stamp: \"2018-06-18T20:42:39Z\" \\(.*\\)[\r\n]"
		"Key length: 16[\r\n]"
		"Key value: 4AC3A7637268E618C52C97CE7766F26A \\(KCV: 72098B\\)[\r\n]"
	)
	set_tests_properties(tr31_tool_test27
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${tr31_tool_test27_regex}
	)

	add_test(NAME tr31_tool_test28
		COMMAND tr31-tool --kbpk 0123456789ABCDEFFEDCBA9876543210 --import D0176D0TB00S0300TC1B2017-05-17T19:41:38.21ZTS1B2018-06-18T20:42:39.22ZPB0A0tGy4eABD31E32E882F6BC6E198890F6EDA720396691AC57710BBC6CF22CC164A1E80D06FE38EE315657DD0DA9ED1EDC6754B2
	)
	string(CONCAT tr31_tool_test28_regex
		"^Key block format version: D[\r\n]"
		"Key block length: 176 bytes[\r\n]"
		".*"
		"Optional blocks \\[3\\]:[\r\n]"
		"\t\\[TC\\] Time of Creation: \"2017-05-17T19:41:38.21Z\" \\(.*\\)[\r\n]"
		"\t\\[TS\\] Time Stamp: \"2018-06-18T20:42:39.22Z\" \\(.*\\)[\r\n]"
		"\t\\[PB\\] Padding Block: \"0tGy4e\"[\r\n]"
		"Key length: 16[\r\n]"
		"Key value: 4AC3A7637268E618C52C97CE7766F26A \\(KCV: 72098B\\)[\r\n]"
	)
	set_tests_properties(tr31_tool_test28
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${tr31_tool_test28_regex}
	)
endif()
