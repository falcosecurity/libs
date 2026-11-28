# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
#
# Regression test for issue #3121: ensure libsinsp.pc correctly references tbb or tbb32 based on
# platform pointer size.
#
# This test validates that:
#
# * On 64-bit platforms (CMAKE_SIZEOF_VOID_P=8), libsinsp.pc requires 'tbb'.
#
# * On 32-bit platforms (CMAKE_SIZEOF_VOID_P!=8), libsinsp.pc requires 'tbb32'.
#
# Emscripten builds do not link TBB, so Requires.private has no tbb module and this check is
# skipped. See the EMSCRIPTEN guard in userspace/libsinsp/CMakeLists.txt.

cmake_minimum_required(VERSION 3.5.1)

# libsinsp omits TBB from Requires.private when EMSCRIPTEN is set.
if(EMSCRIPTEN)
	message(STATUS "Skipping TBB pkg-config module check under Emscripten")
	return()
endif()

# Determine expected pkg-config module name based on pointer size
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(EXPECTED_TBB_MODULE "tbb")
else()
	set(EXPECTED_TBB_MODULE "tbb32")
endif()

message(STATUS "Testing TBB pkg-config module selection:")
message(STATUS "  CMAKE_SIZEOF_VOID_P: ${CMAKE_SIZEOF_VOID_P}")
message(STATUS "  Expected module: ${EXPECTED_TBB_MODULE}")

# Check if SINSP_PKGCONFIG_REQUIRES_PRIVATE contains the expected module
if(NOT DEFINED SINSP_PKGCONFIG_REQUIRES_PRIVATE)
	message(FATAL_ERROR "SINSP_PKGCONFIG_REQUIRES_PRIVATE is not defined")
endif()

# Convert to string for pattern matching
string(REPLACE ";" " " _requires_private_str "${SINSP_PKGCONFIG_REQUIRES_PRIVATE}")
message(STATUS "  Requires.private: ${_requires_private_str}")

# Check for the expected module
string(FIND "${_requires_private_str}" "${EXPECTED_TBB_MODULE}" _found_pos)
if(_found_pos EQUAL -1)
	message(
		FATAL_ERROR
			"Expected '${EXPECTED_TBB_MODULE}' not found in Requires.private: ${_requires_private_str}"
	)
endif()

# On 64-bit, ensure we don't have tbb32 instead of tbb
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	string(FIND "${_requires_private_str}" "tbb32" _wrong_module_pos)
	if(NOT _wrong_module_pos EQUAL -1)
		message(
			FATAL_ERROR "Found 'tbb32' on 64-bit platform, expected 'tbb': ${_requires_private_str}"
		)
	endif()
endif()

# On 32-bit, ensure we don't have tbb instead of tbb32
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	# Check that standalone 'tbb' is not present (allow 'tbb32')
	string(REGEX MATCH "(^|[^0-9])tbb($|[^0-9])" _wrong_module_match "${_requires_private_str}")
	if(_wrong_module_match)
		message(
			FATAL_ERROR "Found 'tbb' on 32-bit platform, expected 'tbb32': ${_requires_private_str}"
		)
	endif()
endif()

message(STATUS "  ✓ Test passed: correct TBB pkg-config module selected")
