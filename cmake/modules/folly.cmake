# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

#
# Minimal Folly (ConcurrentHashMap and transitive deps) via FetchContent.
#
# Downloads Facebook Folly v2026.02.23.00, applies patches, and builds a static library called
# folly_minimal with only the minimal source files needed for ConcurrentHashMap support. See
# proposals/20260212-thread-safe-thread-manager.md and cmake/patches/folly/ for details.
#
# Requires: fmt, double-conversion, glog (included before this module in libsinsp.cmake).
#
# System Folly is not supported; the minimal subset is always built from the bundled sources below.
#

if(TARGET folly_minimal)
	# folly already available
else()
	include(FetchContent)

	set(FOLLY_PATCHES_DIR "${CMAKE_CURRENT_LIST_DIR}/../patches/folly")

	FetchContent_Declare(
		folly
		URL https://github.com/facebook/folly/archive/refs/tags/v2026.02.23.00.tar.gz
		URL_HASH SHA256=b8cd7d15220d07c939acda904b7a96096e91f42300a8dc865f5022236b1b8b94
		# SOURCE_SUBDIR pointing to a nonexistent directory prevents FetchContent_MakeAvailable from
		# processing Folly's own CMakeLists.txt. We define folly_minimal ourselves below.
		SOURCE_SUBDIR _do_not_build
		PATCH_COMMAND
			${CMAKE_COMMAND} -E copy ${FOLLY_PATCHES_DIR}/folly-config.h
			<SOURCE_DIR>/folly/folly-config.h COMMAND patch -p1 --forward -d <SOURCE_DIR> -i
			${FOLLY_PATCHES_DIR}/folly-minimal.patch || true
	)

	FetchContent_MakeAvailable(folly)

	add_library(
		folly_minimal STATIC
		${folly_SOURCE_DIR}/folly/concurrency/CacheLocality.cpp
		${folly_SOURCE_DIR}/folly/container/detail/F14Table.cpp
		${folly_SOURCE_DIR}/folly/detail/Futex.cpp
		${folly_SOURCE_DIR}/folly/detail/StaticSingletonManager.cpp
		${folly_SOURCE_DIR}/folly/detail/thread_local_globals.cpp
		${folly_SOURCE_DIR}/folly/detail/ThreadLocalDetail.cpp
		${folly_SOURCE_DIR}/folly/detail/UniqueInstance.cpp
		${folly_SOURCE_DIR}/folly/Demangle.cpp
		${folly_SOURCE_DIR}/folly/ExceptionString.cpp
		${folly_SOURCE_DIR}/folly/lang/CString.cpp
		${folly_SOURCE_DIR}/folly/lang/Exception.cpp
		${folly_SOURCE_DIR}/folly/lang/SafeAssert.cpp
		${folly_SOURCE_DIR}/folly/lang/ToAscii.cpp
		${folly_SOURCE_DIR}/folly/memory/Malloc.cpp
		${folly_SOURCE_DIR}/folly/memory/SanitizeLeak.cpp
		${folly_SOURCE_DIR}/folly/memory/detail/MallocImpl.cpp
		${folly_SOURCE_DIR}/folly/memory/ReentrantAllocator.cpp
		${folly_SOURCE_DIR}/folly/portability/SysMembarrier.cpp
		${folly_SOURCE_DIR}/folly/ScopeGuard.cpp
		${folly_SOURCE_DIR}/folly/SharedMutex.cpp
		${folly_SOURCE_DIR}/folly/SingletonThreadLocal.cpp
		${folly_SOURCE_DIR}/folly/synchronization/AsymmetricThreadFence.cpp
		${folly_SOURCE_DIR}/folly/synchronization/Hazptr.cpp
		${folly_SOURCE_DIR}/folly/synchronization/HazptrDomain.cpp
		${folly_SOURCE_DIR}/folly/synchronization/ParkingLot.cpp
		${folly_SOURCE_DIR}/folly/synchronization/SanitizeThread.cpp
		${folly_SOURCE_DIR}/folly/system/AtFork.cpp
		${folly_SOURCE_DIR}/folly/system/ThreadId.cpp
	)

	if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
		if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
			message(FATAL_ERROR "Folly requires a 64bit target architecture.")
		endif()
		if(MSVC_VERSION LESS 1900)
			message(
				FATAL_ERROR
					"This build script only supports building Folly on 64-bit Windows with "
					"at least Visual Studio 2017. "
					"MSVC version '${MSVC_VERSION}' is not supported."
			)
		endif()
	endif()

	if(NOT DEFINED FOLLY_HAVE_INT128_T)
		include(CheckTypeSize)
		check_type_size("__int128_t" FOLLY_INT128_T_SIZE)
		if(HAVE_FOLLY_INT128_T_SIZE)
			set(FOLLY_HAVE_INT128_T TRUE)
		endif()
	endif()

	target_include_directories(folly_minimal PUBLIC ${folly_SOURCE_DIR})
	target_compile_features(folly_minimal PUBLIC cxx_std_17)

	# fmt (vendored via cmake/modules/fmt.cmake)
	target_include_directories(folly_minimal PRIVATE "${FMT_INCLUDE_DIR}")
	target_link_libraries(folly_minimal PRIVATE "${FMT_LIB}")
	add_dependencies(folly_minimal fmt)

	# double-conversion must be PUBLIC because folly/Conv.h (a public header) includes
	# <double-conversion/double-conversion.h>.
	find_package(Threads REQUIRED)
	target_link_libraries(
		folly_minimal PUBLIC double-conversion glog::glog Threads::Threads ${CMAKE_DL_LIBS}
	)
endif()
