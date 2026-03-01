# SPDX-License-Identifier: Apache-2.0
#
# Minimal Folly static library for ConcurrentHashMap and its transitive deps. See
# proposals/20260212-thread-safe-thread-manager.md and NOTICES.
#

add_library(
	folly_minimal STATIC
	folly/concurrency/CacheLocality.cpp
	folly/container/detail/F14Table.cpp
	folly/detail/Futex.cpp
	folly/detail/StaticSingletonManager.cpp
	folly/detail/thread_local_globals.cpp
	folly/detail/ThreadLocalDetail.cpp
	folly/detail/UniqueInstance.cpp
	folly/Demangle.cpp
	folly/ExceptionString.cpp
	folly/lang/CString.cpp
	folly/lang/Exception.cpp
	folly/lang/SafeAssert.cpp
	folly/lang/ToAscii.cpp
	folly/memory/Malloc.cpp
	folly/memory/detail/MallocImpl.cpp
	folly/memory/ReentrantAllocator.cpp
	folly/portability/SysMembarrier.cpp
	folly/ScopeGuard.cpp
	folly/SharedMutex.cpp
	folly/SingletonThreadLocal.cpp
	folly/synchronization/AsymmetricThreadFence.cpp
	folly/synchronization/Hazptr.cpp
	folly/synchronization/HazptrDomain.cpp
	folly/synchronization/ParkingLot.cpp
	folly/synchronization/SanitizeThread.cpp
	folly/system/AtFork.cpp
	folly/system/ThreadId.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Check target architecture
  if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Folly requires a 64bit target architecture.")
  endif()

  if (MSVC_VERSION LESS 1900)
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

target_include_directories(folly_minimal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(folly_minimal PUBLIC cxx_std_17)

# fmt is a required dependency (vendored via cmake/modules/fmt.cmake)
target_include_directories(folly_minimal PRIVATE "${FMT_INCLUDE_DIR}")
target_link_libraries(folly_minimal PRIVATE "${FMT_LIB}")
add_dependencies(folly_minimal fmt)

# double-conversion and glog are included from cmake/modules/libsinsp.cmake before this
# subdirectory. double-conversion must be PUBLIC because folly/Conv.h (a public header) includes
# <double-conversion/double-conversion.h>.
find_package(Threads REQUIRED)
target_link_libraries(
	folly_minimal PUBLIC double-conversion glog::glog Threads::Threads ${CMAKE_DL_LIBS}
)
