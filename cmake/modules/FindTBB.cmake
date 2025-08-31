# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

# FindTBB.cmake - Find TBB (Threading Building Blocks) library
# This module provides a fallback when TBBConfig.cmake is not available
#
# This module defines the following variables:
#   TBB_FOUND        - True if TBB was found
#   TBB_INCLUDE_DIRS - TBB include directories
#   TBB_LIBRARIES    - TBB libraries
#   TBB_VERSION      - TBB version (if available)
#
# This module also creates the following imported targets:
#   TBB::tbb         - Main TBB library target

# Try to find TBB using pkg-config first
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_TBB QUIET tbb)
endif()

# Find TBB include directory
find_path(TBB_INCLUDE_DIR
    NAMES tbb/tbb.h
    HINTS
        ${PC_TBB_INCLUDEDIR}
        ${PC_TBB_INCLUDE_DIRS}
        $ENV{TBB_ROOT}/include
        $ENV{TBBROOT}/include
        /usr/include
        /usr/local/include
        /opt/intel/tbb/include
        /opt/intel/oneapi/tbb/latest/include
    PATH_SUFFIXES
        tbb
        include
)

# Find TBB library
find_library(TBB_LIBRARY
    NAMES tbb
    HINTS
        ${PC_TBB_LIBDIR}
        ${PC_TBB_LIBRARY_DIRS}
        $ENV{TBB_ROOT}/lib
        $ENV{TBBROOT}/lib
        /usr/lib
        /usr/local/lib
        /opt/intel/tbb/lib
        /opt/intel/oneapi/tbb/latest/lib
    PATH_SUFFIXES
        lib
        lib64
)

# Find TBB version (try to extract from header file)
if(TBB_INCLUDE_DIR)
    set(TBB_VERSION "")
    if(EXISTS "${TBB_INCLUDE_DIR}/tbb/tbb_stddef.h")
        file(STRINGS "${TBB_INCLUDE_DIR}/tbb/tbb_stddef.h" TBB_VERSION_MAJOR_LINE REGEX "^#define TBB_VERSION_MAJOR")
        file(STRINGS "${TBB_INCLUDE_DIR}/tbb/tbb_stddef.h" TBB_VERSION_MINOR_LINE REGEX "^#define TBB_VERSION_MINOR")
        if(TBB_VERSION_MAJOR_LINE AND TBB_VERSION_MINOR_LINE)
            string(REGEX REPLACE "^#define TBB_VERSION_MAJOR ([0-9]+)$" "\\1" TBB_VERSION_MAJOR "${TBB_VERSION_MAJOR_LINE}")
            string(REGEX REPLACE "^#define TBB_VERSION_MINOR ([0-9]+)$" "\\1" TBB_VERSION_MINOR "${TBB_VERSION_MINOR_LINE}")
            set(TBB_VERSION "${TBB_VERSION_MAJOR}.${TBB_VERSION_MINOR}")
        endif()
    endif()
endif()

# Set TBB_FOUND based on what we found
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TBB
    REQUIRED_VARS TBB_LIBRARY TBB_INCLUDE_DIR
    VERSION_VAR TBB_VERSION
)

# Set TBB variables
if(TBB_FOUND)
    set(TBB_LIBRARIES ${TBB_LIBRARY})
    set(TBB_INCLUDE_DIRS ${TBB_INCLUDE_DIR})

    # Create imported target
    if(NOT TARGET TBB::tbb)
        add_library(TBB::tbb UNKNOWN IMPORTED)
        set_target_properties(TBB::tbb PROPERTIES
            IMPORTED_LOCATION "${TBB_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${TBB_INCLUDE_DIR}"
        )

        # Add compile definitions that might be needed
        if(TBB_VERSION VERSION_GREATER_EQUAL "2021.0")
            set_target_properties(TBB::tbb PROPERTIES
                INTERFACE_COMPILE_DEFINITIONS "TBB_USE_GLIBCXX_VERSION=201703L"
            )
        endif()
    endif()

    if(NOT TBB_FIND_QUIETLY)
        message(STATUS "Found TBB: ${TBB_LIBRARY} (version: ${TBB_VERSION})")
    endif()
else()
    if(TBB_FIND_REQUIRED)
        message(FATAL_ERROR "Could not find TBB library")
    endif()
    if(NOT TBB_FIND_QUIETLY)
        message(WARNING "TBB not found")
    endif()
endif()

# Mark variables as advanced
mark_as_advanced(TBB_INCLUDE_DIR TBB_LIBRARY TBB_VERSION)
