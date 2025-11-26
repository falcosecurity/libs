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

# FindUthash.cmake - Find uthash library This module provides a fallback when uthash is not
# available as a package
#
# This module defines the following variables: UTHASH_FOUND        - True if uthash was found
# UTHASH_INCLUDE_DIRS - uthash include directories

# Try to find uthash using pkg-config first
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
	pkg_check_modules(PC_UTHASH QUIET uthash)
endif()

# Find uthash include directory (looking for uthash.h)
find_path(
	UTHASH_INCLUDE_DIR
	NAMES uthash.h
	HINTS ${PC_UTHASH_INCLUDEDIR} ${PC_UTHASH_INCLUDE_DIRS} $ENV{UTHASH_ROOT}/include /usr/include
		  /usr/local/include /opt/local/include
	PATH_SUFFIXES uthash include
)

# Set UTHASH_FOUND based on what we found
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Uthash REQUIRED_VARS UTHASH_INCLUDE_DIR)

# Set UTHASH variables
if(UTHASH_FOUND)
	set(UTHASH_INCLUDE_DIRS ${UTHASH_INCLUDE_DIR})
	if(NOT Uthash_FIND_QUIETLY)
		message(STATUS "Found uthash: ${UTHASH_INCLUDE_DIRS}")
	endif()
else()
	if(Uthash_FIND_REQUIRED)
		message(FATAL_ERROR "Could not find uthash library")
	endif()
	if(NOT Uthash_FIND_QUIETLY)
		message(WARNING "uthash not found")
	endif()
endif()

# Mark variables as advanced
mark_as_advanced(UTHASH_INCLUDE_DIR)
