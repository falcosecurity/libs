#
# Copyright (C) 2020 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

#
# Valijson (https://github.com/tristanpenman/valijson/)
#

option(USE_BUNDLED_VALIJSON "Enable building of the bundled valijson" ${USE_BUNDLED_DEPS})

if(VALIJSON_INCLUDE)
	# we already have valijson
elseif(NOT USE_BUNDLED_VALIJSON)
	find_package(valijson REQUIRED)
else()
	set(VALIJSON_SRC "${PROJECT_BINARY_DIR}/valijson-prefix/src/valijson")
	set(VALIJSON_INCLUDE "${VALIJSON_SRC}/include")

	message(STATUS "Using bundled valijson in '${VALIJSON_SRC}'")

	ExternalProject_Add(valijson
		PREFIX "${PROJECT_BINARY_DIR}/valijson-prefix"
		URL "https://github.com/tristanpenman/valijson/archive/refs/tags/v0.6.tar.gz"
		URL_HASH "SHA256=e06bf78fc1d26d4956fabc182408ebbbc47e3a6699778cda4aa439c2a6110b09"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND "")	
endif()

if(NOT TARGET valijson)
	add_custom_target(valijson)
endif()

include_directories("${VALIJSON_INCLUDE}")
