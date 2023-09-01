#
# Copyright (C) 2023 The Falco Authors.
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

# We take b64 implementation directly from:
# https://raw.githubusercontent.com/istio/proxy/1.18.2/extensions/common/wasm/base64.h

set(B64_DOWNLOAD_URL "https://raw.githubusercontent.com/istio/proxy/1.18.2/extensions/common/wasm/base64.h")
set(B64_INCLUDE "${CMAKE_BINARY_DIR}/b64")

if(NOT EXISTS "${B64_INCLUDE}/base64.h")
	file(MAKE_DIRECTORY "${B64_INCLUDE}")
	message(STATUS "Download 'base64.h' from: ${B64_DOWNLOAD_URL}")
	file(DOWNLOAD
	"${B64_DOWNLOAD_URL}"
	"${B64_INCLUDE}/base64.h"
	)
endif()

include_directories("${B64_INCLUDE}")
