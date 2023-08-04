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

set(UTHASH_DOWNLOAD_URL "https://raw.githubusercontent.com/troydhanson/uthash/v1.9.8/src/uthash.h")
set(UTHASH_DOWNLOAD_DIR "${LIBSCAP_DIR}/userspace/libscap")

if(NOT EXISTS "${UTHASH_DOWNLOAD_DIR}/uthash.h")
	message(STATUS "Download 'uthash.h' from: ${UTHASH_DOWNLOAD_URL}")
	file(DOWNLOAD
	"${UTHASH_DOWNLOAD_URL}"
	"${UTHASH_DOWNLOAD_DIR}/uthash.h"
	)
endif()
