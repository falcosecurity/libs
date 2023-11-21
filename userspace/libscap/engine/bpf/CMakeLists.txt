# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
add_library(scap_engine_bpf scap_bpf.c attached_prog.c)
add_dependencies(scap_engine_bpf libelf zlib)
target_link_libraries(scap_engine_bpf
PRIVATE
    scap_event_schema
    scap_platform
    scap_engine_util
    scap_error
    ${LIBELF_LIB}
    ${ZLIB_LIB}
)
target_include_directories(scap_engine_bpf PRIVATE ${LIBELF_INCLUDE})

set_scap_target_properties(scap_engine_bpf)
