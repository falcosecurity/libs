#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include(GetVersionFromGit)

function(get_libs_version _var)
    # `+driver` is given to ignore drivers tags when fetching the version of libs
    get_version_from_git(ver "" "+driver")

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_drivers_version _var)
    # `+driver` is given to only fetch drivers tags, thus excluding libs ones
    get_version_from_git(ver "+driver" "")

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_shared_libs_versions _var _sovar)
    string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" sl_ver ${FALCOSECURITY_LIBS_VERSION})

    if(NOT sl_ver)
        set(sl_ver "0.0.0")
    endif()

    set(${_var} ${sl_ver} PARENT_SCOPE)
    string(REPLACE "." ";" sl_ver_list ${sl_ver})
    list(GET sl_ver_list 0 so_ver)
    set(${_sovar} ${so_ver} PARENT_SCOPE)
    return()
endfunction()