#
# Copyright (C) 2022 The Falco Authors.
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

include(GetGitRevisionDescription)

function(_get_git_version _var)
    git_describe(tag "--tags" "--exact-match" ${ARGN})

    if(tag)
        # A tag has been found: use it as the libs version
        set(${_var}
            "${tag}"
            PARENT_SCOPE)
        return()
    endif()

    # Obtain the closest tag
    git_describe(dev_version "--always" "--tags" "--abbrev=7" ${ARGN})

    if(dev_version MATCHES "NOTFOUND$")
        # Fallback version
        set(dev_version "0.0.0")
    else()
        # Extract the git version part and make it SemVer friendly (ie. "-1-g02682d7" to "-1+02682d7" )
        string(REGEX MATCH "(-[1-9][0-9]*-g[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])$"
            git_ver_part "${dev_version}")
        string(REPLACE "${git_ver_part}" "" dev_version "${dev_version}")
        string(REPLACE "-g" "+" git_ver_part "${git_ver_part}")

        if(dev_version MATCHES "\\+")
            string(REPLACE "+" "${git_ver_part}-" dev_version "${dev_version}")
        else()
            string(CONCAT dev_version "${dev_version}" "${git_ver_part}")
        endif()
    endif()

    set(${_var}
        "${dev_version}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_libs_version _var)
    _get_git_version(ver "--exclude=+driver")

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_drivers_version _var)
    _get_git_version(ver "--match=*+driver")

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()
