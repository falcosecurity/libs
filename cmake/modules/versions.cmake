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

function(_get_git_version _var is_driver)
    # Try to obtain the exact git tag
    if (is_driver)
        git_get_exact_tag(tag --match=*+driver)
    else()
        git_get_exact_tag(tag --exclude=*+driver)
    endif()
    if(tag)
        # A tag has been found: use it as the libs version
        set(${_var}
            "${tag}"
            PARENT_SCOPE)
        return()
    endif()

    # Obtain the closest tag
    if (is_driver)
        git_describe(dev_version "--always" "--tags" "--abbrev=7" --match=*+driver)
    else()
        git_describe(dev_version "--always" "--tags" "--abbrev=7" --exclude=*+driver)
    endif()
    string(REGEX MATCH "^[0-9]+.[0-9]+.[0-9]+$" libs_tag ${dev_version})
    string(REGEX MATCH "^[0-9]+.[0-9]+.[0-9]+\\+driver$" driver_tag ${dev_version})
    if(dev_version MATCHES "NOTFOUND$" OR (libs_tag STREQUAL "" AND driver_tag STREQUAL ""))
        # Fetch current hash
        get_git_head_revision(refspec LIBS_HASH)
        if(NOT LIBS_HASH OR LIBS_HASH MATCHES "NOTFOUND$")
            set(dev_version "0.0.0")
        else()
            # Obtain the closest tag
            if (is_driver)
                git_get_latest_tag(LIBS_LATEST_TAG --tags=*+driver)
            else()
                git_get_latest_tag(LIBS_LATEST_TAG --exclude=*+driver --tags)
            endif()

            if(NOT LIBS_LATEST_TAG OR LIBS_LATEST_TAG MATCHES "NOTFOUND$")
                set(dev_version "0.0.0")
            else()
                # Compute commit delta since tag
                git_get_delta_from_tag(LIBS_DELTA ${LIBS_LATEST_TAG} ${LIBS_HASH})
                if(NOT LIBS_DELTA OR LIBS_DELTA MATCHES "NOTFOUND$")
                    set(FALCO_VERSION "0.0.0")
                else()
                    # Cut hash to 7 bytes
                    string(SUBSTRING ${LIBS_HASH} 0 7 LIBS_HASH)
                    # Format dev_version to be semver with prerelease and build part
                    set(dev_version "${LIBS_LATEST_TAG}-${LIBS_DELTA}+${LIBS_HASH}")
                endif()
            endif()
        endif()
    endif()
     # Format dev_version to be semver with prerelease and build part
    string(REPLACE "-g" "+" dev_version "${dev_version}")

    set(${_var}
        "${dev_version}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_libs_version _var)
    _get_git_version(ver false)

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_drivers_version _var)
    _get_git_version(ver true)

    set(${_var}
        "${ver}"
        PARENT_SCOPE)
    return()
endfunction()

function(get_shared_libs_versions _var _sovar)
    string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" sl_ver ${FALCOSECURITY_LIBS_VERSION} )
    if (NOT sl_ver)
        set(sl_ver "0.0.0")
    endif()
    set(${_var} ${sl_ver} PARENT_SCOPE)
    string(REPLACE "." ";" sl_ver_list ${sl_ver})
    list(GET sl_ver_list 0 so_ver)
    set(${_sovar} ${so_ver} PARENT_SCOPE)
    return()
endfunction()
