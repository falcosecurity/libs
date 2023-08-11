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

if(_falcosecurity_get_version_from_git)
    return()
endif()

set(_falcosecurity_get_version_from_git TRUE)

if(NOT FALCOSECURITY_RELEASE_BRANCH_REGEX)
    set(FALCOSECURITY_RELEASE_BRANCH_REGEX "^release/")
endif()

function(_falcosecurity_execute_git _out)
    if(NOT GIT_FOUND)
        find_package(Git QUIET)
    endif()

    execute_process(COMMAND
        "${GIT_EXECUTABLE}"
        ${ARGN}
        WORKING_DIRECTORY
        "${CMAKE_CURRENT_SOURCE_DIR}"
        RESULT_VARIABLE
        res
        OUTPUT_VARIABLE
        out
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    if(NOT res EQUAL 0)
        set(out "")
    endif()

    set(${_out} "${out}" PARENT_SCOPE)
endfunction()

function(_falcosecurity_extract_version version_str x y z found)
    string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" match_result ${version_str})

    if(match_result)
        string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+).*" "\\1" x_val ${match_result})
        string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+).*" "\\2" y_val ${match_result})
        string(REGEX REPLACE "^([0-9]+)\\.([0-9]+)\\.([0-9]+).*" "\\3" z_val ${match_result})
        set(${x} ${x_val} PARENT_SCOPE)
        set(${y} ${y_val} PARENT_SCOPE)
        set(${z} ${z_val} PARENT_SCOPE)
        set(${found} TRUE PARENT_SCOPE)
    else()
        set(${found} FALSE PARENT_SCOPE)
    endif()
endfunction()

# get_version_from_git() provides a basic implementation of the Falco versioning convention.
#
# The primary convention is that all version numbers should be a SemVer2.0-compatible string.
# The version number for the development build must follow a pre-release version pattern.
# To accomplish this, we use Git as the primary data source to construct the version number
# automatically. In this regard, the convention assumes that:
# any Git tag represents an officially released build,
# and each Git commit could potentially be a development build.
#
# With those assumptions, the build system will return a version number based on one of
# the following cases:
#
# - If the current Git checkout points to an exact Git tag,
# we assume it is an officially released version (either a release or a pre-release).
#
# - If we are in a release branch (with the suffix `release/`),
# we assume that each commit (i.e., each development build) represents a potential new patch version.
#
# - If we are in any other branch,
# we assume that each commit (i.e., each development build) represents a potential new minor version.
#
# - In any other case (for example, if there's no git information available),
# version `0.0.0` will be returned as a fallback.
#
# For the officially released versions, we assume the Git tag will carry on the correct information,
# so we return it as-is.
#
# For development versions, the string is built as follows:
# `<x>.<y>.<z>-<count>+<commit>[suffix]`
# Where:
# - `<x>.<y>.<z>` represents the next version number, reflecting either a patch for release branches
# or a minor version for development branches.
# - `<count>` is the number of commits ahead from either:
# - the latest tag on the branch, for release branches; or
# - the closest common ancestor with the branch holding the latest tagged version,
# for development branches.
# - `<commit>` refers to the first 7 digits of the commit hash.
# - `[suffix]` the value of `match_suffix`, if any.
# Note: all non-alphanumerics will be converted to hyphens.
#
#
# This function sets the resulting version string to a variable in the parent scope.
#
# Arguments:
# - _var            Variable to store the resulting version string.
# - match_suffix    Only consider Git references with this suffix.
# - exclude_suffix  Ignore Git references with this suffix.
function(get_version_from_git _var match_suffix exclude_suffix)
    # Release version
    # Try to obtain the exact git tag
    if(exclude_suffix)
        _falcosecurity_execute_git(tag describe --tags --exact-match --match "*${match_suffix}" --exclude "*${exclude_suffix}" HEAD)
    else()
        _falcosecurity_execute_git(tag describe --tags --exact-match --match "*${match_suffix}" HEAD)
    endif()

    if(tag)
        # A tag has been found: use it as the libs version
        set(${_var}
            "${tag}"
            PARENT_SCOPE)
        return()
    endif()

    # Otherwise, we are on a dev version
    _falcosecurity_execute_git(current_hash rev-parse HEAD)
    _falcosecurity_execute_git(current_hash_short rev-parse --short=7 HEAD)
    _falcosecurity_execute_git(current_branch rev-parse --abbrev-ref HEAD)

    set(dev_version "0.0.0")

    # dev version / in a `release/M.m.x` branch
    if(current_branch MATCHES "${FALCOSECURITY_RELEASE_BRANCH_REGEX}")
        # get the latest tag on the release branch
        set(_options --match "*.*.*${match_suffix}")

        if(exclude_suffix)
            set(_options ${_options} --exclude "*${exclude_suffix}")
        endif()

        _falcosecurity_execute_git(tag describe --tags ${_options} --abbrev=0 "${current_branch}")

        if(tag)
            _falcosecurity_extract_version("${tag}" x y z match_found)

            if(match_found)
                math(EXPR z_plus_one "${z} + 1")
                set(dev_version "${x}.${y}.${z_plus_one}")
            endif()
        endif()
    endif()

    # dev version / all other cases (and fallback)
    if(dev_version MATCHES "0.0.0")
        # get the latest tag that exactly matches a version number, sorted by version number in descending order
        _falcosecurity_execute_git(tag for-each-ref --count=1 --sort=-version:refname --format "%(refname:short)" refs/tags/[0-9]*.[0-9]*.[0-9]${match_suffix})

        if(tag)
            _falcosecurity_extract_version("${tag}" x y z match_found)

            if(match_found)
                math(EXPR y_plus_one "${y} + 1")
                set(dev_version "${x}.${y_plus_one}.0")
            endif()
        endif()
    endif()

    # complete dev version with count and hash
    if(NOT dev_version MATCHES "0.0.0")
        _falcosecurity_execute_git(tag_commit rev-list -n 1 "${tag}")
        _falcosecurity_execute_git(tag_common_ancestor merge-base "${current_hash}" "${tag_commit}")
        _falcosecurity_execute_git(commits_count rev-list --count "${tag_common_ancestor}..${current_hash}")

        set(dev_version "${dev_version}-${commits_count}+${current_hash_short}")

        if(match_suffix)
            string(REGEX REPLACE "[^0-9A-Za-z-]" "-" suffix "${match_suffix}")
            set(dev_version "${dev_version}${suffix}")
        endif()
    endif()

    set(${_var}
        "${dev_version}"
        PARENT_SCOPE)
endfunction()