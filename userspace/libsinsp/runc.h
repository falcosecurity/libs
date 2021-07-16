/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <string>

class sinsp_threadinfo;

namespace libsinsp {
namespace runc {

/**
 * @brief A pattern to match cgroup paths against
 *
 *  runc-based runtimes (Docker, containerd, CRI-O, probably others) use the same two cgroup layouts
 *  with slight variations:
 *  - non-systemd layout uses cgroups ending with .../<prefix><container id>
 *  - systemd layout uses .../<prefix><container id>.scope
 *  where <container id> is always 64 hex digits (we report the first 12 as the container id).
 *  For non-systemd only CRI-O seems to use /crio-<container id>, while for systemd layout
 *  while all known container engines use a prefix like "docker-", "crio-" or "containerd-cri-".
 *  We can encode all these variants with a simple list of (prefix, suffix) pairs
 *  (the last one must be a pair of null pointers to mark the end of the array)
 */
struct cgroup_layout {
	const char* prefix;
	const char* suffix;
};

/**
 * @brief Check if `cgroup` ends with <prefix><64_hex_digits><suffix>
 * @param container_id output parameter
 * @return true if `cgroup` matches the pattern
 *
 * If this function returns true, `container_id` will be set to
 * the truncated hex string (first 12 digits). Otherwise, it will remain
 * unchanged.
 */
bool match_one_container_id(const std::string &cgroup, const std::string &prefix, const std::string &suffix, std::string &container_id);

/**
 * @brief Match `cgroup` against a list of layouts using `match_one_container_id()`
 * @param layout an array of (prefix, suffix) pairs
 * @param container_id output parameter
 * @return true if `cgroup` matches any of the patterns
 *
 * `layout` is an array terminated by an empty entry (prefix, suffix both empty)
 *
 * If this function returns true, `container_id` will be set to
 * the truncated hex string (first 12 digits). Otherwise, it will remain
 * unchanged.
 */
bool match_container_id(const std::string &cgroup, const libsinsp::runc::cgroup_layout *layout,
			std::string &container_id);

/**
 * @brief Match all the cgroups of `tinfo` against a list of cgroup layouts
 * @param layout an array of (prefix, suffix) pairs
 * @param container_id output parameter
 * @return true if any of `tinfo`'s cgroups match any of the patterns
 *
 * If this function returns true, `container_id` will be set to
 * the truncated hex string (first 12 digits). Otherwise, it will remain
 * unchanged.
 */
bool matches_runc_cgroups(const sinsp_threadinfo *tinfo, const cgroup_layout *layout, std::string &container_id);
}
}
