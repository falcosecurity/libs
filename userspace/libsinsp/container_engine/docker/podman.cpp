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
#include "podman.h"

#include "container_engine/docker/lookup_request.h"
#include "procfs_utils.h"
#include "runc.h"
#include "sinsp.h"

#include <fstream>

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

std::string podman::m_api_sock = "/run/podman/podman.sock";

namespace {
constexpr const cgroup_layout ROOT_PODMAN_CGROUP_LAYOUT[] = {
	{"/libpod-", ".scope"}, // podman
	{nullptr,    nullptr}
};

std::string get_systemd_cgroup(const sinsp_threadinfo *tinfo)
{
	// the kernel driver does not return cgroups without subsystems (e.g. name=systemd)
	// in the cgroups field, so we have to do a check here, and load /proc/pid/cgroups
	// ourselves if needed

	for(const auto& it : tinfo->m_cgroups)
	{
		if(it.first == "name=systemd")
		{
			return it.second;
		}
	}

	std::stringstream cgroups_file;
	cgroups_file << scap_get_host_root() << "/proc/" << tinfo->m_tid << "/cgroup";

	std::ifstream cgroups(cgroups_file.str());
	return libsinsp::procfs_utils::get_systemd_cgroup(cgroups);
}

int get_userns_root_uid(const sinsp_threadinfo *tinfo)
{
	std::stringstream uid_map_file;
	uid_map_file << scap_get_host_root() << "/proc/" << tinfo->m_tid << "/uid_map";

	std::ifstream uid_map(uid_map_file.str());
	return libsinsp::procfs_utils::get_userns_root_uid(uid_map);
}

// Check whether `tinfo` belongs to a podman container
//
// Returns the uid of the container owner:
//  0 for root containers,
//  >0 for rootless containers,
//  NO_MATCH if the process is not in a podman container
int detect_podman(const sinsp_threadinfo *tinfo, std::string& container_id)
{
	if(matches_runc_cgroups(tinfo, ROOT_PODMAN_CGROUP_LAYOUT, container_id))
	{
		return 0; // root
	}

	std::string systemd_cgroup = get_systemd_cgroup(tinfo);
	if(systemd_cgroup.empty())
	{
		// can't get the cgroup name
		return libsinsp::procfs_utils::NO_MATCH;
	}

	size_t pos = systemd_cgroup.find("podman-");
	if(pos == std::string::npos)
	{
		return libsinsp::procfs_utils::NO_MATCH;
	}

	int podman_pid; // unused except to set the sscanf return value
	char c;         // ^ same
	if(sscanf(systemd_cgroup.c_str() + pos, "podman-%d.scope/%c", &podman_pid, &c) != 2)
	{
		// cgroup doesn't match the expected pattern
		return libsinsp::procfs_utils::NO_MATCH;
	}

	if(!match_one_container_id(systemd_cgroup, ".scope/", "", container_id))
	{
		return libsinsp::procfs_utils::NO_MATCH;
	}

	int uid = get_userns_root_uid(tinfo);
	if(uid == 0)
	{
		// root doesn't spawn rootless containers
		return libsinsp::procfs_utils::NO_MATCH;
	}

	return uid;
}
}

bool podman::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	std::string container_id, container_name, api_sock;
	int uid = detect_podman(tinfo, container_id);

	switch(uid)
	{
	case 0: // root, use the default socket
		api_sock = m_api_sock;
		break;
	case libsinsp::procfs_utils::NO_MATCH:
		return false;
	default: // rootless container, use the user's socket
		api_sock = "/run/user/" + std::to_string(uid) + "/podman/podman.sock";
	}

	docker_lookup_request request(container_id, api_sock, CT_PODMAN, uid, false);
	return resolve_impl(tinfo, request, query_os_for_missing_info);
}

void podman::update_with_size(const std::string& container_id)
{
	// not supported
}
