// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#include <libsinsp/container_engine/docker/podman.h>

#include <libsinsp/container_engine/docker/lookup_request.h>
#include <libsinsp/procfs_utils.h>
#include <libsinsp/runc.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_cgroup.h>

#include <glob.h>
#include <unistd.h>

#include <fstream>

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

std::string podman::m_api_sock = "/run/podman/podman.sock";
std::string podman::m_user_api_sock_pattern = "/run/user/*/podman/podman.sock";

namespace {
constexpr const cgroup_layout ROOT_PODMAN_CGROUP_LAYOUT[] = {
	{"/libpod-", ".scope"}, // podman
	{"/libpod-", ".scope/container"}, // podman
	{"/libpod-", ""}, // non-systemd podman, e.g. on alpine
	{nullptr,    nullptr}
};

int get_userns_root_uid(int64_t tid)
{
	std::stringstream uid_map_file;
	uid_map_file << scap_get_host_root() << "/proc/" << tid << "/uid_map";

	std::ifstream uid_map(uid_map_file.str());
	return libsinsp::procfs_utils::get_userns_root_uid(uid_map);
}

// Check whether `cgroup` describes a podman container
//
// Returns the uid of the container owner:
//  0 for root containers,
//  >0 for rootless containers,
//  NO_MATCH if the process is not in a podman container
int get_podman_cgroup_uid(const std::string &cgroup, std::string &container_id, int64_t tid)
{
	if(cgroup.empty())
	{
		// can't get the cgroup name
		return libsinsp::procfs_utils::NO_MATCH;
	}

	size_t pos = cgroup.find("podman-");
	if(pos != std::string::npos)
	{
		// .../podman-<pid>.scope/<container_id>
		int podman_pid; // unused except to set the sscanf return value
		char c;         // ^ same
		if(sscanf(cgroup.c_str() + pos, "podman-%d.scope/%c", &podman_pid, &c) != 2)
		{
			// cgroup doesn't match the expected pattern
			return libsinsp::procfs_utils::NO_MATCH;
		}

		if(!match_one_container_id(cgroup, ".scope/", "", container_id))
		{
			return libsinsp::procfs_utils::NO_MATCH;
		}

		int uid = get_userns_root_uid(tid);
		if(uid == 0)
		{
			// root doesn't spawn rootless containers
			return libsinsp::procfs_utils::NO_MATCH;
		}

		return uid;
	} else
	{
		// when rootless podman containers are run as a service,
		// there's nothing identifying podman in the cgroup as it looks like:
		// /user.slice/user-<uid>.slice/user@<uid>.service/<unit>/<container_id>
		// where <unit> is whatever started the container, e.g. foo.service
		//
		// let's hope for the best and assume that all such cgroups are
		// podman containers

		// we can probably narrow the prefix down to ".service/" in the typical
		// case but as we're already basically guessing, let's keep it generic
		if(!match_one_container_id(cgroup, "/", "", container_id))
		{
			return libsinsp::procfs_utils::NO_MATCH;
		}

		int uid;
		if(sscanf(cgroup.c_str(), "/user.slice/user-%d.slice/", &uid) == 1)
		{
			return uid;
		}
		return libsinsp::procfs_utils::NO_MATCH;
	}

}

// Check whether `tinfo` belongs to a podman container
//
// Returns the uid of the container owner:
//  0 for root containers,
//  >0 for rootless containers,
//  NO_MATCH if the process is not in a podman container
int detect_podman(const sinsp_threadinfo *tinfo, std::string &container_id)
{
	std::string cgroup;
	if(matches_runc_cgroups(tinfo, ROOT_PODMAN_CGROUP_LAYOUT, container_id, cgroup))
	{
		// User: /user.slice/user-1000.slice/user@1000.service/user.slice/libpod-$ID.scope/container
		// Root: /machine.slice/libpod-$ID.scope/container
		int uid;
		if (sscanf(cgroup.c_str(), "/user.slice/user-%d.slice/", &uid) == 1)
		{
			return uid;
		}
		return 0; // root
	}

	// the kernel driver does not return cgroups without subsystems (e.g. name=systemd)
	// in the cgroups field, so we have to do a check here, and load /proc/pid/cgroups
	// ourselves if needed
	if(tinfo->get_cgroup("name=systemd", cgroup))
	{
		return get_podman_cgroup_uid(cgroup, container_id, tinfo->m_tid);
	}

	sinsp_threadinfo proc_cgroups_tinfo;
	proc_cgroups_tinfo.m_tid = tinfo->m_tid;
	sinsp_cgroup::instance().lookup_cgroups(proc_cgroups_tinfo);

	for(const auto& proc_cgroup: proc_cgroups_tinfo.cgroups())
	{
		int ret = get_podman_cgroup_uid(proc_cgroup.second, container_id, tinfo->m_tid);
		if(ret != libsinsp::procfs_utils::NO_MATCH)
		{
			return ret;
		}
	}

	return libsinsp::procfs_utils::NO_MATCH;
}
}

bool podman::can_api_sock_exist()
{
	glob_t gl;
	int rc;
	int glob_flags = 0;

	// If the GNU extension GLOB_BRACE were universal, we could
	// probably do this as one glob.

	std::string api_sock = scap_get_host_root() + m_api_sock;
	std::string user_api_sock_pattern = scap_get_host_root() + m_user_api_sock_pattern;

	if (access(api_sock.c_str(), R_OK|W_OK) == 0)
	{
		return true;
	}

	// NULL is errfunc
	rc = glob(user_api_sock_pattern.c_str(), glob_flags, NULL, &gl);
	globfree(&gl);

	return (rc == 0);
}

bool podman::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	std::string container_id, api_sock;

	if(m_api_sock_can_exist == nullptr)
	{
		m_api_sock_can_exist.reset(new bool(can_api_sock_exist()));
	}

	if(! (*(m_api_sock_can_exist.get())))
	{
		return false;
	}

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
		break;
	}

	docker_lookup_request request(container_id, api_sock, CT_PODMAN, uid, false);
	return resolve_impl(tinfo, request, query_os_for_missing_info);
}
