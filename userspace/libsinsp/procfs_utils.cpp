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
#include "procfs_utils.h"
#include "logger.h"

#include <cstring>
#include <sstream>
#include <unistd.h>

int libsinsp::procfs_utils::get_userns_root_uid(std::istream& uid_map)
{
	std::string uid_map_line;

	while(std::getline(uid_map, uid_map_line))
	{
		int src_uid, target_uid;
		std::stringstream mapping(uid_map_line);
		mapping >> src_uid;

		// if the target uid we're looking for was anything other than 0,
		// we'd have to check the length of the range as well, but since
		// 0 is the lowest, we're good
		if(src_uid != 0)
		{
			continue;
		}
		mapping >> target_uid;

		return target_uid;
	}

	return libsinsp::procfs_utils::NO_MATCH;
}


std::string libsinsp::procfs_utils::get_systemd_cgroup(std::istream& cgroups)
{
	std::string cgroups_line;

	while(std::getline(cgroups, cgroups_line))
	{
		size_t cgpos = cgroups_line.find(":name=systemd:");
		if(cgpos == std::string::npos)
		{
			continue;
		}

		std::string systemd_cgroup = cgroups_line.substr(cgpos + strlen(":name=systemd:"), std::string::npos);
		return systemd_cgroup;
	}

	return "";
}

//
// ns_helper
//
libsinsp::procfs_utils::ns_helper::ns_helper(const std::string& host_root):
	m_host_root(host_root)
{
	// (try to) init m_host_init_ns_mnt
	char buf[NS_MNT_SIZE] = {0};
	if(-1 == readlink((m_host_root + "/proc/1/ns/mnt").c_str(), buf, NS_MNT_SIZE - 1))
	{
		g_logger.format(sinsp_logger::SEV_WARNING,
				"Cannot read host init ns/mnt: %d", errno);
		m_cannot_read_host_init_ns_mnt = true;
	}
	else
	{
		auto size = strlen(buf) + 1;
		m_host_init_ns_mnt = (char*)malloc(size);
		strncpy(m_host_init_ns_mnt, buf, size);
	}
}

libsinsp::procfs_utils::ns_helper::~ns_helper()
{
	if(m_host_init_ns_mnt)
	{
		free(m_host_init_ns_mnt);
		m_host_init_ns_mnt = nullptr;
	}
}

bool libsinsp::procfs_utils::ns_helper::in_own_ns_mnt(int64_t pid) const
{
	if(m_host_init_ns_mnt == nullptr)
	{
		return false;
	}

	std::string path = m_host_root + "/proc/" + std::to_string(pid) + "/ns/mnt";

	char proc_ns_mnt[NS_MNT_SIZE] = {0};
	if(-1 == readlink(path.c_str(), proc_ns_mnt, NS_MNT_SIZE-1))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"Cannot read process ns/mnt");
		return false;
	}

	if(0 == strncmp(m_host_init_ns_mnt, proc_ns_mnt, NS_MNT_SIZE))
	{
		// Still in the host namespace
		return false;
	}

	return true;
}
