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
#include <libsinsp/procfs_utils.h>
#include <libsinsp/logger.h>

#include <cstring>
#include <sstream>
#include <sys/stat.h>

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


//
// ns_helper
//
libsinsp::procfs_utils::ns_helper::ns_helper(const std::string& host_root):
	m_host_root(host_root)
{
	struct stat rootlink;
	if(-1 == stat((m_host_root + "/proc/1/root").c_str(), &rootlink))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING,
				"Cannot read host init process proc root: %d", errno);
		m_cannot_read_host_init_ns_mnt = true;
	}
	else
	{
		m_host_init_root_inode = rootlink.st_ino;
	}
}

bool libsinsp::procfs_utils::ns_helper::in_own_ns_mnt(int64_t pid) const
{
	if(m_cannot_read_host_init_ns_mnt)
	{
		return false;
	}

	struct stat rootlink;
	if(-1 == stat(get_pid_root(pid).c_str(), &rootlink))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"Cannot read process proc root");
		return false;
	}

	if(static_cast<decltype(m_host_init_root_inode)>(rootlink.st_ino) == m_host_init_root_inode)
	{
		// Still in the host namespace
		return false;
	}

	return true;
}
