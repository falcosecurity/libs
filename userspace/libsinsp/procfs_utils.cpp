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

#include <string>
#include "sinsp.h"

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
