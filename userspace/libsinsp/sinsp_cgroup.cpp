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

#include "sinsp_cgroup.h"
#include "scap_const.h"
#include "scap.h"

#include <mntent.h>

sinsp_cgroup::sinsp_cgroup() = default;

std::shared_ptr<std::string> sinsp_cgroup::lookup_cgroup_dir(const std::string &subsys, int &version)
{
	std::shared_ptr<std::string> cgroup_dir;

	version = 1;

	const auto &it = m_cgroup_dir_cache.find(subsys);
	if(it != m_cgroup_dir_cache.end())
	{
		return it->second;
	}

	// Look for mount point of cgroup filesystem
	// It should be already mounted on the host or by
	// our docker-entrypoint.sh script
	if(strcmp(scap_get_host_root(), "") != 0)
	{
		// We are inside our container, so we should use the directory
		// mounted by it
		auto cgroup = std::string(scap_get_host_root()) + "/cgroup/" + subsys;
		cgroup_dir = std::make_shared<std::string>(cgroup);
	}
	else
	{
		struct mntent mntent_buf = {};
		char mntent_string_buf[4096];
		FILE *fp = setmntent("/proc/mounts", "r");
		struct mntent *entry = getmntent_r(fp, &mntent_buf,
						   mntent_string_buf, sizeof(mntent_string_buf));
		while(entry != nullptr)
		{
			if(strcmp(entry->mnt_type, "cgroup") == 0 &&
			   hasmntopt(entry, subsys.c_str()) != nullptr)
			{
				cgroup_dir = std::make_shared<std::string>(entry->mnt_dir);
				break;
			}
			entry = getmntent(fp);
		}
		endmntent(fp);
	}

	if(cgroup_dir != nullptr)
	{
		m_cgroup_dir_cache[subsys] = cgroup_dir;
	}
	return cgroup_dir;
}

sinsp_cgroup &sinsp_cgroup::instance()
{
	static std::unique_ptr<sinsp_cgroup> instance;

	if(instance == nullptr)
	{
		instance = std::make_unique<sinsp_cgroup>();
	}

	return *instance;
}
