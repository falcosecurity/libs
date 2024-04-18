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

#include <libsinsp/sinsp_cgroup.h>
#include <libscap/scap_const.h>
#include <libscap/scap.h>
#include <libsinsp/sinsp.h>

sinsp_cgroup::sinsp_cgroup() :
	sinsp_cgroup(scap_get_host_root())
{
}

sinsp_cgroup::sinsp_cgroup(std::string &&root) :
	m_root(std::move(root)),
	m_scap_cgroup({})
{
	char error[SCAP_LASTERR_SIZE];
	scap_cgroup_interface_init(&m_scap_cgroup, m_root.c_str(), error, false);
}

std::shared_ptr<std::string> sinsp_cgroup::lookup_cgroup_dir(const std::string &subsys, int &version)
{
	const char *scap_cgroup_dir;

	const auto &it = m_cgroup_dir_cache.find(subsys);
	if(it != m_cgroup_dir_cache.end())
	{
		version = it->second.second;
		return it->second.first;
	}

	scap_cgroup_dir = scap_cgroup_get_subsys_mount(&m_scap_cgroup, subsys.c_str(), &version);
	if(scap_cgroup_dir != nullptr)
	{
		auto cgroup_dir = std::make_shared<std::string>(scap_cgroup_dir);
		m_cgroup_dir_cache[subsys] = std::make_pair(cgroup_dir, version);
		return cgroup_dir;
	}

	return nullptr;
}

void sinsp_cgroup::lookup_cgroups(sinsp_threadinfo& tinfo)
{
	std::string procdirname = m_root + "/proc/" + std::to_string(tinfo.m_tid) + '/';
	scap_cgroup_set thread_cgroups = {};
	char error[SCAP_LASTERR_SIZE];

	int ret = scap_cgroup_get_thread(&m_scap_cgroup, procdirname.c_str(), &thread_cgroups, error);
	if(ret != SCAP_SUCCESS)
	{
		return;
	}

	tinfo.set_cgroups(thread_cgroups.path, thread_cgroups.len);
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

sinsp_cgroup::~sinsp_cgroup()
{
#ifdef __linux__
	scap_cgroup_clear_cache(&m_scap_cgroup);
#endif // __linux__
}
