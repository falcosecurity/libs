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

#pragma once

#include <libscap/linux/scap_cgroup.h>

#include <memory>
#include <string>
#include <unordered_map>

class sinsp_threadinfo;

class sinsp_cgroup {
public:
	sinsp_cgroup();

	explicit sinsp_cgroup(std::string &&root);

	virtual ~sinsp_cgroup();

	std::shared_ptr<std::string> lookup_cgroup_dir(const std::string &subsys, int &version);

	void lookup_cgroups(sinsp_threadinfo& tinfo);

	static sinsp_cgroup &instance();

protected:
	std::string m_root;
	struct scap_cgroup_interface m_scap_cgroup;
	std::unordered_map<std::string, std::pair<std::shared_ptr<std::string>, int>> m_cgroup_dir_cache;
};
