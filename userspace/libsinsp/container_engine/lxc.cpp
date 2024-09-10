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

#include <libsinsp/container_engine/lxc.h>
#include <libsinsp/sinsp.h>

using namespace libsinsp::container_engine;

constexpr const std::string_view LXC_CGROUP_LAYOUT[] = {
        "/lxc/",          // non-systemd
        "/lxc.payload/",  // systemd
        "/lxc.payload.",  // lxc4.0 layout:
                          // https://linuxcontainers.org/lxc/news/2020_03_25_13_03.html
};

bool lxc::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) {
	auto container = sinsp_container_info();
	bool matches = false;

	for(const auto &it : tinfo->cgroups()) {
		const auto &cgroup = it.second;
		for(const auto &cgroup_layout : LXC_CGROUP_LAYOUT) {
			size_t pos = cgroup.find(cgroup_layout);
			if(pos != std::string::npos) {
				auto id_start = pos + cgroup_layout.length();
				auto id_end = cgroup.find('/', id_start);
				container.m_type = CT_LXC;
				container.m_id = cgroup.substr(id_start, id_end - id_start);
				matches = true;
				break;
			}
		}
		if(matches) {
			break;
		}
	}

	if(!matches) {
		return false;
	}

	tinfo->m_container_id = container.m_id;
	if(container_cache().should_lookup(container.m_id, CT_LXC)) {
		container.m_name = container.m_id;
		container.set_lookup_status(sinsp_container_lookup::state::SUCCESSFUL);
		container_cache().add_container(std::make_shared<sinsp_container_info>(container), tinfo);
		container_cache().notify_new_container(container, tinfo);
	}
	return true;
}
