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
#include <libsinsp/container_engine/docker/docker_linux.h>

#include <libsinsp/runc.h>
#include <libsinsp/sinsp_int.h>

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace {

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd docker
	{"/docker-", ".scope"}, // systemd docker
	{nullptr, nullptr}
};
}

std::string docker_linux::m_docker_sock = "/var/run/docker.sock";

bool docker_linux::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	std::string container_id, cgroup;

	if(!matches_runc_cgroups(tinfo, DOCKER_CGROUP_LAYOUT, container_id, cgroup))
	{
		return false;
	}

	return resolve_impl(tinfo, docker_lookup_request(
		container_id,
		m_docker_sock,
		CT_DOCKER,
		0,
		false), query_os_for_missing_info);
}

void docker_linux::update_with_size(const std::string &container_id)
{
	auto cb = [this](const docker_lookup_request& instruction, const sinsp_container_info& res) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): with size callback result=%d",
				instruction.container_id.c_str(),
				res.get_lookup_status());

		sinsp_container_info::ptr_t updated = std::make_shared<sinsp_container_info>(res);
		container_cache().replace_container(updated);
	};

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async size request (%s)",
			container_id.c_str());

	sinsp_container_info result;
	docker_lookup_request instruction(container_id, m_docker_sock, CT_DOCKER, 0, true /*request rw size*/);
	(void)m_docker_info_source->lookup(instruction, result, cb);
}
