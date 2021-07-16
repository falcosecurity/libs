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

#include "container_engine/docker.h"

#include "runc.h"
#include "container_engine/mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace {

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd docker
	{"/docker-", ".scope"}, // systemd docker
	{nullptr, nullptr}
};
}

std::string docker::m_docker_sock = "/var/run/docker.sock";

void docker::cleanup()
{
	m_docker_info_source.reset(NULL);
}

bool docker::detect_docker(const sinsp_threadinfo *tinfo, std::string &container_id, std::string &container_name)
{
	if(matches_runc_cgroups(tinfo, DOCKER_CGROUP_LAYOUT, container_id))
	{
		// The container name is only available in windows
		container_name = s_incomplete_info_name;

		return true;
	}

	return false;
}
