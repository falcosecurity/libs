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

#ifndef _WIN32

#include "container_engine/docker.h"
#include "cgroup_list_counter.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"
#include "utils.h"
#include <unordered_set>

using namespace libsinsp::container_engine;


std::string docker::s_incomplete_info_name = "incomplete";

bool docker::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	std::string container_id, container_name;

	if(!detect_docker(tinfo, container_id, container_name))
	{
		return false;
	}

	docker_lookup_request request(container_id, m_docker_sock, false /*don't request size*/);

	return resolve_impl(tinfo, request, query_os_for_missing_info);

}

void docker::update_with_size(const std::string &container_id)
{
	auto cb = [this](const docker_lookup_request& request, const sinsp_container_info& res) {
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): with size callback result=%d",
				request.container_id.c_str(),
				res.m_lookup_state);

		sinsp_container_info::ptr_t updated = make_shared<sinsp_container_info>(res);
		container_cache().replace_container(updated);
	};

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"docker_async size request (%s)",
			container_id.c_str());

	sinsp_container_info result;
	docker_lookup_request request(container_id, m_docker_sock, true /*request rw size*/);
	(void)m_docker_info_source->lookup(request, result, cb);
}

#endif // _WIN32
