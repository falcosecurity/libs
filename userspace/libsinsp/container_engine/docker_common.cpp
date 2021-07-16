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
	container_cache_interface *cache = &container_cache();

	if(!detect_docker(tinfo, container_id, container_name))
	{
		return false;
	}

	if(!m_docker_info_source)
	{
		g_logger.log("docker_async: Creating docker async source",
			     sinsp_logger::SEV_DEBUG);
		uint64_t max_wait_ms = 10000;
		docker_async_source *src = new docker_async_source(docker_async_source::NO_WAIT_LOOKUP, max_wait_ms, cache);
		m_docker_info_source.reset(src);
	}

	tinfo->m_container_id = container_id;

	sinsp_container_info::ptr_t container_info = cache->get_container(container_id);

	if(!container_info)
	{
		if(!query_os_for_missing_info)
		{
			auto container = std::make_shared<sinsp_container_info>();
			container->m_type = CT_DOCKER;
			container->m_id = container_id;
			cache->notify_new_container(*container);
			return true;
		}

#ifdef HAS_CAPTURE
		if(cache->should_lookup(container_id, CT_DOCKER))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): No existing container info",
					container_id.c_str());

			// give docker a chance to return metadata for this container
			cache->set_lookup_status(container_id, CT_DOCKER, sinsp_container_lookup_state::STARTED);
			parse_docker_async(container_id, cache);
		}
#endif
		return false;
	}

	// Returning true will prevent other container engines from
	// trying to resolve the container, so only return true if we
	// have complete metadata.
	return container_info->is_successful();
}

void docker::parse_docker_async(const string& container_id, container_cache_interface *cache)
{
	auto cb = [cache](const docker_lookup_request& request, const sinsp_container_info& res)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Source callback result=%d",
				request.container_id.c_str(),
				res.m_lookup_state);

		cache->notify_new_container(res);
	};

        sinsp_container_info result;

	docker_lookup_request request(container_id, m_docker_sock, false /*don't request size*/);
	if(m_docker_info_source->lookup(request, result, cb))
	{
		// if a previous lookup call already found the metadata, process it now
		cb(request, result);

		// This should *never* happen, as ttl is 0 (never wait)
		g_logger.format(sinsp_logger::SEV_ERROR,
				"docker_async (%s): Unexpected immediate return from docker_info_source.lookup()",
				container_id.c_str());
	}
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
