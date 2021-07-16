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
#ifdef CYGWING_AGENT

#include "container_engine/docker.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "dragent_win_hal_public.h"

using namespace libsinsp::container_engine;

docker_win::docker_win(container_cache_interface& cache, const wmi_handle_source& wmi_source) :
   container_engine_base(cache),
   m_wmi_handle_source(wmi_source)
{
}

bool docker_win::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	wh_docker_container_info wcinfo = wh_docker_resolve_pid(m_wmi_handle_source.get_wmi_handle(), tinfo->m_pid);
	if(!wcinfo.m_res)
	{
		return false;
	}

	std::string container_id = wcinfo.m_container_id;

	return resolve_impl(tinfo, docker_async_instruction(
		container_id,
		"",
		CT_DOCKER,
		0,
		false), query_os_for_missing_info);
}

void docker_win::update_with_size(const std::string &container_id)
{
	// not supported
}

#endif // CYGWING_AGENT
