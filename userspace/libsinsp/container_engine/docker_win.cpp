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

docker::docker(container_cache_interface& cache, const wmi_handle_source& wmi_source) :
   container_engine_base(cache),
   m_wmi_handle_source(wmi_source)
{
}

void docker::cleanup()
{
	g_docker_info_source.reset(NULL);
}

bool docker::detect_docker(sinsp_threadinfo *tinfo, std::string &container_id, std::string &container_name)
{
	wh_docker_container_info wcinfo = wh_docker_resolve_pid(m_wmi_handle_source.get_wmi_handle(), tinfo->m_pid);
	if(!wcinfo.m_res)
	{
		return false;
	}

	container_id = wcinfo.m_container_id;
	container_name = wcinfo.m_container_name;

	return true;
}

#endif // CYGWING_AGENT
