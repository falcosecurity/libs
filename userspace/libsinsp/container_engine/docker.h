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

#pragma once
#ifndef MINIMAL_BUILD
#ifndef _WIN32 

#include <memory>
#include <string>
#include <vector>
#include <atomic>

#if !defined(_WIN32)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

#include "json/json.h"

#include "async_key_value_source.h"

#include "container.h"
#include "container_info.h"

#include "container_engine/docker/async_source.h"
#include "container_engine/docker/base.h"
#include "container_engine/docker/connection.h"
#include "container_engine/docker/lookup_request.h"
#include "container_engine/container_engine_base.h"
#include "container_engine/sinsp_container_type.h"
#include "container_engine/wmi_handle_source.h"

class sinsp;
class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

class docker : public docker_base
{
public:

#ifdef _WIN32
	docker(container_cache_interface &cache, const wmi_handle_source&);
#else
	docker(container_cache_interface &cache) : docker_base(cache)
	{}
#endif

	// Container name only set for windows. For linux name must be fetched via lookup
	static bool detect_docker(const sinsp_threadinfo* tinfo, std::string& container_id, std::string &container_name);

#ifndef _WIN32
	static void set_docker_sock(std::string docker_sock) {
		m_docker_sock = std::move(docker_sock);
	}
#endif

protected:
	static std::string s_incomplete_info_name;
#ifdef _WIN32
	const wmi_handle_source& m_wmi_handle_source;
#else
	static std::string m_docker_sock;
#endif

private:
	// implement container_engine_base
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
	void update_with_size(const std::string& container_id) override;
};
}
}

#endif // _WIN32
#endif // MINIMAL_BUILD