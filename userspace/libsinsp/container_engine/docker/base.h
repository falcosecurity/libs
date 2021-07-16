#pragma once

#include "container_engine/container_engine_base.h"
#include "container_engine/docker/async_source.h"

class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

class docker_lookup_request;

class docker_base : public container_engine_base
{
public:
	docker_base(container_cache_interface &cache) : container_engine_base(cache)
	{}

	void cleanup() override;

protected:
	void parse_docker_async(const docker_lookup_request& request, container_cache_interface *cache);

	bool resolve_impl(sinsp_threadinfo *tinfo, const docker_lookup_request& request,
			  bool query_os_for_missing_info);

	std::unique_ptr<docker_async_source> m_docker_info_source;
};

}
}
