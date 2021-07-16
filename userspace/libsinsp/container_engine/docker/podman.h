#pragma once

#include "container_engine/docker/base.h"

namespace libsinsp {
namespace container_engine {

class podman : public docker_base
{
public:
	podman(container_cache_interface& cache): docker_base(cache) {}

private:
	static std::string m_api_sock;

	// implement container_engine_base
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
	void update_with_size(const std::string& container_id) override;
};

}
}
