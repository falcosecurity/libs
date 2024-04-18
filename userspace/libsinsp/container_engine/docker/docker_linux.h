#pragma once

#include <libsinsp/container_engine/container_engine_base.h>
#include <libsinsp/container_engine/docker/base.h>

namespace libsinsp {
namespace container_engine {

class docker_linux : public docker_base {
public:
	docker_linux(container_cache_interface& cache) : docker_base(cache) {}

	static void set_docker_sock(std::string docker_sock)
	{
		m_docker_sock = std::move(docker_sock);
	}

	// implement container_engine_base
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;

	void update_with_size(const std::string& container_id) override;

private:
	static std::string m_docker_sock;
};

}
}
