#pragma once

#include <libsinsp/container_engine/docker/base.h>

namespace libsinsp {
namespace container_engine {

class podman : public docker_base
{
public:
	podman(container_cache_interface& cache): docker_base(cache) {}

private:
	static std::string m_api_sock;
	static std::string m_user_api_sock_pattern;

	// true if any file matching any possible api socket pattern
	// exists. Is set at the first call to resolve()
	std::unique_ptr<bool> m_api_sock_can_exist;

	// Return true if any possible api socket pattern exists.
	bool can_api_sock_exist();

	// Return whether or not any possible api socket exists. (The actual socket is
	// implement container_engine_base
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
};

}
}
