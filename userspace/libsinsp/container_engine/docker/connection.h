#pragma once

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

#include <string>

#include <libsinsp/container_engine/docker/lookup_request.h>

namespace libsinsp {
namespace container_engine {

class docker_connection {
public:
	enum docker_response {
		RESP_OK = 0,
		RESP_BAD_REQUEST = 1,
		RESP_ERROR = 2,
		RESP_TIMEOUT = 3
	};

	docker_connection();
	~docker_connection();

	docker_response
	get_docker(const docker_lookup_request& request, const std::string& req_url, std::string& json);

	void set_api_version(const std::string& api_version)
	{
		m_api_version = api_version;
	}

private:
	std::string m_api_version;

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	CURLM *m_curlm;
#endif
};

}
}
