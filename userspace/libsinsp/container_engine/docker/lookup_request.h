#pragma once

namespace libsinsp {
namespace container_engine {

struct docker_lookup_request
{
	docker_lookup_request() :
		request_rw_size(false)
	{}

	docker_lookup_request(const std::string& container_id_value,
			      const std::string& docker_socket_value,
			      bool rw_size_value) :
		container_id(container_id_value),
		docker_socket(docker_socket_value),
		request_rw_size(rw_size_value)
	{}

	bool operator<(const docker_lookup_request& rhs) const
	{
		if(container_id != rhs.container_id)
		{
			return container_id < rhs.container_id;
		}

		if(docker_socket != rhs.docker_socket)
		{
			return docker_socket < rhs.docker_socket;
		}

		return request_rw_size < rhs.request_rw_size;
	}

	bool operator==(const docker_lookup_request& rhs) const
	{
		return container_id == rhs.container_id &&
		       docker_socket == rhs.docker_socket &&
		       request_rw_size == rhs.request_rw_size;
	}

	std::string container_id;
	std::string docker_socket;
	bool request_rw_size;
};


}
}
