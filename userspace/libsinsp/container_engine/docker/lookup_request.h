#pragma once

#include "container_engine/sinsp_container_type.h"

namespace libsinsp {
namespace container_engine {

struct docker_lookup_request
{
	docker_lookup_request() :
		container_type(CT_DOCKER),
		uid(0),
		request_rw_size(false)
	{}

	docker_lookup_request(const std::string& container_id_value,
			      const std::string& docker_socket_value,
			      sinsp_container_type container_type_value,
			      unsigned long uid_value,
			      bool rw_size_value) :
		container_id(container_id_value),
		docker_socket(docker_socket_value),
		container_type(container_type_value),
		uid(uid_value),
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

		if(container_type != rhs.container_type)
		{
			return container_type < rhs.container_type;
		}

		if(uid != rhs.uid)
		{
			return uid < rhs.uid;
		}

		return request_rw_size < rhs.request_rw_size;
	}

	bool operator==(const docker_lookup_request& rhs) const
	{
		return container_id == rhs.container_id &&
		       docker_socket == rhs.docker_socket &&
		       container_type == rhs.container_type &&
		       uid == rhs.uid &&
		       request_rw_size == rhs.request_rw_size;
	}

	std::string container_id;
	std::string docker_socket;
	sinsp_container_type container_type;
	unsigned long uid;
	bool request_rw_size;
};


}
}
