#pragma once

namespace libsinsp {
namespace container_engine {

struct docker_lookup_request
{
	docker_lookup_request() :
		request_rw_size(false)
	{}

	docker_lookup_request(const std::string& container_id_value,
			      bool rw_size_value) :
		container_id(container_id_value),
		request_rw_size(rw_size_value)
	{}

	bool operator<(const docker_lookup_request& rhs) const
	{
		if(container_id != rhs.container_id)
		{
			return container_id < rhs.container_id;
		}

		return request_rw_size < rhs.request_rw_size;
	}

	bool operator==(const docker_lookup_request& rhs) const
	{
		return container_id == rhs.container_id &&
		       request_rw_size == rhs.request_rw_size;
	}

	std::string container_id;
	bool request_rw_size;
};


}
}
