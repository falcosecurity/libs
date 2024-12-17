// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

class sinsp_container_info;
class sinsp_threadinfo;

#include <libsinsp/container_engine/containerd/containers.grpc.pb.h>
#include <libsinsp/container_engine/containerd/images.grpc.pb.h>
#include <libsinsp/container_engine/container_async_source.h>
#include <libsinsp/container_engine/container_engine_base.h>
#include <libsinsp/container_engine/sinsp_container_type.h>

namespace ContainerdContainerService = containerd::services::containers::v1;
namespace ContainerdImageService = containerd::services::images::v1;

namespace libsinsp {
namespace container_engine {

struct containerd_lookup_request {
	containerd_lookup_request(): container_type(CT_CONTAINERD), uid(0), request_rw_size(false) {}

	containerd_lookup_request(const std::string& container_id_value,
	                          sinsp_container_type container_type_value,
	                          unsigned long uid_value,
	                          bool rw_size_value):
	        container_id(container_id_value),
	        container_type(container_type_value),
	        uid(uid_value),
	        request_rw_size(rw_size_value) {}

	bool operator<(const containerd_lookup_request& rhs) const {
		if(container_id != rhs.container_id) {
			return container_id < rhs.container_id;
		}

		if(container_type != rhs.container_type) {
			return container_type < rhs.container_type;
		}

		if(uid != rhs.uid) {
			return uid < rhs.uid;
		}

		return request_rw_size < rhs.request_rw_size;
	}

	bool operator==(const containerd_lookup_request& rhs) const {
		return container_id == rhs.container_id && container_type == rhs.container_type &&
		       uid == rhs.uid && request_rw_size == rhs.request_rw_size;
	}

	std::string container_id;
	sinsp_container_type container_type;
	unsigned long uid;
	bool request_rw_size;
};

class containerd_async_source : public container_async_source<containerd_lookup_request> {
	using key_type = containerd_lookup_request;

public:
	containerd_async_source(const std::string& socket_path,
	                        uint64_t max_wait_ms,
	                        uint64_t ttl_ms,
	                        container_cache_interface* cache);
	virtual ~containerd_async_source();

	bool is_ok();

private:
	bool parse(const containerd_lookup_request& key, sinsp_container_info& container) override;

	const char* name() const override { return "containerd"; };

	sinsp_container_type container_type(const key_type& key) const override {
		return key.container_type;
	}
	std::string container_id(const key_type& key) const override { return key.container_id; }

	grpc::Status list_container_resp(const std::string& container_id,
	                                 ContainerdContainerService::ListContainersResponse& resp);

	grpc::Status get_image_resp(const std::string& image_name,
	                            ContainerdImageService::GetImageResponse& resp);

	std::unique_ptr<ContainerdContainerService::Containers::Stub> m_container_stub;
	std::unique_ptr<ContainerdImageService::Images::Stub> m_image_stub;
	std::string m_socket_path;
};

class containerd : public container_engine_base {
public:
	containerd(container_cache_interface& cache);

	void parse_containerd(const containerd_lookup_request& request,
	                      container_cache_interface* cache);
	bool resolve(sinsp_threadinfo* tinfo, bool query_os_for_missing_info) override;

private:
	std::unique_ptr<containerd_async_source> m_containerd_info_source;
};

}  // namespace container_engine
}  // namespace libsinsp
