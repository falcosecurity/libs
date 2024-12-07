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
#include <libsinsp/container_engine/container_engine_base.h>
#include <libsinsp/container_engine/sinsp_container_type.h>

namespace ContainerdService = containerd::services::containers::v1;

namespace libsinsp {
namespace container_engine {

class containerd_interface {
public:
	containerd_interface(const std::string &socket_path);

	grpc::Status list_container_resp(const std::string &container_id,
	                                 ContainerdService::ListContainersResponse &resp);

	bool is_ok();

private:
	std::unique_ptr<ContainerdService::Containers::Stub> m_stub;
};

class containerd : public container_engine_base {
public:
	containerd(container_cache_interface &cache);

	bool parse_containerd(sinsp_container_info &container, const std::string &container_id);
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;

private:
	std::unique_ptr<containerd_interface> m_interface;
};

}  // namespace container_engine
}  // namespace libsinsp
