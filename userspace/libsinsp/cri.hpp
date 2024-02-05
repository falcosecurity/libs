// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/cri.h>

#include <libsinsp/grpc_channel_registry.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

#include <chrono>

#define MAX_CNIRESULT_LENGTH 4096

namespace
{
template<typename api> bool pod_uses_host_netns(const typename api::PodSandboxStatusResponse &resp)
{
	const auto netns = resp.status().linux().namespaces().options().network();
	return netns == api::NamespaceMode::NODE;
}
} // namespace

namespace libsinsp
{
namespace cri
{

template<typename api> 
inline cri_interface<api>::cri_interface(const std::string &cri_path)
{
	std::shared_ptr<grpc::Channel> channel = libsinsp::grpc_channel_registry::get_channel("unix://" + cri_path);

	m_cri = api::RuntimeService::NewStub(channel);

	typename api::VersionRequest vreq;
	typename api::VersionResponse vresp;

	vreq.set_version(api::version);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	grpc::Status status = m_cri->Version(&context, vreq, &vresp);

	if(!status.ok())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_NOTICE,
				"cri: CRI runtime returned an error after version check at %s: %s", cri_path.c_str(),
				status.error_message().c_str());
		m_cri.reset(nullptr);
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_INFO, "cri: CRI runtime: %s %s", vresp.runtime_name().c_str(),
			vresp.runtime_version().c_str());

	m_cri_image = api::ImageService::NewStub(channel);

	const std::string &runtime_name = vresp.runtime_name();
	if(runtime_name == "containerd")
	{
		m_cri_runtime_type = CT_CONTAINERD;
	}
	else if(runtime_name == "cri-o")
	{
		m_cri_runtime_type = CT_CRIO;
	}
	else
	{
		m_cri_runtime_type = CT_CRI;
	}
	cri_settings::set_cri_runtime_type(m_cri_runtime_type);
}

template<typename api> 
inline sinsp_container_type cri_interface<api>::get_cri_runtime_type() const
{
	return m_cri_runtime_type;
}

template<typename api>
inline grpc::Status cri_interface<api>::get_container_status(const std::string &container_id,
						      typename api::ContainerStatusResponse &resp)
{
	typename api::ContainerStatusRequest req;
	req.set_container_id(container_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	return m_cri->ContainerStatus(&context, req, &resp);
}

template<typename api>
inline grpc::Status cri_interface<api>::get_container_stats(const std::string &container_id,
						     typename api::ContainerStatsResponse &resp)
{
	typename api::ContainerStatsRequest req;
	req.set_container_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_size_timeout());
	context.set_deadline(deadline);
	return m_cri->ContainerStats(&context, req, &resp);
}

template<typename api>
inline std::optional<int64_t> cri_interface<api>::get_writable_layer_size(const std::string &container_id)
{
	// Synchronously get the stats response and update the container table.
	// Note that this needs to use the full id.
	typename api::ContainerStatsResponse resp;
	grpc::Status status = get_container_stats(container_id, resp);

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): Status from ContainerStats: (%s)", container_id.c_str(),
			status.error_message().empty() ? "SUCCESS" : status.error_message().c_str());

	if(!status.ok())
	{
		return std::nullopt;
	}

	if(!resp.has_stats())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: stats() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	const auto &resp_stats = resp.stats();

	if(!resp_stats.has_writable_layer())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: writable_layer() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	if(!resp_stats.writable_layer().has_used_bytes())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: used_bytes() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	return resp_stats.writable_layer().used_bytes().value();
}

template<typename api>
inline bool cri_interface<api>::parse_cri_image(const typename api::ContainerStatus &status,
					 const google::protobuf::Map<std::string, std::string> &info,
					 sinsp_container_info &container)
{
	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest

	bool have_digest = false;
	const auto &image_ref = status.image_ref();
	std::string image_name = status.image().image();
	bool get_tag_from_image = false;
	auto digest_start = image_ref.find("sha256:");

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): parse_cri_image: image_ref=%s, digest_start=%d",
			container.m_id.c_str(), image_ref.c_str(), digest_start);

	switch(digest_start)
	{
	case 0: // sha256:digest
		have_digest = true;
		break;
	case std::string::npos:
		break;
	default: // host/image@sha256:digest
		have_digest = image_ref[digest_start - 1] == '@';
		if(have_digest)
		{
			image_name = image_ref.substr(0, digest_start - 1);
			get_tag_from_image = true;
		}
	}

	if(image_name.empty() || strncmp(image_name.c_str(), "sha256", 6) == 0)
	{
		/* Retrieve image_name from annotations as backup when image name may start with sha256
		or otherwise was not retrieved. Brute force try each schema we know of for containerd and crio container
		runtimes. */

		Json::Value root;
		Json::Reader reader;
		const auto &info_it = info.find("info");
		if(info_it != info.end())
		{
			if(reader.parse(info_it->second, root))
			{
				if(!root.isNull())
				{
					Json::Value jvalue;
					jvalue = root["runtimeSpec"]["annotations"]["io.kubernetes.cri.image-name"];
					if(jvalue.isNull())
					{
						jvalue =
							root["runtimeSpec"]["annotations"]["io.kubernetes.cri-o.Image"];
					}
					if(jvalue.isNull())
					{
						jvalue = root["runtimeSpec"]["annotations"]
							     ["io.kubernetes.cri-o.ImageName"];
					}
					if(!jvalue.isNull())
					{
						image_name = jvalue.asString();
						get_tag_from_image = false;
					}
				}
			}
		}
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): parse_cri_image: have_digest=%d image_name=%s",
			container.m_id.c_str(), have_digest, image_name.c_str());

	std::string hostname, port, digest;
	sinsp_utils::split_container_image(image_name, hostname, port, container.m_imagerepo, container.m_imagetag,
					   digest, false);

	if(get_tag_from_image)
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): parse_cri_image: tag=%s, pulling tag from %s",
				container.m_id.c_str(), container.m_imagetag.c_str(), status.image().image().c_str());

		std::string digest2, repo;
		sinsp_utils::split_container_image(status.image().image(), hostname, port, repo, container.m_imagetag,
						   digest2, false);

		image_name.push_back(':');
		image_name.append(container.m_imagetag);
	}

	container.m_image = image_name;

	if(have_digest)
	{
		container.m_imagedigest = image_ref.substr(digest_start);
	}
	else
	{
		container.m_imagedigest = digest;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): parse_cri_image: repo=%s tag=%s image=%s digest=%s",
			container.m_id.c_str(), container.m_imagerepo.c_str(), container.m_imagetag.c_str(),
			container.m_image.c_str(), container.m_imagedigest.c_str());

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_mounts(const typename api::ContainerStatus &status, sinsp_container_info &container)
{
	for(const auto &mount : status.mounts())
	{
		const char *propagation;
		switch(mount.propagation())
		{
		case api::MountPropagation::PROPAGATION_PRIVATE:
			propagation = "private";
			break;
		case api::MountPropagation::PROPAGATION_HOST_TO_CONTAINER:
			propagation = "rslave";
			break;
		case api::MountPropagation::PROPAGATION_BIDIRECTIONAL:
			propagation = "rshared";
			break;
		default:
			propagation = "unknown";
			break;
		}
		container.m_mounts.emplace_back(mount.host_path(), mount.container_path(), "", !mount.readonly(),
						propagation);
	}
	return true;
}

inline bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key)
{
	if(root.isMember(key))
	{
		*out = &root[key];
		return true;
	}
	return false;
}

template<typename... Args>
inline bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key, Args... args)
{
	if(root.isMember(key))
	{
		return walk_down_json(root[key], out, args...);
	}
	return false;
}

inline bool set_numeric_32(const Json::Value &dict, const std::string &key, int32_t &val)
{
	if(!dict.isMember(key))
	{
		return false;
	}
	const auto &json_val = dict[key];
	if(!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt();
	return true;
}

inline bool set_numeric_64(const Json::Value &dict, const std::string &key, int64_t &val)
{
	if(!dict.isMember(key))
	{
		return false;
	}
	const auto &json_val = dict[key];
	if(!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt64();
	return true;
}

template<typename api> 
inline bool cri_interface<api>::parse_cri_env(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *envs = nullptr;
	if(!walk_down_json(info, &envs, "config", "envs") || !envs->isArray())
	{
		return false;
	}

	for(const auto &env_var : *envs)
	{
		const auto &key = env_var["key"];
		const auto &value = env_var["value"];

		if(key.isString() && value.isString())
		{
			auto var = key.asString();
			var += '=';
			var += value.asString();
			container.m_env.emplace_back(var);
		}
	}

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_json_image(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *image = nullptr;
	if(!walk_down_json(info, &image, "config", "image", "image") || !image->isString())
	{
		return false;
	}

	auto image_str = image->asString();
	auto pos = image_str.find(':');
	if(pos == std::string::npos)
	{
		container.m_imageid = std::move(image_str);
	}
	else
	{
		container.m_imageid = image_str.substr(pos + 1);
	}

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_ext_container_info(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *linux = nullptr;
	if(!walk_down_json(info, &linux, "runtimeSpec", "linux") || !linux->isObject())
	{
		return false;
	}

	const Json::Value *memory = nullptr;
	if(walk_down_json(*linux, &memory, "resources", "memory"))
	{
		set_numeric_64(*memory, "limit", container.m_memory_limit);
		container.m_swap_limit = container.m_memory_limit;
	}

	const Json::Value *cpu = nullptr;
	if(walk_down_json(*linux, &cpu, "resources", "cpu") && cpu->isObject())
	{
		set_numeric_64(*cpu, "shares", container.m_cpu_shares);
		set_numeric_64(*cpu, "quota", container.m_cpu_quota);
		set_numeric_64(*cpu, "period", container.m_cpu_period);
		set_numeric_32(*cpu, "cpuset_cpu_count", container.m_cpuset_cpu_count);
	}

	bool priv_found = false;
	const Json::Value *privileged = nullptr;
	// old containerd?
	if(walk_down_json(*linux, &privileged, "security_context", "privileged") && privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	// containerd
	if(!priv_found && walk_down_json(info, &privileged, "config", "linux", "security_context", "privileged") &&
	   privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	// cri-o
	if(!priv_found && walk_down_json(info, &privileged, "privileged") && privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_user_info(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *uid = nullptr;
	if(!walk_down_json(info, &uid, "runtimeSpec", "process", "user", "uid") || !uid->isInt())
	{
		return false;
	}

	container.m_container_user = std::to_string(uid->asInt());
	return true;
}

// TODO: Explore future schema standardizations, https://github.com/falcosecurity/falco/issues/2387
template<typename api>
inline void cri_interface<api>::get_pod_info_cniresult(typename api::PodSandboxStatusResponse &resp, std::string &cniresult)
{
	Json::Value root;
	Json::Reader reader;
	const auto &info_it = resp.info().find("info");
	if(info_it == resp.info().end())
	{
		return;
	}
	if(!reader.parse(info_it->second, root))
	{
		return;
	}
	if(root.isNull())
	{
		return;
	}

	Json::Value jvalue;
	/* Lookup approach is brute force "try all schemas" we know of, do not condition by container runtime for
	 * possible future "would just work" luck in case other runtimes standardize on one of the current schemas. */

	jvalue = root["cniResult"]["Interfaces"]; /* pod info schema of CT_CONTAINERD runtime. */
	if(!jvalue.isNull())
	{
		/* If applicable remove members / fields not needed for incident response. */
		jvalue.removeMember("lo");
		for(auto &key : jvalue.getMemberNames())
		{
			if(0 == strncmp(key.c_str(), "veth", 4))
			{
				jvalue.removeMember(key);
			}
			else
			{
				jvalue[key].removeMember("Mac");
				jvalue[key].removeMember("Sandbox");
			}
		}

		Json::FastWriter fastWriter;
		cniresult = fastWriter.write(jvalue);
	}

	if(jvalue.isNull())
	{
		jvalue = root["runtimeSpec"]["annotations"]
			     ["io.kubernetes.cri-o.CNIResult"]; /* pod info schema of CT_CRIO runtime. Note interfaces
								   names are unknown here. */
		if(!jvalue.isNull())
		{
			cniresult = jvalue.asString();
		}
	}

	if(cniresult[cniresult.size() - 1] == '\n') /* Make subsequent ETLs nicer w/ minor cleanups if applicable. */
	{
		cniresult.pop_back();
	}

	if(cniresult.size() > MAX_CNIRESULT_LENGTH) /* Safety upper bound, should never happen. */
	{
		cniresult.resize(MAX_CNIRESULT_LENGTH);
	}
}

template<typename api>
inline void cri_interface<api>::get_pod_sandbox_resp(const std::string &pod_sandbox_id,
					      typename api::PodSandboxStatusResponse &resp, grpc::Status &status)
{
	typename api::PodSandboxStatusRequest req;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	status = m_cri->PodSandboxStatus(&context, req, &resp);
}

template<typename api> 
inline uint32_t cri_interface<api>::get_pod_sandbox_ip(typename api::PodSandboxStatusResponse &resp)
{
	if(pod_uses_host_netns<api>(resp))
	{
		return 0;
	}

	const auto &pod_ip = resp.status().network().ip();
	if(pod_ip.empty())
	{
		return 0;
	}

	uint32_t ip;
	if(inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1)
	{
		ASSERT(false);
		return 0;
	}
	else
	{
		return ip;
	}
}

template<typename api>
inline void cri_interface<api>::get_container_ip(const std::string &container_id, uint32_t &container_ip,
					  std::string &cniresult)
{
	container_ip = 0;
	cniresult = "";
	typename api::ListContainersRequest req;
	typename api::ListContainersResponse resp;
	auto filter = req.mutable_filter();
	filter->set_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	grpc::Status lstatus = m_cri->ListContainers(&context, req, &resp);

	switch(resp.containers_size())
	{
	case 0:
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Container id %s not in list from CRI",
				container_id.c_str());
		ASSERT(false);
		break;
	case 1:
	{
		const auto &cri_container = resp.containers(0);
		typename api::PodSandboxStatusResponse resp_pod;
		grpc::Status status_pod;
		get_pod_sandbox_resp(cri_container.pod_sandbox_id(), resp_pod, status_pod);
		if(status_pod.ok())
		{
			container_ip = ntohl(get_pod_sandbox_ip(resp_pod));
			get_pod_info_cniresult(resp_pod, cniresult);
		}
	}
	default:
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Container id %s matches more than once in list from CRI",
				container_id.c_str());
		ASSERT(false);
		break;
	}
}

template<typename api> 
inline std::string cri_interface<api>::get_container_image_id(const std::string &image_ref)
{
	typename api::ListImagesRequest req;
	typename api::ListImagesResponse resp;
	auto filter = req.mutable_filter();
	auto spec = filter->mutable_image();
	spec->set_image(image_ref);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	grpc::Status status = m_cri_image->ListImages(&context, req, &resp);

	switch(resp.images_size())
	{
	case 0:
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Image ref %s not in list from CRI", image_ref.c_str());
		ASSERT(false);
		break;
	case 1:
	{
		const auto &image = resp.images(0);
		return image.id();
	}
	default:
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Image ref %s matches more than once in list from CRI",
				image_ref.c_str());
		ASSERT(false);
		break;
	}

	return "";
}

template<typename api>
inline bool cri_interface<api>::parse_containerd(const typename api::ContainerStatusResponse &status,
					  sinsp_container_info &container)
{
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s) in parse_containerd", container.m_id.c_str());

	const auto &info_it = status.info().find("info");
	if(info_it == status.info().end())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s) no info property, returning",
				container.m_id.c_str());
		return false;
	}

	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(info_it->second, root))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s) could not json parse info, returning",
				container.m_id.c_str());
		ASSERT(false);
		return false;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): will parse info json: %s", container.m_id.c_str(),
			info_it->second.c_str());

	parse_cri_env(root, container);
	parse_cri_json_image(root, container);
	bool ret = parse_cri_ext_container_info(root, container);
	parse_cri_user_info(root, container);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		// Add the pod sandbox id as label to the container.
		// This labels is needed by the filterchecks code to get the pod labels.
		container.m_labels["io.kubernetes.sandbox.id"] = pod_sandbox_id;
		typename api::PodSandboxStatusResponse resp_pod;
		grpc::Status status_pod;
		get_pod_sandbox_resp(pod_sandbox_id, resp_pod, status_pod);
		if(status_pod.ok())
		{
			container.m_container_ip = ntohl(get_pod_sandbox_ip(resp_pod));
			get_pod_info_cniresult(resp_pod, container.m_pod_cniresult);
		}
	}

	return ret;
}

template<typename api>
inline bool cri_interface<api>::parse(const libsinsp::cgroup_limits::cgroup_limits_key &key, sinsp_container_info &container)
{
	typename api::ContainerStatusResponse resp;
	grpc::Status status = get_container_status(container.m_id, resp);

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): Status from ContainerStatus: (%s)", container.m_id.c_str(),
			status.error_message().c_str());

	// If getting the container status fails then try to get the pod sandbox status.
	if(!status.ok())
	{
		typename api::PodSandboxStatusResponse resp;
		grpc::Status status_pod;
		get_pod_sandbox_resp(container.m_id, resp, status_pod);

		if(status_pod.ok())
		{
			container.m_is_pod_sandbox = true;
			// Fill the labels for the pod sanbox.
			// Used to populate the k8s.pod.labels field.
			for(const auto &pair : resp.status().labels())
			{
				if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
				{
					container.m_labels[pair.first] = pair.second;
				}
			}
			return true;
		}
		else
		{
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"cri (%s): id is neither a container nor a pod sandbox: %s",
					container.m_id.c_str(), status.error_message().c_str());
			return false;
		}
	}

	if(!resp.has_status())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s) no status, returning", container.m_id.c_str());
		ASSERT(false);
		return false;
	}

	const auto &resp_container = resp.status();
	const auto &resp_container_info = resp.info();
	container.m_full_id = resp_container.id();
	container.m_name = resp_container.metadata().name();

	// This is in Nanoseconds(in CRI API). Need to convert it to seconds.
	container.m_created_time = static_cast<int64_t>(resp_container.created_at() / ONE_SECOND_IN_NS);

	for(const auto &pair : resp_container.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_labels[pair.first] = pair.second;
		}
	}

	parse_cri_image(resp_container, resp_container_info, container);
	parse_cri_mounts(resp_container, container);

	if(!parse_containerd(resp, container))
	{
		libsinsp::cgroup_limits::cgroup_limits_value limits;
		libsinsp::cgroup_limits::get_cgroup_resource_limits(key, limits);

		container.m_memory_limit = limits.m_memory_limit;
		container.m_cpu_shares = limits.m_cpu_shares;
		container.m_cpu_quota = limits.m_cpu_quota;
		container.m_cpu_period = limits.m_cpu_period;
		container.m_cpuset_cpu_count = limits.m_cpuset_cpu_count;

		// In some cases (e.g. openshift), the cri-o response
		// may not have an info property, which is used to set
		// the container user. In those cases, the container
		// name stays at its default "<NA>" value.
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): after parse_containerd: repo=%s tag=%s image=%s digest=%s",
			container.m_id.c_str(), container.m_imagerepo.c_str(), container.m_imagetag.c_str(),
			container.m_image.c_str(), container.m_imagedigest.c_str());

	if(cri_settings::get_cri_extra_queries())
	{
		if(!container.m_container_ip)
		{
			get_container_ip(container.m_id, container.m_container_ip, container.m_pod_cniresult);
		}
		if(container.m_imageid.empty())
		{
			container.m_imageid = get_container_image_id(resp_container.image_ref());
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"cri (%s): after get_container_image_id: repo=%s tag=%s image=%s digest=%s",
					container.m_id.c_str(), container.m_imagerepo.c_str(),
					container.m_imagetag.c_str(), container.m_image.c_str(),
					container.m_imagedigest.c_str());
		}
	}

	return true;
}
} // namespace cri
} // namespace libsinsp
