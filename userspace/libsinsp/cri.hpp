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

//////////////////////////
// CRI API calls helpers
//////////////////////////

template<typename api>
inline grpc::Status cri_interface<api>::get_container_status_resp(const std::string &container_id,
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
inline grpc::Status cri_interface<api>::get_container_stats_resp(const std::string &container_id,
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
grpc::Status cri_interface<api>::get_pod_sandbox_status_resp(const std::string &pod_sandbox_id,
					      typename api::PodSandboxStatusResponse &resp)
{
	typename api::PodSandboxStatusRequest req;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_settings::get_cri_timeout());
	context.set_deadline(deadline);
	return m_cri->PodSandboxStatus(&context, req, &resp);
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
inline std::optional<int64_t> cri_interface<api>::get_writable_layer_size(const std::string &container_id)
{
	// Synchronously get the stats response and update the container table.
	// Note that this needs to use the full id.
	typename api::ContainerStatsResponse resp;
	grpc::Status status = get_container_stats_resp(container_id, resp);

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

/////////////////////////////
// Generic parsers helpers
/////////////////////////////

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
inline Json::Value cri_interface<api>::get_info_jvalue(const google::protobuf::Map<std::string, std::string> &info)
{

	Json::Value root;
	Json::Reader reader;
	const auto &info_it = info.find("info");
	if(info_it == info.end())
	{
		return root;
	}
	reader.parse(info_it->second, root);
	return root;
}

///////////////////////////////////////////////////////////
// CRI response (ContainerStatusResponse) parsers helpers
///////////////////////////////////////////////////////////


template<typename api>
inline bool cri_interface<api>::parse_cri_base(const typename api::ContainerStatus &status, sinsp_container_info &container)
{
	container.m_full_id = status.id();
	container.m_name = status.metadata().name();
	// This is in Nanoseconds(in CRI API). Need to convert it to seconds.
	container.m_created_time = static_cast<int64_t>(status.created_at() / ONE_SECOND_IN_NS);

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_pod_sandbox_id_for_container(const Json::Value &root,
			     sinsp_container_info &container)
{
	if(root.isNull())
	{
		return false;
	}

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		std::string pod_sandbox_id = root["sandboxID"].asString();
		container.m_pod_sandbox_id = pod_sandbox_id;
		// Add the pod sandbox id as label to the container for backward compatibility
		container.m_labels["io.kubernetes.sandbox.id"] = pod_sandbox_id;
	}

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_labels(const typename api::ContainerStatus &status, sinsp_container_info &container)
{
	for(const auto &pair : status.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_labels[pair.first] = pair.second;
		}
	}
	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_image(const typename api::ContainerStatus &status,
					 const Json::Value &root,
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
		/* Retrieve image_name from annotations as backup when image name may (still) start with sha256
		 * or otherwise was not successfully retrieved. Brute force try each schema we know of for containerd 
		 * and cri-o container runtimes. 
		*/

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
inline bool cri_interface<api>::parse_cri_json_imageid(const Json::Value &root, sinsp_container_info &container)
{
	if(root.isNull())
	{
		return false;
	}

	const Json::Value *image = nullptr;
	if(!walk_down_json(root, &image, "config", "image", "image") || !image->isString())
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

template<typename api> 
inline bool cri_interface<api>::parse_cri_env(const Json::Value &root, sinsp_container_info &container)
{
	if(root.isNull())
	{
		return false;
	}

	const Json::Value *envs = nullptr;
	if(!walk_down_json(root, &envs, "config", "envs") || !envs->isArray())
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
inline bool cri_interface<api>::parse_cri_ext_container_info(const Json::Value &root, sinsp_container_info &container)
{
	if(root.isNull())
	{
		return false;
	}

	const Json::Value *linux = nullptr;
	if(!walk_down_json(root, &linux, "runtimeSpec", "linux") || !linux->isObject())
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
	if(!priv_found && walk_down_json(root, &privileged, "config", "linux", "security_context", "privileged") &&
	   privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	// cri-o
	if(!priv_found && walk_down_json(root, &privileged, "privileged") && privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_user_info(const Json::Value &root, sinsp_container_info &container)
{
	if(root.isNull())
	{
		return false;
	}

	const Json::Value *uid = nullptr;
	if(!walk_down_json(root, &uid, "runtimeSpec", "process", "user", "uid") || !uid->isInt())
	{
		return false;
	}

	container.m_container_user = std::to_string(uid->asInt());
	return true;
}

///////////////////////////////////////////////////////////
// CRI response (PodSandboxStatus) parsers helpers
///////////////////////////////////////////////////////////

// overloaded w/ PodSandboxStatus
template<typename api>
inline bool cri_interface<api>::parse_cri_base(const typename api::PodSandboxStatus &status, sinsp_container_info &container)
{
	container.m_full_id = status.id();
	container.m_name = status.metadata().name();
	// This is in Nanoseconds(in CRI API). Need to convert it to seconds.
	container.m_created_time = static_cast<int64_t>(status.created_at() / ONE_SECOND_IN_NS);

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_pod_sandbox_id_for_podsandbox(sinsp_container_info &container)
{
	container.m_pod_sandbox_id = container.m_full_id;
	// Add the pod sandbox id as label to the container for backward compatibility
	container.m_labels["io.kubernetes.sandbox.id"] = container.m_full_id;

	return true;
}

// overloaded w/ PodSandboxStatus
template<typename api>
inline bool cri_interface<api>::parse_cri_labels(const typename api::PodSandboxStatus &status, sinsp_container_info &container)
{
	for(const auto &pair : status.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_labels[pair.first] = pair.second;
		}
	}
	container.m_labels["io.kubernetes.pod.uid"] = status.metadata().uid();
	container.m_labels["io.kubernetes.pod.name"] = status.metadata().name();
	container.m_labels["io.kubernetes.pod.namespace"] = status.metadata().namespace_();

	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_pod_sandbox_labels(const typename api::PodSandboxStatus &status, sinsp_container_info &container)
{
	for(const auto &pair : status.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_pod_sandbox_labels[pair.first] = pair.second;
		}
	}
	return true;
}

template<typename api>
inline bool cri_interface<api>::parse_cri_pod_sandbox_network(const typename api::PodSandboxStatus &status,
			     const Json::Value &root,
			     sinsp_container_info &container)
{
	//
	// Pod IP
	//

	const auto pod_ip = status.network().ip();
	uint32_t ip;
	if(pod_ip.empty() || 
		// using host netns
		(status.linux().namespaces().options().network() == api::NamespaceMode::NODE) ||
		(inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1))
	{
		container.m_container_ip = 0;
	} else
	{
		container.m_container_ip = ntohl(ip);
	}

	//
	// Pod Sandbox CNI Result
	//

	if(root.isNull())
	{
		return false;
	}

	std::string cniresult;
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

	container.m_pod_sandbox_cniresult = cniresult;

	return true;
}

///////////////////////////////////////////////////////////////////
// Main CRI parse entrypoint (make API calls and parse responses)
///////////////////////////////////////////////////////////////////

template<typename api>
inline bool cri_interface<api>::parse(const libsinsp::cgroup_limits::cgroup_limits_key &key, sinsp_container_info &container)
{
	typename api::ContainerStatusResponse container_status_resp;
	// status contains info around if API call suceeded and is not the container status property
	grpc::Status status = get_container_status_resp(container.m_id, container_status_resp);

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): ContainerStatusResponse status error message: (%s)", container.m_id.c_str(),
			status.error_message().c_str());

	// If container status failed try to get the pod sandbox status.
	if(!status.ok())
	{
		typename api::PodSandboxStatusResponse pod_sandbox_status_resp;
		status = get_pod_sandbox_status_resp(container.m_id, pod_sandbox_status_resp);
		if(status.ok())
		{
			/*
			* We also want to ensure that the pod sandbox container stored in the container cache is
			* fully filled out with available information as applicable.
			* Most notably, the container's m_full_id and m_pod_sandbox_id will be the same, and the
			* absence of container images can be attributed to the fact that they are not available for
			* pod sandbox container processes.
			* Another notable fact is that for pod sandbox containers container.m_lables and 
			* container.m_pod_sandbox_labels are also the same.
			*/
			container.m_is_pod_sandbox = true;
			const auto &resp_pod_sandbox_container = pod_sandbox_status_resp.status();
			const auto &resp_pod_sandbox_container_info = pod_sandbox_status_resp.info();
			const auto root_pod_sandbox = get_info_jvalue(resp_pod_sandbox_container_info);
			parse_cri_base(resp_pod_sandbox_container, container);
			parse_cri_pod_sandbox_id_for_podsandbox(container);
			// `parse_cri_labels`: The pod sandbox container does not contain the namespace etc as labels.
			// To be consistent in the k8s filterchecks we retrieve the namespace from elsewhere in the response and
			// add them as labels
			parse_cri_labels(resp_pod_sandbox_container, container);
			parse_cri_pod_sandbox_network(resp_pod_sandbox_container, root_pod_sandbox, container);
			parse_cri_pod_sandbox_labels(resp_pod_sandbox_container, container);
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

	if(!container_status_resp.has_status())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): ContainerStatusResponse call no status, returning", container.m_id.c_str());
		ASSERT(false);
		return false;
	}

	const auto &resp_container = container_status_resp.status();
	const auto &resp_container_info = container_status_resp.info();
	const auto root_container = get_info_jvalue(resp_container_info);
	parse_cri_base(resp_container, container);
	parse_cri_pod_sandbox_id_for_container(root_container, container);
	parse_cri_labels(resp_container, container);
	parse_cri_image(resp_container, root_container, container);
	parse_cri_json_imageid(root_container, container);
	parse_cri_mounts(resp_container, container);
	parse_cri_env(root_container, container);
	// In some cases (e.g. openshift), the cri-o response may not have an info property, which is used to set the container user. In those cases, the container name stays at its default "<NA>" value.
	parse_cri_user_info(root_container, container);
	bool ret = parse_cri_ext_container_info(root_container, container);
	if(!ret)
	{
		libsinsp::cgroup_limits::cgroup_limits_value limits;
		libsinsp::cgroup_limits::get_cgroup_resource_limits(key, limits);

		container.m_memory_limit = limits.m_memory_limit;
		container.m_cpu_shares = limits.m_cpu_shares;
		container.m_cpu_quota = limits.m_cpu_quota;
		container.m_cpu_period = limits.m_cpu_period;
		container.m_cpuset_cpu_count = limits.m_cpuset_cpu_count;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "cri (%s): after container parsing: repo=%s tag=%s image=%s digest=%s",
			container.m_id.c_str(), container.m_imagerepo.c_str(), container.m_imagetag.c_str(),
			container.m_image.c_str(), container.m_imagedigest.c_str());

	// Enabled by default for Falco consumer
	if(cri_settings::get_cri_extra_queries())
	{
		if(container.m_imageid.empty())
		{
			// `get_container_image_id`: Makes new / extra API calls
			container.m_imageid = get_container_image_id(resp_container.image_ref());
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"cri (%s): after get_container_image_id: repo=%s tag=%s image=%s digest=%s",
					container.m_id.c_str(), container.m_imagerepo.c_str(),
					container.m_imagetag.c_str(), container.m_image.c_str(),
					container.m_imagedigest.c_str());
		}

		/*
		* The recent refactor makes full use of PodSandboxStatusResponse, removing the need to access pod sandbox containers
		* in k8s filterchecks. Now, we also store the pod sandbox labels in the container.
		* While this might seem redundant in cases where multiple containers exist in a pod, considering that the concurrent
		* number of containers on a node is typically capped at 100-300 and many pods contain only 1-3 containers,
		* it doesn't add significant overhead. Moreover, these extra lookups have always been performed for container ips in the past
		* and therefore are no new additions.
		*/
		typename api::PodSandboxStatusResponse pod_sandbox_status_resp;
		status = get_pod_sandbox_status_resp(container.m_pod_sandbox_id, pod_sandbox_status_resp);
		if (!status.ok())
		{
			// do not mark overall lookup as false only because the PodSandboxStatusResponse failed, 
			// but previous ContainerStatusResponse succeeded
			return true;
		}
		const auto &resp_pod_sandbox_container = pod_sandbox_status_resp.status();
		const auto &resp_pod_sandbox_container_info = pod_sandbox_status_resp.info();
		const auto root_pod_sandbox = get_info_jvalue(resp_pod_sandbox_container_info);
		// Add pod response network and labels to original container
		parse_cri_pod_sandbox_network(resp_pod_sandbox_container, root_pod_sandbox, container);
		parse_cri_pod_sandbox_labels(resp_pod_sandbox_container, container);
	}

	return true;
}
} // namespace cri
} // namespace libsinsp
