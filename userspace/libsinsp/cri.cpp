/*
Copyright (C) 2021 The Falco Authors.

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

#include "cri.h"

#include <chrono>
#include "grpc_channel_registry.h"

#include "sinsp.h"
#include "sinsp_int.h"

using namespace std;
#define MAX_CNIRESULT_LENGTH 4096

namespace {
bool pod_uses_host_netns(const runtime::v1alpha2::PodSandboxStatusResponse& resp)
{
	const auto netns = resp.status().linux().namespaces().options().network();
	return netns == runtime::v1alpha2::NODE;
}
}

namespace libsinsp {
namespace cri {
std::vector<std::string> s_cri_unix_socket_paths;
int64_t s_cri_timeout = 1000;
int64_t s_cri_size_timeout = 10000;
sinsp_container_type s_cri_runtime_type = CT_CRI;
std::string s_cri_unix_socket_path;
bool s_cri_extra_queries = true;

cri_interface::cri_interface(const std::string& cri_path)
{
	std::shared_ptr<grpc::Channel> channel = libsinsp::grpc_channel_registry::get_channel("unix://" + cri_path);

	m_cri = runtime::v1alpha2::RuntimeService::NewStub(channel);

	runtime::v1alpha2::VersionRequest vreq;
	runtime::v1alpha2::VersionResponse vresp;

	vreq.set_version("v1alpha2");
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->Version(&context, vreq, &vresp);

	if (!status.ok())
	{
		g_logger.format(sinsp_logger::SEV_NOTICE, "cri: CRI runtime returned an error after version check at %s: %s",
				cri_path.c_str(), status.error_message().c_str());
		m_cri.reset(nullptr);
		return;
	}

	g_logger.format(sinsp_logger::SEV_INFO, "cri: CRI runtime: %s %s", vresp.runtime_name().c_str(), vresp.runtime_version().c_str());

	m_cri_image = runtime::v1alpha2::ImageService::NewStub(channel);

	const std::string& runtime_name = vresp.runtime_name();
	if(runtime_name == "containerd")
	{
		m_cri_runtime_type = CT_CONTAINERD;
	} else if(runtime_name == "cri-o")
	{
		m_cri_runtime_type = CT_CRIO;
	} else
	{
		m_cri_runtime_type = CT_CRI;
	}
	s_cri_runtime_type = m_cri_runtime_type;
}

sinsp_container_type cri_interface::get_cri_runtime_type() const
{
	return m_cri_runtime_type;
}

grpc::Status cri_interface::get_container_status(const std::string& container_id, runtime::v1alpha2::ContainerStatusResponse& resp)
{
	runtime::v1alpha2::ContainerStatusRequest req;
	req.set_container_id(container_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	return m_cri->ContainerStatus(&context, req, &resp);
}

grpc::Status cri_interface::get_container_stats(const std::string& container_id, runtime::v1alpha2::ContainerStatsResponse& resp)
{
	runtime::v1alpha2::ContainerStatsRequest req;
	req.set_container_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_size_timeout);
	context.set_deadline(deadline);
	return m_cri->ContainerStats(&context, req, &resp);
}

std::optional<int64_t> cri_interface::get_writable_layer_size(const std::string &container_id)
{
	// Synchronously get the stats response and update the container table.
	// Note that this needs to use the full id.
	runtime::v1alpha2::ContainerStatsResponse resp;
	grpc::Status status = get_container_stats(container_id, resp);

	g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): Status from ContainerStats: (%s)", container_id.c_str(),
			status.error_message().empty() ? "SUCCESS" : status.error_message().c_str());

	if(!status.ok())
	{
		return std::nullopt;
	}

	if(!resp.has_stats())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: stats() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	const auto &resp_stats = resp.stats();

	if(!resp_stats.has_writable_layer())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: writable_layer() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	if(!resp_stats.writable_layer().has_used_bytes())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): Failed to update size: used_bytes() not found",
				container_id.c_str());
		ASSERT(false);
		return std::nullopt;
	}

	return resp_stats.writable_layer().used_bytes().value();
}

bool cri_interface::parse_cri_image(const runtime::v1alpha2::ContainerStatus &status, const google::protobuf::Map<std::string, std::string> &info, sinsp_container_info &container)
{
	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest

	bool have_digest = false;
	const auto &image_ref = status.image_ref();
	std::string image_name = status.image().image();
	bool get_tag_from_image = false;
	auto digest_start = image_ref.find("sha256:");

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): parse_cri_image: image_ref=%s, digest_start=%d",
			container.m_id.c_str(),
			image_ref.c_str(), digest_start);

	switch (digest_start)
	{
	case 0: // sha256:digest
		have_digest = true;
		break;
	case string::npos:
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
		or otherwise was not retrieved. Brute force try each schema we know of for containerd and crio container runtimes. */

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
						jvalue = root["runtimeSpec"]["annotations"]["io.kubernetes.cri-o.Image"];
					}
					if(jvalue.isNull())
					{
						jvalue = root["runtimeSpec"]["annotations"]["io.kubernetes.cri-o.ImageName"];
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

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): parse_cri_image: have_digest=%d image_name=%s",
			container.m_id.c_str(),
			have_digest, image_name.c_str());

	string hostname, port, digest;
	sinsp_utils::split_container_image(image_name,
					   hostname,
					   port,
					   container.m_imagerepo,
					   container.m_imagetag,
					   digest,
					   false);

	if(get_tag_from_image)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): parse_cri_image: tag=%s, pulling tag from %s",
				container.m_id.c_str(),
				container.m_imagetag.c_str(),
				status.image().image().c_str());

		string digest2, repo;
		sinsp_utils::split_container_image(status.image().image(),
						   hostname,
						   port,
						   repo,
						   container.m_imagetag,
						   digest2,
						   false);

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

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): parse_cri_image: repo=%s tag=%s image=%s digest=%s",
			container.m_id.c_str(),
			container.m_imagerepo.c_str(),
			container.m_imagetag.c_str(),
			container.m_image.c_str(),
			container.m_imagedigest.c_str());

	return true;
}

bool cri_interface::parse_cri_mounts(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info &container)
{
	for(const auto &mount : status.mounts())
	{
		const char *propagation;
		switch(mount.propagation())
		{
		case runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE:
			propagation = "private";
			break;
		case runtime::v1alpha2::MountPropagation::PROPAGATION_HOST_TO_CONTAINER:
			propagation = "rslave";
			break;
		case runtime::v1alpha2::MountPropagation::PROPAGATION_BIDIRECTIONAL:
			propagation = "rshared";
			break;
		default:
			propagation = "unknown";
			break;
		}
		container.m_mounts.emplace_back(
			mount.host_path(),
			mount.container_path(),
			"",
			!mount.readonly(),
			propagation);
	}
	return true;

}

bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key)
{
	if(root.isMember(key))
	{
		*out = &root[key];
		return true;
	}
	return false;
}

template<typename... Args>
bool walk_down_json(const Json::Value &root, const Json::Value **out, const std::string &key, Args... args)
{
	if(root.isMember(key))
	{
		return walk_down_json(root[key], out, args...);
	}
	return false;
}

bool set_numeric_32(const Json::Value& dict, const std::string& key, int32_t& val)
{
	if (!dict.isMember(key))
	{
		return false;
	}
	const auto& json_val = dict[key];
	if (!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt();
	return true;
}

bool set_numeric_64(const Json::Value &dict, const std::string &key, int64_t &val)
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

bool cri_interface::parse_cri_env(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *envs;
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

bool cri_interface::parse_cri_json_image(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *image;
	if(!walk_down_json(info, &image, "config", "image", "image") || !image->isString())
	{
		return false;
	}

	auto image_str = image->asString();
	auto pos = image_str.find(':');
	if(pos == string::npos)
	{
		container.m_imageid = move(image_str);
	} else
	{
		container.m_imageid = image_str.substr(pos + 1);
	}

	return true;
}

bool cri_interface::parse_cri_ext_container_info(const Json::Value &info, sinsp_container_info &container)
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
	const Json::Value *privileged;
	// old containerd?
	if(walk_down_json(*linux, &privileged, "security_context", "privileged") && privileged->isBool())
	{
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	// containerd
	if(!priv_found && walk_down_json(info, &privileged, "config", "linux", "security_context", "privileged") && privileged->isBool()) {
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	// cri-o
	if(!priv_found && walk_down_json(info, &privileged, "privileged") && privileged->isBool()) {
		container.m_privileged = privileged->asBool();
		priv_found = true;
	}

	return true;
}

bool cri_interface::parse_cri_user_info(const Json::Value &info, sinsp_container_info &container)
{
	const Json::Value *uid = nullptr;
	if(!walk_down_json(info, &uid, "runtimeSpec", "process", "user", "uid") || !uid->isInt())
	{
		return false;
	}

	container.m_container_user = std::to_string(uid->asInt());
	return true;
}

bool cri_interface::is_pod_sandbox(const std::string &container_id)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	runtime::v1alpha2::PodSandboxStatusResponse resp;
	req.set_pod_sandbox_id(container_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->PodSandboxStatus(&context, req, &resp);

	return status.ok();
}

// TODO: Explore future schema standardizations, https://github.com/falcosecurity/falco/issues/2387
void cri_interface::get_pod_info_cniresult(runtime::v1alpha2::PodSandboxStatusResponse &resp, std::string &cniresult)
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
	/* Lookup approach is brute force "try all schemas" we know of, do not condition by container runtime for possible future "would just work" luck in case other runtimes standardize on one of the current schemas. */

	jvalue = root["cniResult"]["Interfaces"];	/* pod info schema of CT_CONTAINERD runtime. */
	if(!jvalue.isNull())
	{
		/* If applicable remove members / fields not needed for incident response. */
		jvalue.removeMember("lo");
		for (auto& key : jvalue.getMemberNames())
		{
			if (0 == strncmp(key.c_str(), "veth", 4))
			{
				jvalue.removeMember(key);
			} else
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
		jvalue = root["runtimeSpec"]["annotations"]["io.kubernetes.cri-o.CNIResult"];	/* pod info schema of CT_CRIO runtime. Note interfaces names are unknown here. */
		if(!jvalue.isNull())
		{
			cniresult = jvalue.asString();
		}
	}

	if(cniresult[cniresult.size() - 1] == '\n')		/* Make subsequent ETLs nicer w/ minor cleanups if applicable. */
	{
		cniresult.pop_back();
	}

	if (cniresult.size() > MAX_CNIRESULT_LENGTH)	/* Safety upper bound, should never happen. */
	{
		cniresult.resize(MAX_CNIRESULT_LENGTH);
	}
}

void cri_interface::get_pod_sandbox_resp(const std::string &pod_sandbox_id, runtime::v1alpha2::PodSandboxStatusResponse &resp, grpc::Status &status)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	status = m_cri->PodSandboxStatus(&context, req, &resp);
}

uint32_t cri_interface::get_pod_sandbox_ip(runtime::v1alpha2::PodSandboxStatusResponse &resp)
{
	if(pod_uses_host_netns(resp))
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
	} else
	{
		return ip;
	}
}

void cri_interface::get_container_ip(const std::string &container_id, uint32_t &container_ip, std::string &cniresult)
{
	container_ip = 0;
	cniresult = "";
	runtime::v1alpha2::ListContainersRequest req;
	runtime::v1alpha2::ListContainersResponse resp;
	auto filter = req.mutable_filter();
	filter->set_id(container_id);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status lstatus = m_cri->ListContainers(&context, req, &resp);

	switch(resp.containers_size())
	{
		case 0:
			g_logger.format(sinsp_logger::SEV_WARNING, "Container id %s not in list from CRI", container_id.c_str());
			ASSERT(false);
			break;
		case 1: {
			const auto& cri_container = resp.containers(0);
			runtime::v1alpha2::PodSandboxStatusResponse resp_pod;
			grpc::Status status_pod;
			get_pod_sandbox_resp(cri_container.pod_sandbox_id(), resp_pod, status_pod);
			if (status_pod.ok())
			{
				container_ip =  ntohl(get_pod_sandbox_ip(resp_pod));
				get_pod_info_cniresult(resp_pod, cniresult);
			}
		}
		default:
			g_logger.format(sinsp_logger::SEV_WARNING, "Container id %s matches more than once in list from CRI", container_id.c_str());
			ASSERT(false);
			break;
	}
}

std::string cri_interface::get_container_image_id(const std::string &image_ref)
{
	runtime::v1alpha2::ListImagesRequest req;
	runtime::v1alpha2::ListImagesResponse resp;
	auto filter = req.mutable_filter();
	auto spec = filter->mutable_image();
	spec->set_image(image_ref);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = m_cri_image->ListImages(&context, req, &resp);

	switch(resp.images_size())
	{
		case 0:
			g_logger.format(sinsp_logger::SEV_WARNING, "Image ref %s not in list from CRI", image_ref.c_str());
			ASSERT(false);
			break;
		case 1: {
			const auto& image = resp.images(0);
			return image.id();
		}
		default:
			g_logger.format(sinsp_logger::SEV_WARNING, "Image ref %s matches more than once in list from CRI", image_ref.c_str());
			ASSERT(false);
			break;
	}

	return "";
}
}
}
