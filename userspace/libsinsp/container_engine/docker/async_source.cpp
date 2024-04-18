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
#include <libsinsp/container_engine/docker/async_source.h>
#include <libsinsp/cgroup_list_counter.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/container.h>
#include <libsinsp/utils.h>
#include <unordered_set>

using namespace libsinsp::container_engine;

bool docker_async_source::m_query_image_info = true;

docker_async_source::docker_async_source(uint64_t max_wait_ms,
					 uint64_t ttl_ms,
					 container_cache_interface *cache)
	: container_async_source(max_wait_ms, ttl_ms, cache)
{
}

docker_async_source::~docker_async_source()
{
	this->stop();
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async: Source destructor");
}

bool docker_async_source::get_k8s_pod_spec(const Json::Value &config_obj,
					   Json::Value &spec)
{
	std::string cfg_str;
	Json::Reader reader;
	std::string k8s_label = "annotation.kubectl.kubernetes.io/last-applied-configuration";

	if(config_obj.isNull() ||
	   !config_obj.isMember("Labels") ||
	   !config_obj["Labels"].isMember(k8s_label))
	{
		return false;
	}

	// The pod spec is stored as a stringified json label on the container
	cfg_str = config_obj["Labels"][k8s_label].asString();

	if(cfg_str == "")
	{
		return false;
	}

	Json::Value cfg;
	if(!reader.parse(cfg_str.c_str(), cfg))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse pod config '%s'", cfg_str.c_str());
		return false;
	}

	if(!cfg.isMember("spec") ||
	   !cfg["spec"].isMember("containers") ||
	   !cfg["spec"]["containers"].isArray())
	{
		return false;
	}

	// XXX/mstemm how will this work with init containers?
	spec = cfg["spec"]["containers"][0];

	return true;
}

std::string docker_async_source::normalize_arg(const std::string &arg)
{
	std::string ret = arg;

	if(ret.empty())
	{
		return ret;
	}

	// Remove pairs of leading/trailing " or ' chars, if present
	while(ret.front() == '"' || ret.front() == '\'')
	{
		if(ret.back() == ret.front())
		{
			ret.pop_back();
			ret.erase(0, 1);
		}
	}

	return ret;
}

void docker_async_source::parse_healthcheck(const Json::Value &healthcheck_obj,
					    sinsp_container_info &container)
{
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker (%s): Trying to parse healthcheck from %s",
			container.m_id.c_str(), Json::FastWriter().write(healthcheck_obj).c_str());

	if(healthcheck_obj.isNull())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s (No Healthcheck property)",
				Json::FastWriter().write(healthcheck_obj).c_str());

		return;
	}

	if(!healthcheck_obj.isMember("Test"))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s (Healthcheck does not have Test property)",
				Json::FastWriter().write(healthcheck_obj).c_str());

		return;
	}

	const Json::Value &test_obj = healthcheck_obj["Test"];

	if(!test_obj.isArray())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s (Healthcheck Test property is not array)",
				Json::FastWriter().write(healthcheck_obj).c_str());
		return;
	}

	if(test_obj.size() == 1)
	{
		if(test_obj[0].asString() != "NONE")
		{
			libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s (Expected NONE for single-element Test array)",
					Json::FastWriter().write(healthcheck_obj).c_str());
		}
		return;
	}

	if(test_obj[0].asString() == "CMD")
	{
		std::string exe = normalize_arg(test_obj[1].asString());
		std::vector<std::string> args;

		for(uint32_t i = 2; i < test_obj.size(); i++)
		{
			args.push_back(normalize_arg(test_obj[i].asString()));
		}

		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker (%s): Setting PT_HEALTHCHECK exe=%s nargs=%d",
				container.m_id.c_str(), exe.c_str(), args.size());

		container.m_health_probes.emplace_back(sinsp_container_info::container_health_probe::PT_HEALTHCHECK,
						       std::move(exe),
						       std::move(args));
	}
	else if(test_obj[0].asString() == "CMD-SHELL")
	{
		std::string exe = "/bin/sh";
		std::vector<std::string> args;

		args.push_back("-c");
		args.push_back(test_obj[1].asString());

		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker (%s): Setting PT_HEALTHCHECK exe=%s nargs=%d",
				container.m_id.c_str(), exe.c_str(), args.size());

		container.m_health_probes.emplace_back(sinsp_container_info::container_health_probe::PT_HEALTHCHECK,
						       std::move(exe),
						       std::move(args));
	}
	else
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s (Expected CMD/CMD-SHELL for multi-element Test array)",
				Json::FastWriter().write(healthcheck_obj).c_str());
		return;
	}
}

bool docker_async_source::parse_liveness_readiness_probe(const Json::Value &probe_obj,
							 sinsp_container_info::container_health_probe::probe_type ptype,
							 sinsp_container_info &container)
{
	if(probe_obj.isNull() ||
	   !probe_obj.isMember("exec") ||
	   !probe_obj["exec"].isMember("command"))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_WARNING, "Could not parse liveness/readiness probe from %s",
				Json::FastWriter().write(probe_obj).c_str());
		return false;
	}

	const Json::Value command_obj = probe_obj["exec"]["command"];

	if(!command_obj.isNull() && command_obj.isArray())
	{
		std::string exe;
		std::vector<std::string> args;

		exe = normalize_arg(command_obj[0].asString());
		for(uint32_t i = 1; i < command_obj.size(); i++)
		{
			args.push_back(normalize_arg(command_obj[i].asString()));
		}

		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker (%s): Setting %s exe=%s nargs=%d",
				container.m_id.c_str(),
				sinsp_container_info::container_health_probe::probe_type_names[ptype].c_str(),
				exe.c_str(), args.size());

		container.m_health_probes.emplace_back(ptype, std::move(exe), std::move(args));
	}

	return true;
}

bool docker_async_source::get_sandbox_liveness_readiness_probes(const Json::Value &config_obj,
								sinsp_container_info &container)
{
	std::string sandbox_container_id;
	std::string sandbox_label = "io.kubernetes.sandbox.id";

	if(config_obj.isNull() ||
	   !config_obj.isMember("Labels") ||
	   !config_obj["Labels"].isMember(sandbox_label))
	{
		SINSP_DEBUG("docker (%s): No sandbox label found, not copying liveness/readiness probes",
			    container.m_id.c_str());
		return false;
	}

	sandbox_container_id = config_obj["Labels"][sandbox_label].asString();

	if(sandbox_container_id.size() > 12)
	{
		sandbox_container_id.resize(12);
	}

	sinsp_container_info::ptr_t sandbox_container = m_cache->get_container(sandbox_container_id);

	if(!sandbox_container)
	{
		SINSP_DEBUG("docker (%s): Sandbox container %s doesn't exist, not copying liveness/readiness probes",
			    container.m_id.c_str(), sandbox_container_id.c_str());
		return false;
	}

	if(sandbox_container->m_health_probes.size() == 0)
	{
		SINSP_DEBUG("docker (%s): Sandbox container %s has no liveness/readiness probes, not copying",
			    container.m_id.c_str(), sandbox_container_id.c_str());
		return false;
	}

	SINSP_DEBUG("docker (%s): Copying liveness/readiness probes from sandbox container %s",
		    container.m_id.c_str(), sandbox_container_id.c_str());
	container.m_health_probes = sandbox_container->m_health_probes;

	return true;
}

void docker_async_source::parse_health_probes(const Json::Value &config_obj,
					      sinsp_container_info &container)
{
	Json::Value spec;
	bool liveness_readiness_added = false;

	// When parsing the full container json for live containers, a label contains stringified json that
	// contains the probes.
	if (get_k8s_pod_spec(config_obj, spec))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker (%s): Parsing liveness/readiness probes from pod spec",
				container.m_id.c_str());

		if(spec.isMember("livenessProbe"))
		{
			if(parse_liveness_readiness_probe(spec["livenessProbe"],
							  sinsp_container_info::container_health_probe::PT_LIVENESS_PROBE,
							  container))
			{
				liveness_readiness_added = true;
			}
		}
		else if(spec.isMember("readinessProbe"))
		{
			if(parse_liveness_readiness_probe(spec["readinessProbe"],
							  sinsp_container_info::container_health_probe::PT_READINESS_PROBE,
							  container))
			{
				liveness_readiness_added = true;
			}
		}
	}
		// Otherwise, try to copy the liveness/readiness probe from the sandbox container, if it exists.
	else if (get_sandbox_liveness_readiness_probes(config_obj, container))
	{
		liveness_readiness_added = true;
	}
	else
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker (%s): No liveness/readiness probes found",
				container.m_id.c_str());
	}

	// To avoid any confusion about containers that both refer to
	// a healthcheck and liveness/readiness probe, we only
	// consider a healthcheck if no liveness/readiness was added.
	if(!liveness_readiness_added && config_obj.isMember("Healthcheck"))
	{
		parse_healthcheck(config_obj["Healthcheck"], container);
	}
}

void docker_async_source::set_query_image_info(bool query_image_info)
{
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async: Setting query_image_info=%s",
			(query_image_info ? "true" : "false"));

	m_query_image_info = query_image_info;
}

void docker_async_source::fetch_image_info(const docker_lookup_request& request, sinsp_container_info& container)
{
	Json::Reader reader;

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s) image (%s): Fetching image info",
			request.container_id.c_str(),
			container.m_imageid.c_str());

	std::string img_json;
	std::string url = "/images/" + container.m_imageid + "/json?digests=1";

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async url: %s",
			url.c_str());

	if(m_connection.get_docker(request, url, img_json) != docker_connection::RESP_OK)
	{
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
				"docker_async (%s) image (%s): Could not fetch image info",
				request.container_id.c_str(),
				container.m_imageid.c_str());
		return;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s) image (%s): Image info fetch returned \"%s\"",
			request.container_id.c_str(),
			container.m_imageid.c_str(),
			img_json.c_str());

	Json::Value img_root;
	if(!reader.parse(img_json, img_root))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
				"docker_async (%s) image (%s): Could not parse json image info \"%s\"",
				request.container_id.c_str(),
				container.m_imageid.c_str(),
				img_json.c_str());
		return;
	}

	parse_image_info(container, img_root);
}

void docker_async_source::fetch_image_info_from_list(const docker_lookup_request& request, sinsp_container_info& container)
{
	Json::Reader reader;

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Fetching image list",
			request.container_id.c_str());

	std::string img_json;
	std::string url = "/images/json?digests=1";

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async url: %s",
			url.c_str());

	/*
	* Apparently at least the RHEL9 version of podman doesn't properly respond
	* to /images/json?digests=1, while it does return all the info we need
	* without the query parameter.
	*
	* Since ?digests=1 is defined in the Docker API, prefer this as the default,
	* but also try the podman variant.
	* 
	* Note: the API does not return an HTTP error but instead an empty 200 response,
	* so checking the HTTP status is not enough.
	*/
	if(m_connection.get_docker(request, url, img_json) != docker_connection::RESP_OK
		|| img_json.empty())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
				"docker_async (%s): Could not fetch image list; trying without ?digests=1",
				request.container_id.c_str());

		std::string url = "/images/json";

		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async url: %s",
				url.c_str());

		if(m_connection.get_docker(request, url, img_json) != docker_connection::RESP_OK
			|| img_json.empty())
		{
			libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
					"docker_async (%s): Could not fetch image list",
					request.container_id.c_str());

			return;
		}
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Image list fetch returned \"%s\"",
			request.container_id.c_str(),
			img_json.c_str());

	Json::Value img_root;
	if(!reader.parse(img_json, img_root))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
				"docker_async (%s): Could not parse json image list \"%s\"",
				request.container_id.c_str(),
				img_json.c_str());
		return;
	}

	const std::string match_name = container.m_imagerepo + ':' + container.m_imagetag;
	for(const auto& img : img_root)
	{
		// the "Names" field is podman specific. we could parse repotags
		// twice but this is less effort and we only call this function
		// for podman anyway
		const auto& names = img["Names"];
		if(!names.isArray())
		{
			return;
		}

		for(const auto& name : names)
		{
			if(name == match_name)
			{
				std::string imgstr = img["Id"].asString();
				size_t cpos = imgstr.find(':');
				if(cpos != std::string::npos)
				{
					imgstr = imgstr.substr(cpos + 1);
				}
				container.m_imageid = std::move(imgstr);

				parse_image_info(container, img);
				return;
			}
		}
	}
}

void docker_async_source::parse_image_info(sinsp_container_info& container, const Json::Value& img)
{
	const auto& podman_digest = img["Digest"];
	if(podman_digest.isString())
	{
		// img["Digest"] if present is the digest in the form we need it
		// e.g. "sha256:b6a9fc3535388a6fc04f3bdb83fb4d9d0b4ffd85e7609a6ff2f0f731427823e3"
		// so just use it directly
		container.m_imagedigest = podman_digest.asString();
	}
	else
	{
		// img_root["RepoDigests"] contains only digests for images pulled from registries.
		// If an image gets retagged and is never pushed to any registry, we will not find
		// that entry in container.m_imagerepo. Also, for locally built images we have the
		// same issue. This leads to container.m_imagedigest being empty as well.
		//
		// Each individual digest looks like e.g.
		// "docker.io/library/redis@sha256:b6a9fc3535388a6fc04f3bdb83fb4d9d0b4ffd85e7609a6ff2f0f731427823e3"
		// so we need to split it at the `@` (the part before is the repo,
		// the part after is the digest)
		std::unordered_set<std::string> imageDigestSet;
		for(const auto& rdig : img["RepoDigests"])
		{
			if(rdig.isString())
			{
				std::string repodigest = rdig.asString();
				std::string digest = repodigest.substr(repodigest.find('@')+1);
				imageDigestSet.insert(digest);
				if(container.m_imagerepo.empty())
				{
					container.m_imagerepo = repodigest.substr(0, repodigest.find('@'));
				}
				if(repodigest.find(container.m_imagerepo) != std::string::npos)
				{
					container.m_imagedigest = digest;
					break;
				}
			}
		}
		// fix image digest for locally tagged images or multiple repo digests.
		// Case 1: One repo digest with many tags.
		// Case 2: Many repo digests with the same digest value.
		if(container.m_imagedigest.empty() && imageDigestSet.size() == 1) {
			container.m_imagedigest = *imageDigestSet.begin();
		}
	}
	for(const auto& rtag : img["RepoTags"])
	{
		if(rtag.isString())
		{
			std::string repotag = rtag.asString();
			if(container.m_imagerepo.empty())
			{
				container.m_imagerepo = repotag.substr(0, repotag.rfind(':'));
			}
			if(repotag.find(container.m_imagerepo) != std::string::npos)
			{
				container.m_imagetag = repotag.substr(repotag.rfind(':')+1);
				break;
			}
		}
	}
}

void docker_async_source::get_image_info(const docker_lookup_request& request, sinsp_container_info& container, const Json::Value& root)
{
	container.m_image = root["Config"]["Image"].asString();

	// podman has the image *name*, not the *id* in the Image field
	// detect that with the presence of '/' in the field
	std::string imgstr = root["Image"].asString();
	if(imgstr.find('/') == std::string::npos)
	{
		// no '/' in the Image field, assume it's a Docker image id
		size_t cpos = imgstr.find(':');
		if(cpos != std::string::npos)
		{
			container.m_imageid = imgstr.substr(cpos + 1);
		}

		// containers can be spawned using just the imageID as image name,
		// with or without the hash prefix (e.g. sha256:)
		//
		// e.g. an image with the id `sha256:ddcca4b8a6f0367b5de2764dfe76b0a4bfa6d75237932185923705da47004347`
		// can be used to run a container as:
		// - docker run sha256:ddcca4b8a6f0367b5de2764dfe76b0a4bfa6d75237932185923705da47004347
		// - docker run ddcca4b8a6f0367b5de2764dfe76b0a4bfa6d75237932185923705da47004347
		// - docker run sha256:ddcca4
		// - docker run ddcca4
		//
		// in all these cases we need to determine the image repo/tag
		// via the API (in `fetch_image_info()`)
		//
		// otherwise we assume the name passed to `docker run`
		// (available in container.m_image) is the repo name like `redis`
		// and use that to determine the name and tag
		bool no_name = sinsp_utils::startswith(container.m_imageid, container.m_image) ||
				   sinsp_utils::startswith(imgstr, container.m_image);

		if(!no_name || !m_query_image_info)
		{
			std::string hostname, port;
			sinsp_utils::split_container_image(container.m_image,
							   hostname,
							   port,
							   container.m_imagerepo,
							   container.m_imagetag,
							   container.m_imagedigest,
							   false);
		}

		if(m_query_image_info && !container.m_imageid.empty() &&
		   (no_name || container.m_imagedigest.empty() || container.m_imagetag.empty()))
		{
			fetch_image_info(request, container);
		}

		if(container.m_imagetag.empty())
		{
			container.m_imagetag = "latest";
		}
	}
	else
	{
		// a '/' is present in the Image field. Parse it into parts
		std::string hostname, port;
		sinsp_utils::split_container_image(imgstr,
						   hostname,
						   port,
						   container.m_imagerepo,
						   container.m_imagetag,
						   container.m_imagedigest,
						   false);

		// we need the tag set in the call to `fetch_image_from_list`
		// so set it here instead of after the if/else
		if(container.m_imagetag.empty())
		{
			container.m_imagetag = "latest";
		}

		// we don't have the image id so we need to list all images
		// and find the matching one by comparing the repo names
		if(m_query_image_info)
		{
			fetch_image_info_from_list(request, container);
		}
	}

}
void docker_async_source::parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts)
{
	if(!mnt_obj.isNull() && mnt_obj.isArray())
	{
		for(uint32_t i=0; i<mnt_obj.size(); i++)
		{
			const Json::Value &mount = mnt_obj[i];
			mounts.emplace_back(mount["Source"], mount["Destination"],
					    mount["Mode"], mount["RW"],
					    mount["Propagation"]);
		}
	}
}


bool docker_async_source::parse(const docker_lookup_request& request, sinsp_container_info& container)
{
	std::string json;

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Looking up info for container via socket %s",
			request.container_id.c_str(), request.docker_socket.c_str());

	std::string api_request = "/containers/" + request.container_id + "/json";
	if(request.request_rw_size)
	{
		api_request += "?size=true";
	}

	docker_connection::docker_response resp = m_connection.get_docker(request, api_request, json);

	switch(resp) {
	case docker_connection::docker_response::RESP_BAD_REQUEST:
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Initial url fetch failed, trying w/o api version",
				request.container_id.c_str());

		m_connection.set_api_version("");
		json = "";
		resp = m_connection.get_docker(request, "/containers/" + request.container_id + "/json", json);
		if (resp == docker_connection::docker_response::RESP_OK)
		{
			break;
		}
		/* FALLTHRU */
	case docker_connection::docker_response::RESP_ERROR:
	case docker_connection::docker_response::RESP_TIMEOUT:
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Url fetch failed, returning false",
				request.container_id.c_str());
		return false;

	case docker_connection::docker_response::RESP_OK:
		break;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): Parsing containers response \"%s\"",
			request.container_id.c_str(),
			json.c_str());

	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(json, root);
	if(!parsingSuccessful)
	{
		libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
				"docker_async (%s): Could not parse json \"%s\", returning false",
				request.container_id.c_str(),
				json.c_str());

		ASSERT(false);
		return false;
	}
	
	get_image_info(request, container, root);

	const Json::Value& config_obj = root["Config"];
	const Json::Value& user = config_obj["User"];
	if(!user.isNull())
	{
		container.m_container_user = user.asString();
	}

	parse_health_probes(config_obj, container);

	container.m_full_id = root["Id"].asString();
	container.m_name = root["Name"].asString();
	// k8s Docker container names could have '/' as the first character.
	if(!container.m_name.empty() && container.m_name[0] == '/')
	{
		container.m_name = container.m_name.substr(1);
	}
	if(container.m_name.find("k8s_POD") == 0)
	{
		container.m_is_pod_sandbox = true;
	}

	// Get the created time - this will be string format i.e. "%Y-%m-%dT%H:%M:%SZ"
	// Convert it to seconds. This can be done with get_epoc_utc_seconds()
	container.m_created_time = static_cast<int64_t>(get_epoch_utc_seconds(root["Created"].asString()));

	const Json::Value& net_obj = root["NetworkSettings"];

	std::string ip = net_obj["IPAddress"].asString();

	if(ip.empty())
	{
		const Json::Value& hconfig_obj = root["HostConfig"];
		std::string net_mode = hconfig_obj["NetworkMode"].asString();

		if(strncmp(net_mode.c_str(), "container:", strlen("container:")) == 0)
		{
			std::string secondary_container_id = net_mode.substr(net_mode.find(":") + 1);

			sinsp_container_info pcnt;
			pcnt.m_id = secondary_container_id;

			// This is a *blocking* fetch of the
			// secondary container, but we're in a
			// separate thread so this is ok.
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s), secondary (%s): Doing blocking fetch of secondary container",
					request.container_id.c_str(),
					secondary_container_id.c_str());

			if(parse(docker_lookup_request(secondary_container_id,
						       request.docker_socket,
						       request.container_type,
						       request.uid,
						       false /*don't request size since we just need the IP*/),
				 pcnt))
			{
				libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
						"docker_async (%s), secondary (%s): Secondary fetch successful",
						request.container_id.c_str(),
						secondary_container_id.c_str());
				container.m_container_ip = pcnt.m_container_ip;
			}
			else
			{
				libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
						"docker_async (%s), secondary (%s): Secondary fetch failed",
						request.container_id.c_str(),
						secondary_container_id.c_str());
			}
		}
	}
	else
	{
		if(inet_pton(AF_INET, ip.c_str(), &container.m_container_ip) == -1)
		{
			ASSERT(false);
		}
		container.m_container_ip = ntohl(container.m_container_ip);
	}

	std::vector<std::string> ports = net_obj["Ports"].getMemberNames();
	for(std::vector<std::string>::const_iterator it = ports.begin(); it != ports.end(); ++it)
	{
		size_t tcp_pos = it->find("/tcp");
		if(tcp_pos == std::string::npos)
		{
			continue;
		}

		uint16_t container_port = atoi(it->c_str());

		const Json::Value& v = net_obj["Ports"][*it];
		if(v.isArray())
		{
			for(uint32_t j = 0; j < v.size(); ++j)
			{
				sinsp_container_info::container_port_mapping port_mapping;

				ip = v[j]["HostIp"].asString();
				std::string port = v[j]["HostPort"].asString();

				if(inet_pton(AF_INET, ip.c_str(), &port_mapping.m_host_ip) == -1)
				{
					ASSERT(false);
					continue;
				}
				port_mapping.m_host_ip = ntohl(port_mapping.m_host_ip);

				port_mapping.m_container_port = container_port;
				port_mapping.m_host_port = atoi(port.c_str());
				container.m_port_mappings.push_back(port_mapping);
			}
		}
	}

	std::vector<std::string> labels = config_obj["Labels"].getMemberNames();
	for(std::vector<std::string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
	{
		std::string val = config_obj["Labels"][*it].asString();
		if(val.length() <= sinsp_container_info::m_container_label_max_length ) {
			container.m_labels[*it] = val;
		}
	}

	if(request.container_type == sinsp_container_type::CT_PODMAN)
	{
		if(request.uid == 0)
		{
			container.m_labels.erase("podman_owner_uid");
		}
		else
		{
			container.m_labels["podman_owner_uid"] = std::to_string(request.uid);
		}
	}

	const Json::Value& env_vars = config_obj["Env"];

	for(const auto& env_var : env_vars)
	{
		if(env_var.isString())
		{
			container.m_env.emplace_back(env_var.asString());
		}
	}

	const auto& host_config_obj = root["HostConfig"];
	container.m_memory_limit = host_config_obj["Memory"].asInt64();
	container.m_swap_limit = host_config_obj["MemorySwap"].asInt64();
	const auto cpu_shares = host_config_obj["CpuShares"].asInt64();
	if(cpu_shares > 0)
	{
		container.m_cpu_shares = cpu_shares;
	}

	/**
	 * 2 separate docker APIs use CFS CPU scheduler to constrain container CPU usage
	 * Reference: https://docs.docker.com/engine/reference/run/
	 * 1) docker run --cpus=<Number of CPUS>
	 *    <Number of CPUs> is converted into a cfs_cpu_quota value for the default cfs_cpu_period=100000
	 *    cfs_cpu_period cannot be changed with this API
	 *    For example, if <Number of CPUs>=0.5, cfs_cpu_quota=50000 and cfs_cpu_period=100000
	 * 2) docker run --cpu-quota=<quota> --cpu-period=<period>
	 *    CFS quota and/or period can be set directly. The default period is 100000 and default quota
	 *    is 0 (which translates to unconstrained)
	 *    For example, if <quota>=12345 and <period>=67890, then cfs_cpu_quota=12345 and cfs_cpu_period=67890
	 * These 2 APIs are mutually exclusive: docker throws an error if an attempt is made to use --cpus in combination
	 * with either --cpu-quota or --cpu-period
	 *
	 * docker_response json output:
	 * 1) When --cpus is used, the value is returned as NanoCpus; both CpuQuota and CpuPeriod are 0
	 *    Since cfs_cpu_period=100000=10^5 and 10^9 NanoCpus is 1 CPU, which translates to cfs_cpu_quota=100000=10^5,
	 *    we need to divide NanoCpus by 10^4=10000 to convert NanoCpus into cfs_cpu_quota
	 *
	 * 2) When --cpu-quota and/or --cpu-period are used, the corresponding values are returned; NanoCpus is 0
	 */
	container.m_cpu_quota = std::max(host_config_obj["CpuQuota"].asInt64(), host_config_obj["NanoCpus"].asInt64()/10000);
	const auto cpu_period = host_config_obj["CpuPeriod"].asInt64();
	if(cpu_period > 0)
	{
		container.m_cpu_period = cpu_period;
	}
	const auto cpuset_cpus = host_config_obj["CpusetCpus"].asString();
	if (!cpuset_cpus.empty())
	{
		libsinsp::cgroup_list_counter counter;
		container.m_cpuset_cpu_count = counter(cpuset_cpus.c_str());
	}
	const Json::Value& privileged = host_config_obj["Privileged"];
	if(!privileged.isNull() && privileged.isBool())
	{
		container.m_privileged = privileged.asBool();
	}

	parse_json_mounts(root["Mounts"], container.m_mounts);

	container.m_size_rw_bytes = root["SizeRw"].asInt64();

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"docker_async (%s): parse returning true",
			request.container_id.c_str());
	return true;
}

