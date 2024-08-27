#pragma once

#include <libsinsp/container_info.h>

#include <libsinsp/container_engine/container_async_source.h>
#include <libsinsp/container_engine/docker/connection.h>
#include <libsinsp/container_engine/docker/lookup_request.h>

namespace libsinsp {
namespace container_engine {

class container_cache_interface;

class docker_async_source : public container_async_source<docker_lookup_request>
{
	using key_type = docker_lookup_request;

public:
	docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, container_cache_interface *cache);
	virtual ~docker_async_source();

	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);
	static void set_query_image_info(bool query_image_info);

private:
	bool parse(const docker_lookup_request& key, sinsp_container_info& container) override;

	const char* name() const override { return "docker"; };

	sinsp_container_type container_type(const key_type& key) const override
	{
		return key.container_type;
	}
	std::string container_id(const key_type& key) const override
	{
		return key.container_id;
	}

	// Look for a pod specification in this container's labels and
	// if found set spec to the pod spec.
	bool get_k8s_pod_spec(const Json::Value &config_obj,
			      Json::Value &spec);

	std::string normalize_arg(const std::string &arg);

	// Parse a healthcheck out of the provided healthcheck object,
	// updating the container info with any healthcheck found.
	void parse_healthcheck(const Json::Value &healthcheck_obj,
			       sinsp_container_info &container);

	// Parse either a readiness or liveness probe out of the
	// provided object, updating the container info with any probe
	// found. Returns true if the healthcheck/livenesss/readiness
	// probe info was found and could be parsed.
	bool parse_liveness_readiness_probe(const Json::Value &probe_obj,
					    sinsp_container_info::container_health_probe::probe_type ptype,
					    sinsp_container_info &container);

	// See if this config has a io.kubernetes.sandbox.id label
	// referring to a different container. (NOTE: this is not the
	// same as docker's sandbox id, which refers to networks.) If
	// it does, try to copy the health checks from that container
	// to the provided container_info pointer. Returns true if a
	// sandbox container id was found, the corresponding container
	// was found, and if the health checks could be copied from
	// that container.
	bool get_sandbox_liveness_readiness_probes(const Json::Value &config_obj,
						   sinsp_container_info &container);

	// Parse all healthchecks/liveness probes/readiness probes out
	// of the provided object, updating the container info as required.
	void parse_health_probes(const Json::Value &config_obj,
				 sinsp_container_info &container);

	// Analyze the container JSON response and get the details about
	// the image, possibly executing extra API calls
	void get_image_info(const docker_lookup_request& request, sinsp_container_info& container, const Json::Value& root);

	// Given the image info (either the result of /images/<image-id>/json,
	// or one of the items from the result of /images/json), find
	// the image digest, repo and repo tag
	static void parse_image_info(sinsp_container_info& container, const Json::Value& img);

	// Fetch the image info for the current container's m_imageid
	void fetch_image_info(const docker_lookup_request& request, sinsp_container_info& container);

	// Podman reports image repository/tag instead of the image id,
	// so to fetch the image digest we need to list all the images,
	// find one with matching repository/tag and get the digest from there
	void fetch_image_info_from_list(const docker_lookup_request& request, sinsp_container_info& container);

	docker_connection m_connection;
	static bool m_query_image_info;
};


}
}
