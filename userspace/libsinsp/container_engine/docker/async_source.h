#pragma once

#include "async_key_value_source.h"
#include "container_info.h"

#include "container_engine/docker/connection.h"
#include "container_engine/docker/lookup_request.h"

namespace libsinsp {
namespace container_engine {

class container_cache_interface;

class docker_async_source : public sysdig::async_key_value_source<docker_lookup_request, sinsp_container_info>
{
public:
	docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, container_cache_interface *cache);
	virtual ~docker_async_source();

	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);
	static void set_query_image_info(bool query_image_info);

protected:
	void run_impl();

private:
	bool parse_docker(const docker_lookup_request& request, sinsp_container_info& container);

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

	container_cache_interface *m_cache;
	docker_connection m_connection;
	static bool m_query_image_info;
};


}
}
