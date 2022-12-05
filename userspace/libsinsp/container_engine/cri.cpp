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

#include "container_engine/cri.h"

#include <sys/stat.h>
#ifdef GRPC_INCLUDE_IS_GRPCPP
#	include <grpcpp/grpcpp.h>
#else
#	include <grpc++/grpc++.h>
#endif
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#include "cgroup_limits.h"
#include "runc.h"
#include "container_engine/mesos.h"
#include <cri.h>
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::cri;
using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace
{
// do the CRI communication asynchronously
bool s_async = true;

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd containerd
	{"/crio-", ""}, // non-systemd cri-o
	{"/cri-containerd-", ".scope"}, // systemd containerd
	{"/crio-", ".scope"}, // systemd cri-o
	{":cri-containerd:", ""}, // containerd without "SystemdCgroup = true"
	{nullptr, nullptr}
};
} // namespace

bool cri_async_source::parse_containerd(const runtime::v1alpha2::ContainerStatusResponse& status, sinsp_container_info &container)
{
	g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s) in parse_containerd", container.m_id.c_str());

	const auto &info_it = status.info().find("info");
	if(info_it == status.info().end())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s) no info property, returning", container.m_id.c_str());
		return false;
	}

	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(info_it->second, root))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s) could not json parse info, returning", container.m_id.c_str());
		ASSERT(false);
		return false;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): will parse info json: %s",
			container.m_id.c_str(),
			info_it->second.c_str());

	m_cri->parse_cri_env(root, container);
	m_cri->parse_cri_json_image(root, container);
	bool ret = m_cri->parse_cri_ext_container_info(root, container);
	m_cri->parse_cri_user_info(root, container);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		container.m_container_ip = ntohl(m_cri->get_pod_sandbox_ip(pod_sandbox_id));
	}

	return ret;
}

bool cri_async_source::parse(const key_type& key, sinsp_container_info& container)
{
	runtime::v1alpha2::ContainerStatusResponse resp;
	grpc::Status status = m_cri->get_container_status(container.m_id, resp);

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): Status from ContainerStatus: (%s)",
			container.m_id.c_str(),
			status.error_message().c_str());

	if(!status.ok())
	{
		if(m_cri->is_pod_sandbox(container.m_id))
		{
			container.m_is_pod_sandbox = true;
			return true;
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): id is neither a container nor a pod sandbox: %s",
				container.m_id.c_str(), status.error_message().c_str());
		return false;
	}

	if(!resp.has_status())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s) no status, returning", container.m_id.c_str());
		ASSERT(false);
		return false;
	}

	const auto &resp_container = resp.status();
	container.m_full_id = resp_container.id();
	container.m_name = resp_container.metadata().name();

	// This is in Nanoseconds(in CRI API). Need to convert it to seconds.
	container.m_created_time = static_cast<int64_t>(resp_container.created_at() / ONE_SECOND_IN_NS );

	for(const auto &pair : resp_container.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_labels[pair.first] = pair.second;
		}
	}

	m_cri->parse_cri_image(resp_container, container);
	m_cri->parse_cri_mounts(resp_container, container);

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

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): after parse_containerd: repo=%s tag=%s image=%s digest=%s",
			container.m_id.c_str(),
			container.m_imagerepo.c_str(),
			container.m_imagetag.c_str(),
			container.m_image.c_str(),
			container.m_imagedigest.c_str());


	if(s_cri_extra_queries)
	{
		if(!container.m_container_ip)
		{
			container.m_container_ip = m_cri->get_container_ip(container.m_id);
		}
		if(container.m_imageid.empty())
		{
			container.m_imageid = m_cri->get_container_image_id(resp_container.image_ref());
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri (%s): after get_container_image_id: repo=%s tag=%s image=%s digest=%s",
					container.m_id.c_str(),
					container.m_imagerepo.c_str(),
					container.m_imagetag.c_str(),
					container.m_image.c_str(),
					container.m_imagedigest.c_str());

		}
	}

	return true;
}

cri::cri(container_cache_interface &cache) : container_engine_base(cache)
{
	if (s_cri_unix_socket_paths.empty())
	{
		// Default value when empty
		s_cri_unix_socket_paths.emplace_back("/run/containerd/containerd.sock");
	}

	// Try all specified unix socket paths
	// NOTE: having multiple container runtimes on the same host is a sporadic case,
	// so we wouldn't make things complex to support that.
	// On the other hand, specifying multiple unix socket paths (and using only the first match)
	// will solve the "same config, multiple hosts" use case.
	for (auto &p : s_cri_unix_socket_paths)
	{
		if(p.empty())
		{
			continue;
		}

		auto cri_path = scap_get_host_root() + p;
		struct stat s = {};
		if(stat(cri_path.c_str(), &s) != 0 || (s.st_mode & S_IFMT) != S_IFSOCK)
		{
			continue;
		}

		m_cri = std::unique_ptr<libsinsp::cri::cri_interface>(new libsinsp::cri::cri_interface(cri_path));
		if(!m_cri->is_ok())
		{
			m_cri.reset(nullptr);
		}
		else
		{
			// Store used unix_socket_path
			s_cri_unix_socket_path = p;
			break;
		}
	}
}

void cri::cleanup()
{
	if(m_async_source)
	{
		m_async_source->quiesce();
	}
	s_cri_extra_queries = true;
}

void cri::set_cri_socket_path(const std::string& path)
{
	s_cri_unix_socket_paths.clear();
	add_cri_socket_path(path);
}

void cri::add_cri_socket_path(const std::string& path)
{
	s_cri_unix_socket_paths.push_back(path);
}

void cri::set_cri_timeout(int64_t timeout_ms)
{
	s_cri_timeout = timeout_ms;
}

void cri::set_extra_queries(bool extra_queries) {
	s_cri_extra_queries = extra_queries;
}

void cri::set_async(bool async)
{
	s_async = async;
}

bool cri::resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info)
{
	container_cache_interface *cache = &container_cache();
	std::string container_id, cgroup;

	if(!matches_runc_cgroups(tinfo, CRI_CGROUP_LAYOUT, container_id, cgroup))
	{
		return false;
	}
	tinfo->m_container_id = container_id;

	if(!m_cri)
	{
		// This isn't an error in the case where the
		// configured unix domain socket doesn't exist. In
		// that case, s_cri isn't initialized at all. Hence,
		// the DEBUG.
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Could not parse cri (no s_cri object)",
				container_id.c_str());
		return false;
	}

	if(!cache->should_lookup(container_id, m_cri->get_cri_runtime_type()))
	{
		return true;
	}

	auto container = sinsp_container_info();
	container.m_id = container_id;
	container.m_type = m_cri->get_cri_runtime_type();
	if (mesos::set_mesos_task_id(container, tinfo))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s) Mesos CRI container, Mesos task ID: [%s]",
				container_id.c_str(), container.m_mesos_task_id.c_str());
	}

	if (query_os_for_missing_info)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Performing lookup",
				container_id.c_str());

		container.set_lookup_status(sinsp_container_lookup::state::SUCCESSFUL);
		libsinsp::cgroup_limits::cgroup_limits_key key(
			container.m_id,
			tinfo->get_cgroup("cpu"),
			tinfo->get_cgroup("memory"),
			tinfo->get_cgroup("cpuset"));

		if(!m_async_source)
		{
			uint64_t max_wait_ms = 10000;
			auto async_source = new cri_async_source(cache, m_cri.get(), max_wait_ms);
			m_async_source = std::unique_ptr<cri_async_source>(async_source);
		}

		cache->set_lookup_status(container_id, m_cri->get_cri_runtime_type(), sinsp_container_lookup::state::STARTED);

		sinsp_container_info result;

		bool done;
		const bool async = s_async && cache->async_allowed();
		if(async)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri_async (%s): Starting asynchronous lookup",
					container_id.c_str());
			done = m_async_source->lookup(key, result);
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri_async (%s): Starting synchronous lookup",
					container_id.c_str());
			done = m_async_source->lookup_sync(key, result);
		}

		if (done)
		{
			// if a previous lookup call already found the metadata, process it now
			m_async_source->source_callback(key, result);

			if(async)
			{
				// This should *never* happen, in async mode as ttl is 0 (never wait)
				g_logger.format(sinsp_logger::SEV_ERROR,
						"cri_async (%s): Unexpected immediate return from cri_async lookup",
						container_id.c_str());

			}
		}
	}
	else
	{
		cache->notify_new_container(container, tinfo);
	}
	return true;
}

void cri::update_with_size(const std::string& container_id)
{
	sinsp_container_info::ptr_t existing = container_cache().get_container(container_id);
	if(!existing)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"cri (%s): Failed to locate existing container data",
				container_id.c_str());
		ASSERT(false);
		return;
	}

	// Synchronously get the stats response and update the container table.
	// Note that this needs to use the full id.
	runtime::v1alpha2::ContainerStatsResponse resp;
	grpc::Status status = m_cri->get_container_stats(existing->m_full_id, resp);

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): full id (%s): Status from ContainerStats: (%s)",
			container_id.c_str(),
			existing->m_full_id.c_str(),
			status.error_message().empty() ? "SUCCESS" : status.error_message().c_str());

	if(!status.ok())
	{
		return;
	}

	if(!resp.has_stats())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Failed to update size: stats() not found",
				container_id.c_str());
		ASSERT(false);
		return;
	}

	const auto& resp_stats = resp.stats();

	if(!resp_stats.has_writable_layer())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Failed to update size: writable_layer() not found",
				container_id.c_str());
		ASSERT(false);
		return;
	}

	if(!resp_stats.writable_layer().has_used_bytes())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Failed to update size: used_bytes() not found",
				container_id.c_str());
		ASSERT(false);
		return;
	}

	// Make a mutable copy of the existing container_info
	shared_ptr<sinsp_container_info> updated(std::make_shared<sinsp_container_info>(*existing));
	updated->m_size_rw_bytes = resp_stats.writable_layer().used_bytes().value();

	if(existing->m_size_rw_bytes == updated->m_size_rw_bytes)
	{
		// no data has changed
		return;
	}

	container_cache().replace_container(updated);
}


