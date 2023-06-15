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

#include "runc.h"
#include "container_engine/mesos.h"

#include "cri.hpp"

#include <memory>
#include "sinsp.h"
#include "sinsp_int.h"

using namespace std;
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


cri::cri(container_cache_interface &cache) : container_engine_base(cache)
{
	if (s_cri_unix_socket_paths.empty())
	{
		// containerd as primary default value when empty
		s_cri_unix_socket_paths.emplace_back("/run/containerd/containerd.sock");
		// crio-o as secondary default value when empty
		s_cri_unix_socket_paths.emplace_back("/run/crio/crio.sock");
		// k3s containerd as third option when empty
		s_cri_unix_socket_paths.emplace_back("/run/k3s/containerd/containerd.sock");
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

		m_cri = std::make_unique<libsinsp::cri::cri_interface_v1alpha2>(cri_path);
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
			// Each lookup attempt involves two CRI API calls (see
			// `cri_async_source::parse`), each one having a default timeout
			// of 1000ms (`cri::set_cri_timeout`).
			// On top of that, there's an exponential backoff with 125ms start
			// time (`sinsp_container_lookup::delay`) with a maximum of 5
			// retries.
			// The maximum time to complete all attempts can be then evaluated
			// with the following formula:
			//
			// max_wait_ms = (2 * s_cri_timeout) * n + (125 * (2^n - 1))
			//
			// Note that this excludes the time for the last 2 CRI API calls
			// that will be performed anyway, even if the TTL expires.
			//
			// With n=5 the result is 13875ms, we keep some margin as we are
			// taking into account elapsed time.
			uint64_t max_wait_ms = 20000;
			auto async_source = new cri_async_source(cache, m_cri.get(), max_wait_ms);
			m_async_source = std::unique_ptr<cri_async_source>(async_source);
		}

		cache->set_lookup_status(container_id, m_cri->get_cri_runtime_type(), sinsp_container_lookup::state::STARTED);

		// sinsp_container_lookup is set-up to perform 5 retries at most, with
		// an exponential backoff with 2000 ms of maximum wait time.
		sinsp_container_info result(sinsp_container_lookup(5, 2000));

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

	std::optional<int64_t> writable_layer_size = m_cri->get_writable_layer_size(existing->m_full_id);

	if(!writable_layer_size.has_value())
	{
		return;
	}

	// Make a mutable copy of the existing container_info
	shared_ptr<sinsp_container_info> updated(std::make_shared<sinsp_container_info>(*existing));
	updated->m_size_rw_bytes = *writable_layer_size;

	if(existing->m_size_rw_bytes == updated->m_size_rw_bytes)
	{
		// no data has changed
		return;
	}

	container_cache().replace_container(updated);
}

bool cri_async_source::parse(const cri_async_source::key_type &key, sinsp_container_info &container)
{
	return m_cri->parse(key, container);
}
