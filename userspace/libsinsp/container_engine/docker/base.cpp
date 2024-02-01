#include <libsinsp/container_engine/docker/base.h>

#include <libsinsp/sinsp.h>

using namespace libsinsp::container_engine;

void docker_base::cleanup()
{
	m_docker_info_source.reset(NULL);
}

bool
docker_base::resolve_impl(sinsp_threadinfo *tinfo, const docker_lookup_request& request, bool query_os_for_missing_info)
{
	container_cache_interface *cache = &container_cache();
	if(!m_docker_info_source)
	{
		libsinsp_logger()->log("docker_async: Creating docker async source",
			     sinsp_logger::SEV_DEBUG);
		uint64_t max_wait_ms = 10000;
		auto src = new docker_async_source(docker_async_source::NO_WAIT_LOOKUP, max_wait_ms, cache);
		m_docker_info_source.reset(src);
	}

	tinfo->m_container_id = request.container_id;

	sinsp_container_info::ptr_t container_info = cache->get_container(request.container_id);

	if(!container_info)
	{
		if(!query_os_for_missing_info)
		{
			auto container = sinsp_container_info();
			container.m_type = request.container_type;
			container.m_id = request.container_id;
			cache->notify_new_container(container, tinfo);
			return true;
		}

		if(cache->should_lookup(request.container_id, request.container_type))
		{
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): No existing container info",
					request.container_id.c_str());

			// give docker a chance to return metadata for this container
			cache->set_lookup_status(request.container_id, request.container_type, sinsp_container_lookup::state::STARTED);
			parse_docker(request, cache);
		}
		return false;
	}

	// Returning true will prevent other container engines from
	// trying to resolve the container, so only return true if we
	// have complete metadata.
	return container_info->is_successful();
}

void docker_base::parse_docker(const docker_lookup_request& request, container_cache_interface *cache)
{
	sinsp_container_info result;

	bool done;
	if (cache->async_allowed())
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Starting asynchronous lookup",
				request.container_id.c_str());
		done = m_docker_info_source->lookup(request, result);
	}
	else
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Starting synchronous lookup",
				request.container_id.c_str());
		done = m_docker_info_source->lookup_sync(request, result);
	}
	if (done)
	{
		// if a previous lookup call already found the metadata, process it now
		m_docker_info_source->source_callback(request, result);

		if(cache->async_allowed())
		{
			// This should *never* happen, in async mode as ttl is 0 (never wait)
			libsinsp_logger()->format(sinsp_logger::SEV_ERROR,
					"docker_async (%s): Unexpected immediate return from docker_info_source.lookup()",
					request.container_id.c_str());

		}
	}
}

