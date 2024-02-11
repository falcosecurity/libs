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

#include <libsinsp/logger.h>

#include <libsinsp/container_engine/container_cache_interface.h>

namespace libsinsp
{

namespace container_engine
{

template<typename key_type>
container_async_source<key_type>::container_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, container_cache_interface* cache):
	parent_type(max_wait_ms, ttl_ms),
	m_cache(cache)
{
}

template<typename key_type>
bool container_async_source<key_type>::lookup(const key_type& key,
					      sinsp_container_info& value)
{
    return parent_type::lookup(
        key,
        value,
        std::bind(
            &container_async_source::source_callback,
            this,
            std::placeholders::_1,
            std::placeholders::_2));
}

template<typename key_type>
bool container_async_source<key_type>::lookup(const key_type& key,
					      sinsp_container_info& value,
					      const callback_handler& handler)
{
	return parent_type::lookup(key, value, handler);
}

template<typename key_type>
bool container_async_source<key_type>::lookup_sync(const key_type& key, sinsp_container_info& value)
{
	value.m_type = container_type(key);
	value.m_id = container_id(key);

	if(!parse(key, value))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"%s (%s): Failed to get metadata, returning successful=false",
				name(),
				value.m_id.c_str());

		value.set_lookup_status(sinsp_container_lookup::state::FAILED);
	}

	return true;
}

template<typename key_type>
void container_async_source<key_type>::source_callback(const key_type& key, const sinsp_container_info& res)
{
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			"%s_async (%s): Source callback result=%d",
			name(),
			container_id(key).c_str(),
			res.get_lookup_status());

	m_cache->notify_new_container(res);
};

template<typename key_type>
void container_async_source<key_type>::run_impl()
{
	key_type key;
	sinsp_container_info res;

	while(this->dequeue_next_key(key, &res))
	{
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
				"%s_async (%s): Source dequeued key attempt=%u",
				name(),
				container_id(key).c_str(),
				res.m_lookup.retry_no());

		lookup_sync(key, res);

		if(!res.m_lookup.should_retry())
		{
			// Either the fetch was successful or the
			// maximum number of retries have occurred.
			if(!res.m_lookup.is_successful())
			{
				libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
						"%s_async (%s): Could not look up container info after %u retries",
						name(),
						container_id(key).c_str(),
						res.m_lookup.retry_no());
			}

			this->store_value(key, res);
		}
		else
		{
			// Make a new attempt
			res.m_lookup.attempt_increment();

			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
					"%s_async (%s): lookup retry no. %d",
					name(),
					container_id(key).c_str(),
					res.m_lookup.retry_no());

			this->defer_lookup(key,
					   &res,
					   std::chrono::milliseconds(res.m_lookup.delay()));
		}

		// Reset res
		res.clear();
	}
}

} // namespace container_engine
} // namespace libsinsp
