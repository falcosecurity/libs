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

#include <libsinsp/async/async_key_value_source.h>
#include <libsinsp/container_info.h>
#include <chrono>

namespace libsinsp
{
namespace container_engine
{

class container_cache_interface;

/**
 * Asynchronous metadata lookup base class.
 *
 * @tparam key_type lookup key
 */
template<typename key_type>
class container_async_source : public libsinsp::async_key_value_source<key_type, sinsp_container_info>
{
	using parent_type = libsinsp::async_key_value_source<key_type, sinsp_container_info>;
	using callback_handler = typename parent_type::callback_handler;

public:
	container_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, container_cache_interface* cache);
	virtual ~container_async_source() {}

	// convenience method with default callback
	bool lookup(const key_type& key, sinsp_container_info& value);

	bool lookup(const key_type& key,
		    sinsp_container_info& value,
		    const callback_handler& handler);

	bool lookup_sync(const key_type& key, sinsp_container_info& value);

	void source_callback(const key_type& key, const sinsp_container_info& res);

protected:
	virtual const char* name() const = 0;

	virtual bool parse(const key_type& key, sinsp_container_info& value) = 0;

	virtual sinsp_container_type container_type(const key_type& key) const = 0;
	virtual std::string container_id(const key_type& key) const = 0;

	container_cache_interface* m_cache;

private:
	void run_impl() override;
};

} // namespace container_engine
} // namespace libsinsp

#include <libsinsp/container_engine/container_async_source.tpp>
