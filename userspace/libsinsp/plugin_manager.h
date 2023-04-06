/*
Copyright (C) 2022 The Falco Authors.

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

#include <vector>
#include <string>
#include <unordered_map>
#include "version.h"
#include "event.h"
#include "plugin.h"
#include "sinsp_exception.h"

/**
 * @brief Manager for plugins loaded at runtime.
 */
class sinsp_plugin_manager
{
public:
	sinsp_plugin_manager(std::vector<std::string>& event_sources):
		m_event_sources(event_sources),
		m_plugins(),
		m_plugins_id_index(),
		m_plugins_id_source_index(),
		m_last_id_in(-1),
		m_last_id_out(-1),
		m_last_source_in(-1),
		m_last_source_out(-1) { }
	virtual ~sinsp_plugin_manager() = default;
	sinsp_plugin_manager(sinsp_plugin_manager&&) = default;
	sinsp_plugin_manager& operator = (sinsp_plugin_manager&&) = default;
	sinsp_plugin_manager(const sinsp_plugin_manager& s) = delete;
	sinsp_plugin_manager& operator = (const sinsp_plugin_manager& s) = delete;

	/**
	 * @brief Adds a plugin in the manager.
	 */
	void add(std::shared_ptr<sinsp_plugin> plugin)
	{
		for(auto& it : m_plugins)
		{
			// todo(jasondellaluce): we may consider dropping this constraint in the future
			if(it->name() == plugin->name())
			{
				throw sinsp_exception(
					"found another plugin with name " + it->name() + ". Aborting.");
			}

			if (it->caps() & CAP_SOURCING
				&& plugin->caps() & CAP_SOURCING
				&& it->id() == plugin->id())
			{
				throw sinsp_exception(
					"found another plugin with ID " + std::to_string(it->id()) + ". Aborting.");
			}
		}
		auto plugin_index = m_plugins.size();
		m_plugins.push_back(plugin);
		if (plugin->caps() & CAP_SOURCING)
		{
			auto source_index = m_event_sources.size();
			m_event_sources.push_back(plugin->event_source());
			m_plugins_id_index[plugin->id()] = plugin_index;
			m_plugins_id_source_index[plugin->id()] = source_index;
		}
	}

	/**
	 * @brief Returns all the plugins in the manager.
	 */
	inline const std::vector<std::shared_ptr<sinsp_plugin>>& plugins() const
	{
		return m_plugins;
	}

	/**
	 * @brief Returns a plugin given its ID. The plugin is guaranteed to have
	 * the CAP_EVENT_SOURCE capability. Returns nullptr if no plugin exists
	 * with the given ID.
	 */
	inline std::shared_ptr<sinsp_plugin> plugin_by_id(uint32_t plugin_id) const
	{
		if (plugin_id != m_last_id_in)
		{
			auto it = m_plugins_id_index.find(plugin_id);
			if(it == m_plugins_id_index.end())
			{
				return nullptr;
			}
			m_last_id_in = plugin_id;
			m_last_id_out = it->second;
		}
		return m_plugins[m_last_id_out];
	}

	/**
	 * @brief  Returns a plugin given an event. The plugin is guaranteed to have
	 * the CAP_EVENT_SOURCE capability.
	 */
	inline std::shared_ptr<sinsp_plugin> plugin_by_evt(sinsp_evt* evt) const
	{
		if(evt && evt->get_type() == PPME_PLUGINEVENT_E)
		{
			sinsp_evt_param *parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			return plugin_by_id(*(int32_t *)parinfo->m_val);
		}
		return nullptr;
	}

	/**
	 * @brief Given a plugin id, returns a the index of a source name as
	 * in the order of the inspector's event sources list. `found` is filled
	 * with `true` if a plugin with a given ID is found in the manager,
	 * otherwise it is filled with `false`.
	 */
	inline std::size_t source_idx_by_plugin_id(uint32_t plugin_id, bool& found) const
	{
		auto it = m_plugins_id_source_index.find(plugin_id);
		found = it != m_plugins_id_source_index.end();
		return found ? it->second : sinsp_no_event_source_idx;
	}

private:
	std::vector<std::string>& m_event_sources;
	std::vector<std::shared_ptr<sinsp_plugin>> m_plugins;
	std::unordered_map<uint32_t, size_t> m_plugins_id_index;
	std::unordered_map<uint32_t, size_t> m_plugins_id_source_index;
	mutable size_t m_last_id_in;
	mutable size_t m_last_id_out;
	mutable size_t m_last_source_in;
	mutable size_t m_last_source_out;
};
