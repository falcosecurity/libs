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

#include <vector>
#include <string>
#include <unordered_map>
#include <libsinsp/version.h>
#include <libsinsp/event.h>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp_exception.h>

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

			/* Every plugin with event sourcing capability requires its own unique plugin event ID unless the ID is `0`
			 * in that case there could be multiple plugins with sourcing capabilities loaded
			 */
			if (it->caps() & CAP_SOURCING
				&& plugin->caps() & CAP_SOURCING
				&& plugin->id() != 0
				&& it->id() == plugin->id())
			{
				throw sinsp_exception(
					"found another plugin with ID " + std::to_string(it->id()) + ". Aborting.");
			}
		}
		if (plugin->caps() & CAP_SOURCING && plugin->id() != 0)
		{
			// note: we avoid duplicate entries in the evt sources list
			bool existing = false;

			/* Get the source index:
			 * - First we search it in the array to see if it is already present
			 * - if not present the new source position will be the first available in the `m_event_sources` array
			 */
			auto source_index = m_event_sources.size();
			for (size_t i = 0; i < m_event_sources.size(); i++)
			{
				if (m_event_sources[i] == plugin->event_source())
				{
					existing = true;
					source_index = i;
					break;
				}
			}
			if (!existing)
			{
				/* Push the source in the array if it doesn't already exist */
				m_event_sources.push_back(plugin->event_source());
			}
			auto plugin_index = m_plugins.size();
			m_plugins_id_index[plugin->id()] = plugin_index;
			m_plugins_id_source_index[plugin->id()] = source_index;
		}
		/* Push the new plugin in the array */
		m_plugins.push_back(plugin);
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
			return plugin_by_id(evt->get_param(0)->as<int32_t>());
		}
		return nullptr;
	}

	/**
	 * @brief Given a plugin id, returns the index of a source name as
	 * in the order of the inspector's event sources list. `found` is filled
	 * with `true` if a plugin with a given ID is found in the manager,
	 * otherwise it is filled with `false`.
	 */
	inline std::size_t source_idx_by_plugin_id(uint32_t plugin_id, bool& found) const
	{
		if (plugin_id != m_last_source_in)
		{
			auto it = m_plugins_id_source_index.find(plugin_id);
			if(it == m_plugins_id_source_index.end())
			{
				found = false;
				return sinsp_no_event_source_idx;
			}
			m_last_source_in = plugin_id;
			m_last_source_out = it->second;
		}
		found = true;
		return m_last_source_out;
	}

private:
	/* vector containing all plugins event source names, added in order of arrival.
	 * This is a reference to the inspector one!
	 */
	std::vector<std::string>& m_event_sources;

	/* vector containing all loaded plugins, added in order of arrival */
	std::vector<std::shared_ptr<sinsp_plugin>> m_plugins;

	/* The key is the plugin id the value is the index of the plugin in the `m_plugins` vector */
	std::unordered_map<uint32_t, size_t> m_plugins_id_index;

	/* The key is the plugin id the value is the index of the plugin source in the `m_event_sources` vector */
	std::unordered_map<uint32_t, size_t> m_plugins_id_source_index;
	mutable size_t m_last_id_in;
	mutable size_t m_last_id_out;
	mutable size_t m_last_source_in;
	mutable size_t m_last_source_out;
};
