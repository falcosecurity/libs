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
#include <algorithm>
#include "plugin_manager.h"
#include "sinsp_exception.h"

sinsp_plugin_manager::~sinsp_plugin_manager()
{
	m_plugins.clear();
	m_source_names.clear();
	m_plugins_id_index.clear();
	m_plugins_id_source_index.clear();
}

void sinsp_plugin_manager::add(std::shared_ptr<sinsp_plugin> plugin)
{
	for(auto& it : m_plugins)
	{
		if(it->name() == plugin->name())
		{
			throw sinsp_exception(
				"found multiple plugins with name " + it->name() + ". Aborting.");
		}
	}
	auto index = m_plugins.size();
	m_plugins.push_back(plugin);
	if (plugin->caps() & CAP_SOURCING)
	{
		auto source_index = m_source_names.size();
		m_source_names.push_back(plugin->event_source());
		m_plugins_id_index[plugin->id()] = index;
		m_plugins_id_source_index[plugin->id()] = source_index;
	}	
}

const std::vector<std::string>& sinsp_plugin_manager::sources() const
{
	return m_source_names;
}

const std::vector<std::shared_ptr<sinsp_plugin>>& sinsp_plugin_manager::plugins() const
{
	return m_plugins;
}

std::vector<sinsp_plugin_manager::info> sinsp_plugin_manager::infos() const
{
	std::vector<sinsp_plugin_manager::info> ret;
	for(auto p : plugins())
	{
		sinsp_plugin_manager::info info;
		info.name = p->name();
		info.description = p->description();
		info.contact = p->contact();
		info.plugin_version = p->plugin_version();
		info.required_api_version = p->required_api_version();
		info.caps = p->caps();
		info.id = info.caps & CAP_SOURCING ? p->id() : 0;
		ret.push_back(info);
	}
	return ret;
}

std::shared_ptr<sinsp_plugin_cap_sourcing> sinsp_plugin_manager::plugin_by_id(uint32_t id) const
{
	auto it = m_plugins_id_index.find(id);
	return it != m_plugins_id_index.end() ? m_plugins[it->second] : nullptr;
}

std::shared_ptr<sinsp_plugin_cap_sourcing> sinsp_plugin_manager::plugin_by_evt(sinsp_evt &evt) const
{
	if(evt.get_type() == PPME_PLUGINEVENT_E)
	{
		sinsp_evt_param *parinfo = evt.get_param(0);
		ASSERT(parinfo->m_len == sizeof(int32_t));
		return plugin_by_id(*(int32_t *)parinfo->m_val);
	}
	return nullptr;
}

size_t sinsp_plugin_manager::source_by_plugin_id(uint32_t plugin_id, bool& found) const
{
	auto it = m_plugins_id_source_index.find(plugin_id);
	found = it != m_plugins_id_source_index.end();
	return found ? it->second : 0;
}
