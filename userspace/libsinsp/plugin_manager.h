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

/*!
	\brief Manager for plugins loaded at runtime
*/
class sinsp_plugin_manager
{
public:
	/*!
		\brief Contains important info about a plugin, suitable for
		printing or other checks like compatibility.
	*/
	struct info
	{
		uint32_t id; // only for plugins with CAP_EVENT_SOURCE capability
		ss_plugin_caps caps;
		std::string name;
		std::string description;
		std::string contact;
		sinsp_version plugin_version;
		sinsp_version required_api_version;
	};

	virtual ~sinsp_plugin_manager();

	/*!
		\brief Adds a plugin in the manager
	*/
	void add(std::shared_ptr<sinsp_plugin> plugin);

	/*!
		\brief Returns all the plugins
	*/
	const std::vector<std::shared_ptr<sinsp_plugin>>& plugins() const;

	/*!
		\brief Returns the source names from all the plugins. The index
		is maintained constant until reset() is invoked, so it may be used
		by consumers for efficient index-based lookups.
	*/
	const std::vector<std::string>& sources() const;

	/*!
		\brief Returns names/descriptions/etc for all the plugins
	*/
	std::vector<info> infos() const;

	/*!
		\brief Returns a plugin given its ID
	*/
	std::shared_ptr<sinsp_plugin_cap_sourcing> plugin_by_id(uint32_t id) const;

	/*!
		\brief Returns a plugin given an event
	*/
	std::shared_ptr<sinsp_plugin_cap_sourcing> plugin_by_evt(sinsp_evt &evt) const;

	/*!
		\brief Returns a the index of a source name as in the order of sources()
		given a plugin id
	*/
	size_t source_by_plugin_id(uint32_t plugin_id, bool& found) const;

private:
	std::vector<std::shared_ptr<sinsp_plugin>> m_plugins;
	std::vector<std::string> m_source_names;
	std::unordered_map<uint32_t, uint32_t> m_plugins_id_index;
	std::unordered_map<uint32_t, uint32_t> m_plugins_id_source_index;
};
