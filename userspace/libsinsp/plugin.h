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

#include <memory>
#include <unordered_set>
#include <string>
#include <vector>
#include <engine/source_plugin/source_plugin_public.h>
#include "event.h"
#include "version.h"
#include "../plugin/plugin_loader.h"

// todo(jasondellaluce: remove this forward declaration)
class sinsp_filter_check;

/**
 * @brief An object-oriented representation of a plugin.
 */
class sinsp_plugin
{
public:
	struct open_param
	{
		open_param() = default;
		~open_param() = default;
		open_param(open_param&&) = default;
		open_param& operator = (open_param&&) = default;
		open_param(const open_param& s) = default;
		open_param& operator = (const open_param& s) = default;

		std::string value;
		std::string desc;
		std::string separator;
	};

	/**
	 * @brief Create a plugin from the dynamic library at the provided path.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(const std::string& path, std::string& errstr);
	
	/**
	 * @brief Create a plugin from the provided api vtable.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(const plugin_api* api, std::string& errstr);

	/**
	 * @brief Return whether a filesystem dynamic library object is loaded.
	 */
	static bool is_plugin_loaded(std::string& filepath);

	/**
	 * @brief If the plugin has CAP_EXTRACTION capability, returns a
	 * filtercheck with its exported fields. Returns NULL otherwise.
	 * 
	 * todo(jasondellaluce): make this return a unique_ptr
	 */
	static sinsp_filter_check* new_filtercheck(std::shared_ptr<sinsp_plugin> plugin);

	/**
	 * @brief Returns true if the source is compatible with the given set
	 * of sources.
	 */
	static inline bool is_source_compatible(
		const std::unordered_set<std::string>& sources, const std::string& source)
	{
		return sources.empty() || sources.find(source) != sources.end();
	}

	sinsp_plugin(plugin_handle_t* handle):
		m_caps(CAP_NONE),
		m_id(-1),
		m_state(nullptr),
		m_handle(handle) { }
	virtual ~sinsp_plugin();
	sinsp_plugin(sinsp_plugin&&) = default;
	sinsp_plugin& operator = (sinsp_plugin&&) = default;
	sinsp_plugin(const sinsp_plugin& s) = delete;
	sinsp_plugin& operator = (const sinsp_plugin& s) = delete;

	/** Common API **/
	inline plugin_caps_t caps() const
	{
		return m_caps;
	}

	inline const std::string& name() const
	{
		return m_name;
	}

	inline const std::string& description() const
	{
		return m_description;
	}

	inline const std::string& contact() const
	{
		return m_contact;
	}

	inline const sinsp_version& plugin_version() const
	{
		return m_plugin_version;
	}

	inline const sinsp_version& required_api_version() const
	{
		return m_required_api_version;
	}

	bool init(const std::string& config, std::string& errstr);
	void destroy();
	std::string get_last_error() const;
	std::string get_init_schema(ss_plugin_schema_type& schema_type) const;

	/** Event Sourcing **/
	inline uint32_t id() const
	{
		return m_id;
	}

	inline const std::string& event_source() const
	{
		return m_event_source;
	}

	scap_source_plugin& as_scap_source();
	std::string get_progress(uint32_t& progress_pct) const;
	std::string event_to_string(sinsp_evt* evt) const;
	std::vector<open_param> list_open_params() const;

	/** Field Extraction **/
	inline const std::unordered_set<std::string>& extract_event_sources() const
	{
		return m_extract_event_sources;
	}

	inline const std::vector<filtercheck_field_info>& fields() const
	{
		return m_fields;
	}

	bool extract_fields(ss_plugin_event& evt, uint32_t num_fields, ss_plugin_extract_field *fields) const;

// note(jasondellaluce): we set these as protected in order to allow unit
// testing mocking these values, without having to declare their accessors
// as virtual (thus avoiding performance loss in some hot paths).
protected:
	plugin_caps_t m_caps;
	std::string m_name;
	std::string m_description;
	std::string m_contact;
	sinsp_version m_plugin_version;
	sinsp_version m_required_api_version;

	/** Event Sourcing */
	uint32_t m_id;
	std::string m_event_source;

private:
	ss_plugin_t* m_state;
	plugin_handle_t* m_handle;

	/** Event Sourcing **/
	scap_source_plugin m_scap_source_plugin;

	/** Field Extraction **/
	std::vector<filtercheck_field_info> m_fields;
	std::unordered_set<std::string> m_extract_event_sources;

	void validate_init_config(std::string& config);
	bool resolve_dylib_symbols(std::string& errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info& tf);
	void validate_init_config_json_schema(std::string& config, std::string& schema);
};
