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

#include <memory>
#include <unordered_set>
#include <string>
#include <vector>
#include <atomic>
#include <libscap/engine/source_plugin/source_plugin_public.h>
#include <libsinsp/event.h>
#include <libsinsp/version.h>
#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/state/table_registry.h>
#include <plugin/plugin_loader.h>

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
	static std::shared_ptr<sinsp_plugin> create(
		const std::string& path,
		const std::shared_ptr<libsinsp::state::table_registry>& treg,
		std::string& errstr);

	/**
	 * @brief Create a plugin from the provided api vtable.
	 * On error, the shared_ptr will == nullptr and errstr is set with an error.
	 */
	static std::shared_ptr<sinsp_plugin> create(
		const plugin_api* api,
		const std::shared_ptr<libsinsp::state::table_registry>& treg,
		std::string& errstr);

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

	sinsp_plugin(plugin_handle_t*
			handle, const std::shared_ptr<libsinsp::state::table_registry>& treg):
		m_caps(CAP_NONE),
		m_name(),
		m_description(),
		m_contact(),
		m_plugin_version(),
		m_required_api_version(),
		m_id(0),
		m_event_source(),
		m_inited(false),
		m_state(nullptr),
		m_handle(handle),
		m_last_owner_err(),
		m_scap_source_plugin(),
		m_fields(),
		m_extract_event_sources(),
		m_extract_event_codes(),
		m_parse_event_sources(),
		m_parse_event_codes(),
		m_table_registry(treg),
		m_table_infos(),
		m_owned_tables(),
		m_accessed_tables(),
		m_async_event_sources(),
		m_async_event_names(),
		m_async_evt_handler(nullptr) { }
	virtual ~sinsp_plugin();
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

	const libsinsp::events::set<ppm_event_code>& extract_event_codes() const;

	inline const std::vector<filtercheck_field_info>& fields() const
	{
		return m_fields;
	}

	bool extract_fields(sinsp_evt* evt, uint32_t num_fields, ss_plugin_extract_field *fields) const;

	/** Event Parsing **/
	inline const std::unordered_set<std::string>& parse_event_sources() const
	{
		return m_parse_event_sources;
	}

	const libsinsp::events::set<ppm_event_code>& parse_event_codes() const;

	bool parse_event(sinsp_evt* evt) const;

	/** Async Events **/
	inline const std::unordered_set<std::string>& async_event_sources() const
	{
		return m_async_event_sources;
	}

	inline const std::unordered_set<std::string>& async_event_names() const
	{
		return m_async_event_names;
	}

	using async_event_handler_t = std::function<void(const sinsp_plugin&, std::unique_ptr<sinsp_evt>)>;

	bool set_async_event_handler(async_event_handler_t handler);

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
	/* this checks if we already called the init API */
	bool m_inited;
	ss_plugin_t* m_state;
	plugin_handle_t* m_handle;
	std::string m_last_owner_err;

	/** Event Sourcing **/
	scap_source_plugin m_scap_source_plugin;

	/** Field Extraction **/
	std::vector<filtercheck_field_info> m_fields;
	std::unordered_set<std::string> m_extract_event_sources;
	libsinsp::events::set<ppm_event_code> m_extract_event_codes;

	/** Event Parsing **/
	struct accessed_table_input_deleter { void operator()(ss_plugin_table_input* r); };
	using owned_table_t = std::unique_ptr<libsinsp::state::base_table>;
	using accessed_table_t = std::unique_ptr<ss_plugin_table_input, accessed_table_input_deleter>;
	std::unordered_set<std::string> m_parse_event_sources;
	libsinsp::events::set<ppm_event_code> m_parse_event_codes;
	std::shared_ptr<libsinsp::state::table_registry> m_table_registry;
	std::vector<ss_plugin_table_info> m_table_infos;
	std::unordered_map<std::string, owned_table_t> m_owned_tables;
	/* contains tables that the plugin accessed at least once */
	std::unordered_map<std::string, accessed_table_t> m_accessed_tables;

	/** Async Events **/
	std::unordered_set<std::string> m_async_event_sources;
	std::unordered_set<std::string> m_async_event_names;
	std::atomic<async_event_handler_t*> m_async_evt_handler; // note: we don't have thread-safe smart pointers

	/** Generic helpers **/
	void validate_init_config(std::string& config);
	bool resolve_dylib_symbols(std::string& errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info& tf);
	void resolve_dylib_compatible_sources(
		const std::string& symbol,
		const char *(*get_sources)(),
		std::unordered_set<std::string>& sources);
	void resolve_dylib_compatible_codes(
		uint16_t *(*get_codes)(uint32_t* numtypes,ss_plugin_t* s),
		const std::unordered_set<std::string>& sources,
		libsinsp::events::set<ppm_event_code>& codes);
	void validate_init_config_json_schema(std::string& config, std::string& schema);
	static const char* get_owner_last_error(ss_plugin_owner_t* o);

	/** Event parsing helpers **/
	static void table_field_api(ss_plugin_table_fields_vtable& out, ss_plugin_table_fields_vtable_ext& extout);
	static void table_read_api(ss_plugin_table_reader_vtable& out, ss_plugin_table_reader_vtable_ext& extout);
	static void table_write_api(ss_plugin_table_writer_vtable& out, ss_plugin_table_writer_vtable_ext& extout);
	static ss_plugin_table_info* table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables);
	static ss_plugin_table_t *table_api_get_table(ss_plugin_owner_t *o, const char *name, ss_plugin_state_type key_type);
	static ss_plugin_rc table_api_add_table(ss_plugin_owner_t *o, const ss_plugin_table_input* in);

	/** Async events helpers **/
	static ss_plugin_rc handle_plugin_async_event(ss_plugin_owner_t *o, const ss_plugin_event* evt, char* err);

	friend struct sinsp_table_wrapper;
};
