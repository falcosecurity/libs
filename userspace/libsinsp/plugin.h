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

#include <atomic>
#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>
#include <plugin_info.h>
#include "version.h"

#ifdef _WIN32
typedef HINSTANCE sinsp_plugin_handle;
#else
typedef void* sinsp_plugin_handle;
#endif

//
// A plugin has capabilities.
// There are following plugin caps at the moment:
// * ability to source events and provide them to the event loop
// * ability to extract fields from events created by other plugins
//
typedef enum
{
	CAP_SOURCING     = 1 << 0,
	CAP_EXTRACTION   = 1 << 1
} ss_plugin_caps;

class sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_common() = default;
	virtual bool init(const char* config) = 0;
	virtual void destroy() = 0;
	virtual std::string get_last_error() const = 0;
	virtual const std::string &name() const = 0;
	virtual const std::string &description() const = 0;
	virtual const std::string &contact() const = 0;
	virtual const sinsp_version &plugin_version() const = 0;
	virtual const sinsp_version &required_api_version() const = 0;
	virtual std::string get_init_schema(ss_plugin_schema_type& schema_type) const = 0;
	virtual ss_plugin_caps caps() const = 0;
};

class sinsp_plugin_cap_sourcing: public sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_sourcing() = default;

	// Describes a valid parameter for the open() function.
	struct open_param {
		std::string value;
		std::string desc;
	};

	// Return a struct to be used as scap source plugin
	virtual scap_source_plugin& as_scap_source() = 0;

	virtual uint32_t id() const = 0;
	virtual const std::string &event_source() const = 0;

	virtual std::string get_progress(uint32_t &progress_pct) const = 0;

	virtual std::string event_to_string(sinsp_evt* evt) const = 0;

	virtual std::vector<open_param> list_open_params() const = 0;
};

class sinsp_plugin_cap_extraction: public sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_extraction() = default;

	virtual const std::set<std::string> &extract_event_sources() const = 0;

	virtual bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const = 0;

	virtual const std::vector<filtercheck_field_info>& fields() const = 0;
};

// Class that holds a plugin.
// it extends sinsp_plugin_cap itself because it exposes a
// resolve_dylib_symbols() logic for common plugin symbols
class sinsp_plugin: public sinsp_plugin_cap_sourcing, public sinsp_plugin_cap_extraction
{
public:
	// Create a plugin from the dynamic library at the provided
	// path. On error, the shared_ptr will == NULL and errstr is
	// set with an error.
	static std::shared_ptr<sinsp_plugin> create_plugin(
		std::string &filepath,
		const char* config,
		std::string &errstr);

	// Return whether a filesystem object is loaded
	static bool is_plugin_loaded(std::string &filepath);

	sinsp_plugin(sinsp_plugin_handle handle);
	virtual ~sinsp_plugin();

	/** Common API **/
	bool init(const char* config) override;
	void destroy() override;
	std::string get_last_error() const override;
	const std::string &name() const override;
	const std::string &description() const override;
	const std::string &contact() const override;
	const sinsp_version &plugin_version() const override;
	const sinsp_version &required_api_version() const override;
	std::string get_init_schema(ss_plugin_schema_type& schema_type) const override;
	ss_plugin_caps caps() const override;

	/** Event Sourcing **/
	scap_source_plugin& as_scap_source() override;
	uint32_t id() const override;
	const std::string &event_source() const override;
	std::string get_progress(uint32_t &progress_pct) const override;
	std::string event_to_string(sinsp_evt* evt) const override;
	std::vector<sinsp_plugin_cap_sourcing::open_param> list_open_params() const override;

	/** Field Extraction **/
	const std::set<std::string> &extract_event_sources() const override;
	bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const override;
	const std::vector<filtercheck_field_info>& fields() const override;

private:
	std::string m_name;
	std::string m_description;
	std::string m_contact;
	sinsp_version m_plugin_version;
	sinsp_version m_required_api_version;

	plugin_api m_api;
	ss_plugin_t* m_state;
	ss_plugin_caps m_caps;
	sinsp_plugin_handle m_handle;

	/** Event Sourcing **/
	uint32_t m_id;
	std::string m_event_source;
	scap_source_plugin m_scap_source_plugin;

	/** Field Extraction **/
	std::vector<filtercheck_field_info> m_fields;
	std::set<std::string> m_extract_event_sources;

	void validate_init_config(std::string& config);
	bool resolve_dylib_symbols(std::string &errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info &tf);
	void validate_init_config_json_schema(std::string& config, std::string &schema);
	static void destroy_handle(sinsp_plugin_handle handle);
	void* getsym(const char* name, std::string &errstr);
};
