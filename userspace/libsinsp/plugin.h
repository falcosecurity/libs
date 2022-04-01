/*
Copyright (C) 2021 The Falco Authors.

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

#include "filter_check_list.h"

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

class sinsp_plugin_cap_sourcing
{
public:
	// Describes a valid parameter for the open() function.
	struct open_param {
		std::string value;
		std::string desc;
	};

	// Return a struct to be used as scap source plugin
	virtual scap_source_plugin *as_scap_source() = 0;

	virtual uint32_t id() = 0;
	virtual const std::string &event_source() = 0;

	virtual std::string get_progress(uint32_t &progress_pct) = 0;

	virtual std::string event_to_string(const uint8_t *data, uint32_t datalen) = 0;

	virtual std::vector<open_param> list_open_params() = 0;
};

class sinsp_plugin_cap_extraction
{
public:
	virtual const std::set<std::string> &extract_event_sources() = 0;

	// Return true if the provided source is compatible with this
	// plugin with extractor capabilities, either because it does
	// not name any extract sources, or if the provided source is
	// in the set of extract sources.
	virtual bool source_compatible(const std::string &source) = 0;

	virtual bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) = 0;

	virtual const filtercheck_field_info *fields() = 0;
	virtual uint32_t nfields() = 0;
};

// Class that holds a plugin.
// it extends sinsp_plugin_cap itself because it exposes a
// resolve_dylib_symbols() logic for common plugin symbols
class sinsp_plugin: public sinsp_plugin_cap_sourcing, public sinsp_plugin_cap_extraction
{
public:
	class version {
	public:
		version();
		version(const std::string &version_str);
		virtual ~version();

		std::string as_string() const;
		bool check(version &requested) const;

		bool m_valid;
		uint32_t m_version_major;
		uint32_t m_version_minor;
		uint32_t m_version_patch;
	};

	// Contains important info about a plugin, suitable for
	// printing or other checks like compatibility.
	struct info {
		ss_plugin_caps caps;
		std::string name;
		std::string description;
		std::string contact;
		version plugin_version;
		version required_api_version;

		// Only filled in for plugins with CAP_EVENT_SOURCE capability
		uint32_t id;
	};

	// Create a plugin from the dynamic library at the provided
	// path. On error, the shared_ptr will == NULL and errstr is
	// set with an error.
	static std::shared_ptr<sinsp_plugin> create_plugin(std::string &filepath,
													   const char* config,
													   std::string &errstr,
													   filter_check_list &available_checks);

	// Return whether a filesystem object is loaded
	static bool is_plugin_loaded(std::string &filepath);

	sinsp_plugin(sinsp_plugin_handle handle);
	virtual ~sinsp_plugin();

	bool init(const char* config);
	void destroy();

	/** Common API **/
	std::string get_last_error();
	const std::string &name();
	const std::string &description();
	const std::string &contact();
	const version &plugin_version();
	const version &required_api_version();

	std::string get_init_schema(ss_plugin_schema_type& schema_type);
	void validate_init_config(std::string& config);
	/** **/

	/** Sourcing API **/
	scap_source_plugin *as_scap_source();

	uint32_t id();
	const std::string &event_source();

	std::string get_progress(uint32_t &progress_pct);

	std::string event_to_string(const uint8_t *data, uint32_t datalen);

	std::vector<sinsp_plugin_cap_sourcing::open_param> list_open_params();
	/** **/

	/** Extraction API **/
	const std::set<std::string> &extract_event_sources();

	// Return true if the provided source is compatible with this
	// plugin with extractor capabilities, either because it does
	// not name any extract sources, or if the provided source is
	// in the set of extract sources.
	bool source_compatible(const std::string &source);

	bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields);

	const filtercheck_field_info *fields();
	uint32_t nfields();
	/** **/

	ss_plugin_caps caps();

private:
	std::string m_name;
	std::string m_description;
	std::string m_contact;
	version m_plugin_version;
	version m_required_api_version;

	plugin_api m_api;
	ss_plugin_t* m_state;
	ss_plugin_caps m_caps;
	sinsp_plugin_handle m_handle;

	/** Sourcing related **/
	uint32_t m_id;
	std::string m_event_source;
	static scap_source_plugin sp;
	/** **/

	/** Extraction related **/
	std::unique_ptr<filtercheck_field_info[]> m_fields;
	int32_t m_nfields;
	std::set<std::string> m_extract_event_sources;
	/** **/

	bool resolve_dylib_symbols(std::string &errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info &tf);
	void validate_init_config_json_schema(std::string& config, std::string &schema);
	static void destroy_handle(sinsp_plugin_handle handle);
	void* getsym(const char* name, std::string &errstr);
};
