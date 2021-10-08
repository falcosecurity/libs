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

#include <plugin_info.h>

class sinsp_filter_check_plugin;

// Base class for source/extractor plugins. Can not be created directly.
class sinsp_plugin
{
public:
	class version {
	public:
		version();
		version(const std::string &version_str);
		virtual ~version();

		std::string as_string() const;

		bool m_valid;
		uint32_t m_version_major;
		uint32_t m_version_minor;
		uint32_t m_version_patch;
	};

	// Contains important info about a plugin, suitable for
	// printing or other checks like compatibility.
	struct info {
		ss_plugin_type type;
		std::string name;
		std::string description;
		std::string contact;
		version plugin_version;
		version required_api_version;

		// Only filled in for source plugins
		uint32_t id;
	};

	// Similar to struct ss_plugin_extract_field, but with c++
	// types to avoid having to track memory allocations.
	struct ext_field {
		std::string field;
		std::string arg;
		uint32_t ftype;

		bool field_present;
		std::string res_str;
		uint64_t res_u64;
	};

	// Create and register a plugin from a shared library pointed
	// to by filepath, and add it to the inspector.
	// The created sinsp_plugin is returned.
	static std::shared_ptr<sinsp_plugin> register_plugin(sinsp* inspector, std::string filepath, char *config);

	// Create a plugin from the dynamic library at the provided
	// path. On error, the shared_ptr will == NULL and errstr is
	// set with an error.
	static std::shared_ptr<sinsp_plugin> create_plugin(std::string &filepath, char *config, std::string &errstr);

	// Return a string with names/descriptions/etc of all plugins used by this inspector
	static std::list<sinsp_plugin::info> plugin_infos(sinsp *inspector);

	sinsp_plugin();
	virtual ~sinsp_plugin();

	// Given a dynamic library handle, fill in common properties
	// (name/desc/etc) and required functions
	// (init/destroy/extract/etc).
	// Returns true on success, false + sets errstr on error.
	virtual bool resolve_dylib_symbols(void *handle, std::string &errstr);

	bool init(char *config);
	void destroy();

	virtual ss_plugin_type type() = 0;

	std::string get_last_error();

	const std::string &name();
	const std::string &description();
	const std::string &contact();
	const version &plugin_version();
	const version &required_api_version();
	const filtercheck_field_info *fields();
	uint32_t nfields();

	bool extract_field(ss_plugin_event &evt, sinsp_plugin::ext_field &field);

protected:
	// Helper function to resolve symbols
	static void* getsym(void* handle, const char* name, std::string &errstr);

	// Helper function to set a string from an allocated charbuf and free the charbuf.
	std::string str_from_alloc_charbuf(char *charbuf);

	// init() will call this to save the resulting state struct
	virtual void set_plugin_state(ss_plugin_t *state) = 0;
	virtual ss_plugin_t *plugin_state() = 0;

private:
	// Functions common to all derived plugin
	// types. get_required_api_version/get_type are common but not
	// included here as they are called in create_plugin()
	typedef struct {
		char* (*get_required_api_version)();
		void (*free_mem)(void *ptr);
		ss_plugin_t* (*init)(char* config, int32_t* rc);
		void (*destroy)(ss_plugin_t* s);
		char* (*get_last_error)(ss_plugin_t* s);
		char* (*get_name)();
		char* (*get_description)();
		char* (*get_contact)();
		char* (*get_version)();
		char* (*get_fields)();
		int32_t (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
	} common_plugin_info;

	std::string m_name;
	std::string m_description;
	std::string m_contact;
	version m_plugin_version;
	version m_required_api_version;

	// Allocated instead of vector to match how it will be held in filter_check_info
	std::unique_ptr<filtercheck_field_info[]> m_fields;
	int32_t m_nfields;

	common_plugin_info m_plugin_info;
};

// Note that this doesn't have a next() method, as event generation is
// handled at the libscap level.
class sinsp_source_plugin : public sinsp_plugin
{
public:
	sinsp_source_plugin();
	virtual ~sinsp_source_plugin();

	bool resolve_dylib_symbols(void *handle, std::string &errstr) override;

	ss_plugin_type type() override { return TYPE_SOURCE_PLUGIN; };
	uint32_t id();
	const std::string &event_source();

	// For libscap that only works with struct of functions.
	source_plugin_info *plugin_info();

	// Note that embedding ss_instance_t in the object means that
	// a plugin can only have one open active at a time.
	bool open(char *params, int32_t &rc);
	void close();
	std::string get_progress(uint32_t &progress_pct);

	std::string event_to_string(const uint8_t *data, uint32_t datalen);

protected:
	void set_plugin_state(ss_plugin_t *state) override;
	virtual ss_plugin_t *plugin_state() override;

private:
	uint32_t m_id;
	std::string m_event_source;

	source_plugin_info m_source_plugin_info;
};

class sinsp_extractor_plugin : public sinsp_plugin
{
public:
	sinsp_extractor_plugin();
	virtual ~sinsp_extractor_plugin();

	bool resolve_dylib_symbols(void *handle, std::string &errstr) override;

	ss_plugin_type type() override { return TYPE_EXTRACTOR_PLUGIN; };

	const std::set<std::string> &extract_event_sources();

	// Return true if the provided source is compatible with this
	// extractor plugin, either because the extractor plugin does
	// not name any extract sources, or if the provided source is
	// in the set of extract sources.
	bool source_compatible(const std::string &source);

protected:
	void set_plugin_state(ss_plugin_t *state) override;
	virtual ss_plugin_t *plugin_state() override;

private:
	extractor_plugin_info m_extractor_plugin_info;
	std::set<std::string> m_extract_event_sources;
};
