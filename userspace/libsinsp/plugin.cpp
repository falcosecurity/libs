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


#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <sstream>
#include <numeric>
#include <json/json.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <valijson/adapters/jsoncpp_adapter.hpp>
#pragma GCC diagnostic pop
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

#include <libsinsp/sinsp_int.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_filtercheck.h>
#include <libscap/strl.h>

using namespace std;

static constexpr const char* s_not_init_err = "plugin capability used before init";

static constexpr const char* s_init_twice_err = "plugin has been initialized twice";

//
// Plugin Type Look Up Table
//
const std::unordered_map<std::string, ppm_param_type> s_pt_lut = {
	{"string", PT_CHARBUF},
	{"uint64", PT_UINT64},
	{"reltime", PT_RELTIME},
	{"abstime", PT_ABSTIME},
	{"bool", PT_BOOL},
	{"ipaddr", PT_IPADDR},
	{"ipnet", PT_IPNET},
};

// Used below--set a std::string from the provided allocated charbuf
static std::string str_from_alloc_charbuf(const char* charbuf)
{
	std::string str;

	if(charbuf != NULL)
	{
		str = charbuf;
	}

	return str;
}

const char* sinsp_plugin::get_owner_last_error(ss_plugin_owner_t* o)
{
	auto t = static_cast<sinsp_plugin*>(o);
	if (t->m_last_owner_err.empty())
	{
		return NULL;
	}
	return t->m_last_owner_err.c_str();
}

const void sinsp_plugin::log(char* msg, ss_plugin_log_severity sev)
{
	libsinsp_logger()->log(msg, (sinsp_logger::severity)sev);
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create(
		const plugin_api* api,
		const std::shared_ptr<libsinsp::state::table_registry>& treg,
		std::string& errstr)
{
	char loadererr[PLUGIN_MAX_ERRLEN];
	auto handle = plugin_load_api(api, loadererr);
	if (handle == NULL)
	{
		errstr = loadererr;
		return nullptr;
	}

	std::shared_ptr<sinsp_plugin> plugin(new sinsp_plugin(handle, treg));
	if (!plugin->resolve_dylib_symbols(errstr))
	{
		// plugin and handle get deleted here by shared_ptr
		return nullptr;
	}

	return plugin;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create(
		const std::string &filepath,
		const std::shared_ptr<libsinsp::state::table_registry>& treg,
		std::string& errstr)
{
	char loadererr[PLUGIN_MAX_ERRLEN];
	auto handle = plugin_load(filepath.c_str(), loadererr);
	if (handle == NULL)
	{
		errstr = loadererr;
		return nullptr;
	}

	std::shared_ptr<sinsp_plugin> plugin(new sinsp_plugin(handle, treg));
	if (!plugin->resolve_dylib_symbols(errstr))
	{
		// plugin and handle get deleted here by shared_ptr
		return nullptr;
	}

	return plugin;
}

bool sinsp_plugin::is_plugin_loaded(std::string &filepath)
{
	return plugin_is_loaded(filepath.c_str());
}

sinsp_plugin::~sinsp_plugin()
{
	destroy();
	plugin_unload(m_handle);

	auto cur_async_handler = m_async_evt_handler.load();
	if (cur_async_handler)
	{
		m_async_evt_handler.store(nullptr);
		delete cur_async_handler;
	}
}

bool sinsp_plugin::init(const std::string &config, std::string &errstr)
{
	if (m_inited)
	{
		errstr = std::string(s_init_twice_err) + ": " + m_name;
		return false;
	}

	if (!m_handle->api.init)
	{
		errstr = string("init api symbol not found");
		return false;
	}

	ss_plugin_rc rc;
	std::string conf = config;
	validate_init_config(conf);

	ss_plugin_init_input in = {};
	in.owner = this;
	in.get_owner_last_error = sinsp_plugin::get_owner_last_error;
	in.tables = NULL;
	in.config = conf.c_str();
	in.log = sinsp_plugin::log;

	ss_plugin_init_tables_input tables_in = {};
	ss_plugin_table_fields_vtable_ext table_fields_ext = {};

	if (m_caps & (CAP_PARSING | CAP_EXTRACTION))
	{
		tables_in.fields_ext = &table_fields_ext;
		sinsp_plugin::table_field_api(tables_in.fields, table_fields_ext);
		tables_in.list_tables = sinsp_plugin::table_api_list_tables;
		tables_in.get_table = sinsp_plugin::table_api_get_table;
		tables_in.add_table = sinsp_plugin::table_api_add_table;
		in.tables = &tables_in;
	}
	ss_plugin_t *state = m_handle->api.init(&in, &rc);
	if (state != NULL)
	{
		// Plugins can return a state even if the result code is
		// SS_PLUGIN_FAILURE, which can be useful to set an init
		// error that can later be retrieved through get_last_error().
		m_state = state;
	}

	m_inited = true;
	if (rc != SS_PLUGIN_SUCCESS)
	{
		errstr = "could not initialize plugin: " + get_last_error();
		return false;
	}

	// resolve post-init event code filters
	if (m_caps & CAP_EXTRACTION)
	{
		/* Here we populate the `m_extract_event_codes` for the plugin, while `m_extract_event_sources` is already populated in the plugin_init */
		resolve_dylib_compatible_codes(m_handle->api.get_extract_event_types,
			m_extract_event_sources, m_extract_event_codes);
	}
	if (m_caps & CAP_PARSING)
	{
		/* Here we populate the `m_parse_event_codes` for the plugin, while `m_parse_event_sources` is already populated in the plugin_init */
		resolve_dylib_compatible_codes(m_handle->api.get_parse_event_types,
			m_parse_event_sources, m_parse_event_codes);
	}

	return true;
}

void sinsp_plugin::destroy()
{
	m_inited = false;
	if(m_state && m_handle->api.destroy)
	{
		m_handle->api.destroy(m_state);
		m_state = NULL;
	}
}

std::string sinsp_plugin::get_last_error() const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	std::string ret;
	if(m_state)
	{
		ret = str_from_alloc_charbuf(m_handle->api.get_last_error(m_state));
	}
	else
	{
		ret = "plugin handle or 'get_last_error' function not defined";
	}

	return ret;
}

void sinsp_plugin::resolve_dylib_field_arg(Json::Value root, filtercheck_field_info &tf)
{
	if (root.isNull())
	{
		return;
	}

	const Json::Value &isRequired = root.get("isRequired", Json::Value::null);
	if (!isRequired.isNull())
	{
		if (!isRequired.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isRequired property is not boolean");
		}

		if (isRequired.asBool() == true)
		{
			// All the extra casting is because this is the one flags value
			// that is strongly typed and not just an int.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_REQUIRED);
		}
	}

	const Json::Value &isIndex = root.get("isIndex", Json::Value::null);
	if (!isIndex.isNull())
	{
		if (!isIndex.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isIndex property is not boolean");
		}

		if (isIndex.asBool() == true)
		{
			// We set `EPF_ARG_ALLOWED` implicitly.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_INDEX);
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_ALLOWED);
		}
	}

	const Json::Value &isKey = root.get("isKey", Json::Value::null);
	if (!isKey.isNull())
	{
		if (!isKey.isBool())
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " isKey property is not boolean");
		}

		if (isKey.asBool() == true)
		{
			// We set `EPF_ARG_ALLOWED` implicitly.
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_KEY);
			tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags | (int) filtercheck_field_flags::EPF_ARG_ALLOWED);
		}
	}

	if((tf.m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED)
	   && !(tf.m_flags & filtercheck_field_flags::EPF_ARG_INDEX
	        || tf.m_flags & filtercheck_field_flags::EPF_ARG_KEY))
	{
		throw sinsp_exception(string("error in plugin ") + m_name + ": field " + tf.m_name + " arg has isRequired true, but none of isKey nor isIndex is true");
	}
	return;
}

// this logic is shared between the field extraction and event parsing caps
void sinsp_plugin::resolve_dylib_compatible_codes(
		uint16_t *(*get_codes)(uint32_t*,ss_plugin_t*),
		const std::unordered_set<std::string>& sources,
		libsinsp::events::set<ppm_event_code>& codes)
{
	codes.clear();
	if (get_codes != NULL)
	{
		uint32_t ntypes = 0;
		auto types = get_codes(&ntypes, m_state);
		if (types)
		{
			for (uint32_t i = 0; i < ntypes; i++)
			{
				codes.insert((ppm_event_code) types[i]);
			}
		}
	}
	if (codes.empty())
	{
		if (is_source_compatible(sources, sinsp_syscall_event_source_name))
		{
			codes = libsinsp::events::all_event_set();
		}
		else
		{
			codes.insert(ppm_event_code::PPME_PLUGINEVENT_E);
		}
	}
}

static void resolve_dylib_json_strlist(
		const std::string& plname,
		const std::string& symbol,
		const char *(*get_list)(),
		std::unordered_set<std::string>& out,
		bool allow_empty)
{
	out.clear();
	if(get_list == NULL)
	{
		return;
	}

	std::string jsonstr = str_from_alloc_charbuf(get_list());

	if(jsonstr.empty())
	{
		if(allow_empty)
		{
			// Do nothing, we allow an empty json string.
			return;
		}
		else
		{
			throw sinsp_exception("error in plugin " + plname + ": '"
				+ symbol + "' did not return a json array but it should");
		}
	}

	Json::Value root;
	if (!Json::Reader().parse(jsonstr, root) || root.type() != Json::arrayValue)
	{
		throw sinsp_exception("error in plugin " + plname + ": '"
			+ symbol + "' did not return a json array");
	}
	for (const auto& j : root)
	{
		if (!j.isConvertibleTo(Json::stringValue))
		{
			throw sinsp_exception("error in plugin " + plname + ": '"
				+ symbol + "' did not return a json array");
		}
		auto src = j.asString();
		if (!src.empty())
		{
			out.insert(src);
		}
	}
}

// this logic is shared between the field extraction and event parsing caps
void sinsp_plugin::resolve_dylib_compatible_sources(
		const std::string& symbol,
		const char *(*get_sources)(),
		std::unordered_set<std::string>& sources)
{
	resolve_dylib_json_strlist(name(), symbol, get_sources, sources, true);

	// A plugin with source capability extracts/parses events
	// from its own specific source (if no other sources are specified)
	if (m_caps & CAP_SOURCING && !m_event_source.empty())
	{
		sources.insert(m_event_source);
	}
}

bool sinsp_plugin::resolve_dylib_symbols(std::string &errstr)
{
	char err[PLUGIN_MAX_ERRLEN];

	// Before doing anything else, check the required api version
	if (!plugin_check_required_api_version(m_handle, err))
	{
		errstr = err;
		return false;
	}

	// check that the API requirements are satisfied
	// These are the minimum APIs that all plugins should implement
	if (!plugin_check_required_symbols(m_handle, err))
	{
		errstr = err;
		return false;
	}

	// store descriptive info in internal state
	m_name = str_from_alloc_charbuf(m_handle->api.get_name());
	m_description = str_from_alloc_charbuf(m_handle->api.get_description());
	m_contact = str_from_alloc_charbuf(m_handle->api.get_contact());
	std::string version_str = str_from_alloc_charbuf(m_handle->api.get_version());
	m_plugin_version = sinsp_version(version_str);
	if(!m_plugin_version.is_valid())
	{
		errstr = "plugin provided an invalid version string: '" + version_str + "'";
		return false;
	}
	std::string req_api_version_str = str_from_alloc_charbuf(m_handle->api.get_required_api_version());
	m_required_api_version = sinsp_version(req_api_version_str);
	if(!m_required_api_version.is_valid())
	{
		errstr = "plugin provided an invalid required api version string: '" + req_api_version_str + "'";
		return false;
	}

	// read capabilities and process their info
	m_caps = plugin_get_capabilities(m_handle, err);
	if (m_caps & CAP_BROKEN)
	{
		errstr = "broken plugin capabilities: " + std::string(err);
		return false;
	}
	if (m_caps == CAP_NONE)
	{
		errstr = "plugin does not implement any capability";
		return false;
	}

	if(m_caps & CAP_SOURCING)
	{
		/* Default case: no id and no source */
		m_id = 0;
		m_event_source.clear();
		if (m_handle->api.get_id != NULL
			&& m_handle->api.get_event_source != NULL
			&& m_handle->api.get_id() != 0)
		{
			m_id = m_handle->api.get_id();
			m_event_source = str_from_alloc_charbuf(m_handle->api.get_event_source());
			if (m_event_source == sinsp_syscall_event_source_name)
			{
				errstr = "plugin can't implement the reserved event source '" + m_event_source + "'";
				return false;
			}
		}
	}

	if(m_caps & CAP_EXTRACTION)
	{
		//
		// If filter fields are exported by the plugin, get the json from get_fields(),
		// parse it, create our list of fields, and create a filtercheck from the fields.
		//
		const char *sfields = m_handle->api.get_fields();
		if (sfields == NULL) {
			throw sinsp_exception(
					string("error in plugin ") + name() + ": get_fields returned a null string");
		}
		string json(sfields);

		Json::Value root;
		if (Json::Reader().parse(json, root) == false || root.type() != Json::arrayValue) {
			throw sinsp_exception(
					string("error in plugin ") + name() + ": get_fields returned an invalid JSON");
		}

		m_fields.clear();
		for (Json::Value::ArrayIndex j = 0; j < root.size(); j++) {
			filtercheck_field_info tf;
			tf.m_flags = EPF_NONE;

			const Json::Value &jvtype = root[j]["type"];
			string ftype = jvtype.asString();
			if (ftype == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no type");
			}
			const Json::Value &jvname = root[j]["name"];
			string fname = jvname.asString();
			if (fname == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no name");
			}
			const Json::Value &jvdisplay = root[j]["display"];
			string fdisplay = jvdisplay.asString();
			const Json::Value &jvdesc = root[j]["desc"];
			string fdesc = jvdesc.asString();
			if (fdesc == "") {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": field JSON entry has no desc");
			}

			strlcpy(tf.m_name, fname.c_str(), sizeof(tf.m_name));
			strlcpy(tf.m_display, fdisplay.c_str(), sizeof(tf.m_display));
			strlcpy(tf.m_description, fdesc.c_str(), sizeof(tf.m_description));
			tf.m_print_format = PF_DEC;
			if(s_pt_lut.find(ftype) != s_pt_lut.end()) {
				tf.m_type = s_pt_lut.at(ftype);
			} else {
				throw sinsp_exception(
						string("error in plugin ") + name() + ": invalid field type " + ftype);
			}

			const Json::Value &jvIsList = root[j].get("isList", Json::Value::null);
			if (!jvIsList.isNull()) {
				if (!jvIsList.isBool()) {
					throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
					                      " isList property is not boolean ");
				}

				if (jvIsList.asBool()) {
					tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
					                                        (int) filtercheck_field_flags::EPF_IS_LIST);
				}
			}

			resolve_dylib_field_arg(root[j].get("arg", Json::Value::null), tf);

			const Json::Value &jvProperties = root[j].get("properties", Json::Value::null);
			if (!jvProperties.isNull()) {
				if (!jvProperties.isArray()) {
					throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
					                      " properties property is not array ");
				}

				for (const auto & prop : jvProperties) {
						if (!prop.isString()) {
						throw sinsp_exception(string("error in plugin ") + name() + ": field " + fname +
						                      " properties value is not string ");
					}

					const std::string &str = prop.asString();

					// "hidden" is used inside and outside libs. "info" and "conversation" are used outside libs.
					if (str == "hidden") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_TABLE_ONLY);
					} else if (str == "info") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_INFO);
					} else if (str == "conversation") {
						tf.m_flags = (filtercheck_field_flags) ((int) tf.m_flags |
						                                        (int) filtercheck_field_flags::EPF_CONVERSATION);
					}
				}
			}
			m_fields.push_back(tf);
		}

		// This API is not compulsory for the extraction capability
		resolve_dylib_compatible_sources("get_extract_event_sources",
			m_handle->api.get_extract_event_sources, m_extract_event_sources);
	}

	if(m_caps & CAP_PARSING)
	{
		resolve_dylib_compatible_sources("get_parse_event_sources",
			m_handle->api.get_parse_event_sources, m_parse_event_sources);
	}

	if(m_caps & CAP_ASYNC)
	{
		resolve_dylib_compatible_sources("get_async_event_sources",
			m_handle->api.get_async_event_sources, m_async_event_sources);
		resolve_dylib_json_strlist(name(), "get_async_events",
			m_handle->api.get_async_events, m_async_event_names, false);
	}

	return true;
}

std::string sinsp_plugin::get_init_schema(ss_plugin_schema_type& schema_type) const
{
	schema_type = SS_PLUGIN_SCHEMA_NONE;
	if (m_handle->api.get_init_schema != NULL)
	{
		return str_from_alloc_charbuf(m_handle->api.get_init_schema(&schema_type));
	}
	return std::string("");
}

const libsinsp::events::set<ppm_event_code>& sinsp_plugin::extract_event_codes() const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}
	return m_extract_event_codes;
}

const libsinsp::events::set<ppm_event_code>& sinsp_plugin::parse_event_codes() const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}
	return m_parse_event_codes;
}

void sinsp_plugin::validate_init_config(std::string& config)
{
	ss_plugin_schema_type schema_type;
	std::string schema = get_init_schema(schema_type);
	if (!schema.empty() && schema_type != SS_PLUGIN_SCHEMA_NONE)
	{
		switch (schema_type)
		{
			case SS_PLUGIN_SCHEMA_JSON:
				validate_init_config_json_schema(config, schema);
				break;
			default:
				ASSERT(false);
				throw sinsp_exception(
					string("error in plugin ")
					+ name()
					+ ": get_init_schema returned an unknown schema type "
					+ to_string(schema_type));
		}
	}
}

void sinsp_plugin::validate_init_config_json_schema(std::string& config, std::string &schema)
{
	Json::Value schemaJson;
	if(!Json::Reader().parse(schema, schemaJson) || schemaJson.type() != Json::objectValue)
	{
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ ": get_init_schema did not return a json object");
	}

	// stub empty configs to an empty json object
	if (config.size() == 0)
	{
		config = "{}";
	}
	Json::Value configJson;
	if(!Json::Reader().parse(config, configJson))
	{
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ ": init config is not a valid json");
	}

	// validate config with json schema
	valijson::Schema schemaDef;
	valijson::SchemaParser schemaParser;
	valijson::Validator validator;
	valijson::ValidationResults validationResults;
	valijson::adapters::JsonCppAdapter configAdapter(configJson);
	valijson::adapters::JsonCppAdapter schemaAdapter(schemaJson);
	schemaParser.populateSchema(schemaAdapter, schemaDef);
	if (!validator.validate(schemaDef, configAdapter, &validationResults))
	{
		valijson::ValidationResults::Error error;
		// report only the top-most error
		if (validationResults.popError(error))
		{
			throw sinsp_exception(
				string("error in plugin ")
				+ name()
				+ " init config: In "
				+ std::accumulate(error.context.begin(), error.context.end(), std::string(""))
				+ ", "
				+ error.description);
		}
		// validation failed with no specific error
		throw sinsp_exception(
			string("error in plugin ")
			+ name()
			+ " init config: failed parsing with provided schema");
	}
}

/** Event Source CAP **/

scap_source_plugin& sinsp_plugin::as_scap_source()
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	if (!(caps() & CAP_SOURCING))
	{
		throw sinsp_exception("can't create scap_source_plugin from a plugin without CAP_SOURCING capability.");
	}

	m_scap_source_plugin.state = m_state;
	m_scap_source_plugin.name = m_name.c_str();
	m_scap_source_plugin.id = m_id;
	m_scap_source_plugin.open = m_handle->api.open;
	m_scap_source_plugin.close = m_handle->api.close;
	m_scap_source_plugin.get_last_error = m_handle->api.get_last_error;
	m_scap_source_plugin.next_batch = m_handle->api.next_batch;
	return m_scap_source_plugin;
}

std::string sinsp_plugin::get_progress(uint32_t &progress_pct) const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	std::string ret;
	progress_pct = 0;

	if(!m_handle->api.get_progress || !m_scap_source_plugin.handle)
	{
		return ret;
	}

	uint32_t ppct;
	ret = str_from_alloc_charbuf(m_handle->api.get_progress(m_state, m_scap_source_plugin.handle, &ppct));

	progress_pct = ppct;

	return ret;
}

std::string sinsp_plugin::event_to_string(sinsp_evt* evt) const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	if (evt->get_type() != PPME_PLUGINEVENT_E || evt->get_param(0)->as<uint32_t>() != m_id)
	{
		throw sinsp_exception("can't format unknown non-plugin event to string");
	}

	string ret = "";
	auto datalen = evt->get_param(1)->m_len;
	auto data = (const uint8_t *) evt->get_param(1)->m_val;
	if (m_state && m_handle->api.event_to_string)
	{
		ss_plugin_event_input input;
		input.evt = (const ss_plugin_event*) evt->m_pevt;
		input.evtnum = evt->get_num();
		input.evtsrc = evt->get_source_name();
		ret = str_from_alloc_charbuf(m_handle->api.event_to_string(m_state, &input));
	}
	if (ret.empty())
	{
		ret += "datalen=";
		ret += std::to_string(datalen);
		ret += " data=";
		for (size_t i = 0; i < std::min(datalen, uint32_t(50)); ++i)
		{
			if (!std::isprint(data[i]))
			{
				ret += "<binary>";
				return ret;
			}
		}
		ret.append((char*) data, std::min(datalen, uint32_t(50)));
		if (datalen > 50)
		{
			ret += "...";
		}
	}
	return ret;
}

std::vector<sinsp_plugin::open_param> sinsp_plugin::list_open_params() const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	std::vector<sinsp_plugin::open_param> list;
	if(m_state && m_handle->api.list_open_params)
	{
		ss_plugin_rc rc;
		string jsonString = str_from_alloc_charbuf(m_handle->api.list_open_params(m_state, &rc));
		if (rc != SS_PLUGIN_SUCCESS)
		{
			throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params has error " + get_last_error());
		}

		if (jsonString.size() > 0)
		{
			Json::Value root;
			if(Json::Reader().parse(jsonString, root) == false || root.type() != Json::arrayValue)
			{
				throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params returned a non-array JSON");
			}
			for(Json::Value::ArrayIndex i = 0; i < root.size(); i++)
			{
				open_param param;
				param.value = root[i]["value"].asString();
				if(param.value == "")
				{
					throw sinsp_exception(string("error in plugin ") + name() + ": list_open_params has entry with no value");
				}
				param.desc = root[i]["desc"].asString();
				param.separator = root[i]["separator"].asString();
				list.push_back(param);
			}
		}
	}

	return list;
}

/** End of Event Source CAP **/

/** Field Extraction CAP **/

sinsp_filter_check* sinsp_plugin::new_filtercheck(std::shared_ptr<sinsp_plugin> plugin)
{
	return new sinsp_filter_check_plugin(plugin);
}

bool sinsp_plugin::extract_fields(sinsp_evt* evt, uint32_t num_fields, ss_plugin_extract_field *fields) const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	ss_plugin_event_input ev;
	ev.evt = (const ss_plugin_event*) evt->m_pevt;
	ev.evtnum = evt->get_num();
	ev.evtsrc = evt->get_source_name();

	ss_plugin_field_extract_input in;
	ss_plugin_table_reader_vtable_ext table_reader_ext;
	in.num_fields = num_fields;
	in.fields = fields;
	in.owner = (ss_plugin_owner_t *) this;
	in.get_owner_last_error = sinsp_plugin::get_owner_last_error;
	in.table_reader_ext = &table_reader_ext;
	sinsp_plugin::table_read_api(in.table_reader, table_reader_ext);
	return m_handle->api.extract_fields(m_state, &ev, &in) == SS_PLUGIN_SUCCESS;
}

/** End of Field Extraction CAP **/

/** Event Parsing CAP **/

bool sinsp_plugin::parse_event(sinsp_evt* evt) const
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	ss_plugin_event_input ev;
	ev.evt = (const ss_plugin_event*) evt->m_pevt;
	ev.evtnum = evt->get_num();
	ev.evtsrc = evt->get_source_name();

	ss_plugin_event_parse_input in;
	ss_plugin_table_reader_vtable_ext table_reader_ext;
	ss_plugin_table_writer_vtable_ext table_writer_ext;
	in.owner = (ss_plugin_owner_t *) this;
	in.get_owner_last_error = sinsp_plugin::get_owner_last_error;
	in.table_reader_ext = &table_reader_ext;
	in.table_writer_ext = &table_writer_ext;
	sinsp_plugin::table_read_api(in.table_reader, table_reader_ext);
	sinsp_plugin::table_write_api(in.table_writer, table_writer_ext);

	auto res = m_handle->api.parse_event(m_state, &ev, &in);
	return res == SS_PLUGIN_SUCCESS;
}

/** End of Event Parsing CAP **/

/** Async Events CAP **/

ss_plugin_rc sinsp_plugin::handle_plugin_async_event(ss_plugin_owner_t *o, const ss_plugin_event* e, char* err)
{
	// note: this function can be invoked from different plugin threads,
	// so we need to make sure that every variable we read is either constant
	// during the lifetime of those threads, or that it is atomic.
	auto p = static_cast<sinsp_plugin*>(o);
	auto handler = p->m_async_evt_handler.load();
	if (!(p->caps() & CAP_ASYNC))
	{
		if (err)
		{
			strlcpy(err, "plugin without async events cap used as async handler", PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}

	if (!handler)
	{
		if (err)
		{
			auto e = "async event sent with NULL handler: " + p->name();
			strlcpy(err, e.c_str(), PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}

	if (e->type != PPME_ASYNCEVENT_E || e->nparams != 3)
	{
		if (err)
		{
			auto e = "malformed async event produced by plugin: " + p->name();
			strlcpy(err, e.c_str(), PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}

	auto name = (const char*) ((uint8_t*) e + sizeof(ss_plugin_event) + 4+4+4+4);
	if (p->async_event_names().find(name) == p->async_event_names().end())
	{
		if (err)
		{
			auto e = "incompatible async event '" + std::string(name)
				+ "' produced by plugin: " + p->name();
			strlcpy(err, e.c_str(), PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}

	try
	{
		auto evt = std::unique_ptr<sinsp_evt>(new sinsp_evt());
		ASSERT(evt->m_pevt_storage == nullptr);
		evt->m_pevt_storage = new char[e->len];
		memcpy(evt->m_pevt_storage, e, e->len);
		evt->m_cpuid = 0;
		evt->m_evtnum = 0;
		evt->m_pevt = (scap_evt *) evt->m_pevt_storage;
		evt->init();
		// note: plugin ID and timestamp will be set by the inspector
		(*handler)(*p, std::move(evt));
	}
	catch (const std::exception& _e)
	{
		if (err)
		{
			strlcpy(err, _e.what(), PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}
	catch (...)
	{
		if (err)
		{
			strlcpy(err, "unknwon error in pushing async event", PLUGIN_MAX_ERRLEN);
		}
		return SS_PLUGIN_FAILURE;
	}

	return SS_PLUGIN_SUCCESS;
}

bool sinsp_plugin::set_async_event_handler(async_event_handler_t handler)
{
	if (!m_inited)
	{
		throw sinsp_exception(std::string(s_not_init_err) + ": " + m_name);
	}

	// note: setting the handler before invoking the plugin's function,
	// so that it can be visible to other threads that can potentially
	// be spawned by the plugin for producing async events.
	// In the same way, we need to reset it to NULL after the function
	// returns, to allow any potential extra threads to finish before
	// changing the value. In any case, we make the handler function
	// atomic in case plugin developers fail in stopping async threads.
	//
	// As for the atomic updates to m_async_evt_handler, the possible cases
	// depend on the current handler (CH) and new handler (NH):
	//   - CH null, NH null: the handler value is already null, no updates needed.
	//   - CH null, NH not-null: the handler value must be updated before setting
	//     it to the plugin, so that any newly-spawned thread in the plugin
	//     can see the new value. In case of failure, we should set the handler
	//     to its previous value.
	//   - CH not-null, NH null: the handler value must be updated after setting
	//     it to the plugin, so that any already-running thread in the plugin
	//     can be stopped before setting the handler to null. In case of success,
	//     we can set the handler value to null.
	//   - CH not-null, NH not-null: not supported for now, need to reset
	//     the current handler to null before setting a new one.

	auto cur_handler = m_async_evt_handler.load();
	auto new_handler = (handler != nullptr) ? new async_event_handler_t(handler) : nullptr;

	if (new_handler != nullptr)
	{
		if (cur_handler != nullptr)
		{
			delete new_handler;
			throw sinsp_exception("must reset the async event handler before setting a new one");
		}
		m_async_evt_handler.store(new_handler);
	}

	auto callback = (handler != nullptr) ? sinsp_plugin::handle_plugin_async_event : NULL;
	auto rc = m_handle->api.set_async_event_handler(m_state, this, callback);

	if (cur_handler == nullptr && new_handler != nullptr)
	{
		if (rc != SS_PLUGIN_SUCCESS)
		{
			// new handler rejected, restore current one
			delete new_handler;
			m_async_evt_handler.store(cur_handler);
		}
	}

	if (cur_handler != nullptr && new_handler == nullptr)
	{
		if (rc == SS_PLUGIN_SUCCESS)
		{
			// new handler accepted, delete current one
			delete cur_handler;
			m_async_evt_handler.store(new_handler);
		}
	}

	return rc == SS_PLUGIN_SUCCESS;
}
