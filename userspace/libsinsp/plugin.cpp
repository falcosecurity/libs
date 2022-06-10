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

#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <sstream>
#include <numeric>
#include <json/json.h>
#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

#include "sinsp_int.h"
#include "sinsp_exception.h"
#include "plugin.h"
#include "plugin_filtercheck.h"

using namespace std;

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

std::shared_ptr<sinsp_plugin> sinsp_plugin::create(
	const std::string &filepath,
	std::string &errstr)
{
#ifdef _WIN32
	sinsp_plugin_handle handle = LoadLibrary(filepath.c_str());

	if(handle == NULL)
	{
		errstr = "error loading plugin " + filepath + ": ";
		DWORD flg = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
		LPTSTR msg_buf = 0;
		if(FormatMessageA(flg, 0, GetLastError(), 0, (LPTSTR)&msg_buf, 0, NULL))
		if(msg_buf)
		{
			errstr.append(msg_buf, strlen(msg_buf));
			LocalFree(msg_buf);
		}
		return ret;
	}
#else
	sinsp_plugin_handle handle = dlopen(filepath.c_str(), RTLD_LAZY);

	if(handle == NULL)
	{
		errstr = "error loading plugin " + filepath + ": " + dlerror();
		return nullptr;
	}
#endif

	std::shared_ptr<sinsp_plugin> plugin(new sinsp_plugin(handle));
	if (!plugin->resolve_dylib_symbols(errstr))
	{
		return nullptr;
	}
	if (plugin->m_caps == 0)
	{
		errstr = "loaded plugin implements no capability: " + filepath;
		return nullptr;
	}
	return plugin;
}

void* sinsp_plugin::getsym(const char* name, std::string &errstr)
{
	void *ret;

#ifdef _WIN32
	ret = GetProcAddress(m_handle, name);
#else
	ret = dlsym(m_handle, name);
#endif

	if(ret == NULL)
	{
		errstr = string("Dynamic library symbol ") + name + " not present";
	} else {
		errstr = "";
	}

	return ret;
}

ss_plugin_caps sinsp_plugin::caps() const
{
	return m_caps;
}

bool sinsp_plugin::is_plugin_loaded(std::string &filepath)
{
#ifdef _WIN32
	/*
	 * LoadLibrary maps the module into the address space of the calling process, if necessary,
	 * and increments the modules reference count, if it is already mapped.
	 * GetModuleHandle, however, returns the handle to a mapped module
	 * without incrementing its reference count.
	 *
	 * This returns an HMODULE indeed, but they are the same thing
	 */
	sinsp_plugin_handle handle = (HINSTANCE)GetModuleHandle(filepath.c_str());
#else
	/*
	 * RTLD_NOLOAD (since glibc 2.2)
	 *	Don't load the shared object. This can be used to test if
	 *	the object is already resident (dlopen() returns NULL if
	 *	it is not, or the object's handle if it is resident).
	 *	This does not increment dlobject reference count.
	 */
	sinsp_plugin_handle handle = dlopen(filepath.c_str(), RTLD_LAZY | RTLD_NOLOAD);
#endif
	return handle != NULL;
}

sinsp_plugin::sinsp_plugin(sinsp_plugin_handle handle)
	: m_state(nullptr), m_caps((ss_plugin_caps) 0), m_handle(handle)
{
	memset(&m_api, 0, sizeof(m_api));
	m_id = -1;
	m_fields.clear();
}

sinsp_plugin::~sinsp_plugin()
{
	destroy();
	destroy_handle(m_handle);
	m_fields.clear();
}

bool sinsp_plugin::init(const std::string &config, std::string &errstr)
{
	if (!m_api.init)
	{
		errstr = string("init api symbol not found");
		return false;
	}

	ss_plugin_rc rc;
	std::string conf = config;
	validate_init_config(conf);

	ss_plugin_t *state = m_api.init(conf.c_str(), &rc);
	if (state != NULL)
	{
		// Plugins can return a state even if the result code is
		// SS_PLUGIN_FAILURE, which can be useful to set an init
		// error that can later be retrieved through get_last_error().
		m_state = state;
	}

	if (rc != SS_PLUGIN_SUCCESS)
	{
		errstr = "Could not initialize plugin: " + get_last_error();
		return false;
	}

	return true;
}

void sinsp_plugin::destroy()
{
	if(m_state && m_api.destroy)
	{
		m_api.destroy(m_state);
		m_state = NULL;
	}
}

std::string sinsp_plugin::get_last_error() const
{
	std::string ret;

	if(m_state)
	{
		ret = str_from_alloc_charbuf(m_api.get_last_error(m_state));
	}
	else
	{
		ret = "Plugin handle or get_last_error function not defined";
	}

	return ret;
}

const std::string &sinsp_plugin::name() const
{
	return m_name;
}

const std::string &sinsp_plugin::description() const
{
	return m_description;
}

const std::string &sinsp_plugin::contact() const
{
	return m_contact;
}

const sinsp_version &sinsp_plugin::plugin_version() const
{
	return m_plugin_version;
}

const sinsp_version &sinsp_plugin::required_api_version() const
{
	return m_required_api_version;
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

bool sinsp_plugin::resolve_dylib_symbols(std::string &errstr)
{

	if ((*(void **) (&(m_api.get_required_api_version)) = getsym("plugin_get_required_api_version", errstr)) == NULL)
	{
		errstr = string("Could not resolve plugin_get_required_api_version function");
		return false;
	}

	std::string req_version_str = str_from_alloc_charbuf(m_api.get_required_api_version());
	m_required_api_version = sinsp_version(req_version_str);
	if(!m_required_api_version.m_valid)
	{
		errstr = string("Could not parse version string from ") + req_version_str;
		return false;
	}
	// Before doing anything else, check the required api
	// version. If it doesn't match, return an error.
	// This is always valid
	sinsp_version frameworkVers(PLUGIN_API_VERSION_STR);
	if(!frameworkVers.check(m_required_api_version))
	{
		errstr = string("Unsupported plugin required api version ") + m_required_api_version.as_string();
		return false;
	}

	/** Common plugin API **/
	// Some functions are required and return false if not found.
	if((*(void **) (&(m_api.get_last_error)) = getsym("plugin_get_last_error", errstr)) == NULL ||
	   (*(void **) (&(m_api.get_name)) = getsym("plugin_get_name", errstr)) == NULL ||
	   (*(void **) (&(m_api.get_description)) = getsym("plugin_get_description", errstr)) == NULL ||
	   (*(void **) (&(m_api.get_contact)) = getsym("plugin_get_contact", errstr)) == NULL ||
	   (*(void **) (&(m_api.get_version)) = getsym("plugin_get_version", errstr)) == NULL)
	{
		return false;
	}

	// Others are not and the values will be checked when needed.
	(*(void **) (&m_api.init)) = getsym("plugin_init", errstr);
	(*(void **) (&m_api.destroy)) = getsym("plugin_destroy", errstr);
	(*(void **) (&m_api.get_init_schema)) = getsym("plugin_get_init_schema", errstr);

	m_name = str_from_alloc_charbuf(m_api.get_name());
	m_description = str_from_alloc_charbuf(m_api.get_description());
	m_contact = str_from_alloc_charbuf(m_api.get_contact());

	std::string version_str = str_from_alloc_charbuf(m_api.get_version());
	m_plugin_version = sinsp_version(version_str);
	if(!m_plugin_version.m_valid)
	{
		errstr = string("Could not parse version string from ") + version_str;
		return false;
	}
	/** **/

	/** Sourcing API **/
	if((*(void **) (&(m_api.get_id)) = getsym("plugin_get_id", errstr)) != NULL &&
	   (*(void **) (&(m_api.get_event_source)) = getsym("plugin_get_event_source", errstr)) != NULL &&
	   (*(void **) (&(m_api.open)) = getsym("plugin_open", errstr)) != NULL &&
	   (*(void **) (&(m_api.close)) = getsym("plugin_close", errstr)) != NULL &&
	   (*(void **) (&(m_api.next_batch)) = getsym("plugin_next_batch", errstr)) != NULL)
	{
		m_caps = (ss_plugin_caps) ((uint32_t) m_caps | (uint32_t) CAP_SOURCING);

		(*(void **) (&m_api.get_progress)) = getsym("plugin_get_progress", errstr);
		(*(void **) (&m_api.list_open_params)) = getsym("plugin_list_open_params", errstr);
		(*(void **) (&m_api.event_to_string)) = getsym("plugin_event_to_string", errstr);

		m_id = m_api.get_id();
		m_event_source = str_from_alloc_charbuf(m_api.get_event_source());
	}
	else
	{
		m_api.get_id = NULL;
		m_api.get_event_source = NULL;
		m_api.open = NULL;
		m_api.close = NULL;
		m_api.next_batch = NULL;
	}
	/** **/

	/** Extraction API **/
	if((*(void **) (&(m_api.get_fields)) = getsym("plugin_get_fields", errstr)) != NULL &&
	   (*(void **) (&(m_api.extract_fields)) = getsym("plugin_extract_fields", errstr)) != NULL) {

		m_caps = (ss_plugin_caps) ((uint32_t) m_caps | (uint32_t) CAP_EXTRACTION);

		(*(void **) (&m_api.get_extract_event_sources)) = getsym("plugin_get_extract_event_sources", errstr);


		//
		// If filter fields are exported by the plugin, get the json from get_fields(),
		// parse it, create our list of fields, and create a filtercheck from the fields.
		//
		const char *sfields = m_api.get_fields();
		if (sfields == NULL) {
			throw sinsp_exception(
					string("error in plugin ") + name() + ": get_fields returned a null string");
		}
		string json(sfields);
		SINSP_DEBUG("Parsing Fields JSON=%s", json.c_str());
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

			if (ftype == "string") {
				tf.m_type = PT_CHARBUF;
			} else if (ftype == "uint64") {
				tf.m_type = PT_UINT64;
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

		if (m_api.get_extract_event_sources != NULL) {
			std::string esources = str_from_alloc_charbuf(m_api.get_extract_event_sources());

			if (esources.length() == 0)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources returned an empty string");
			}

			Json::Value root;
			if (!Json::Reader().parse(esources, root) || root.type() != Json::arrayValue)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources did not return a json array");
			}

			for (const auto & j : root)
			{
				if (!j.isConvertibleTo(Json::stringValue))
				{
					throw sinsp_exception(string("error in plugin ") + name() +
					                      ": get_extract_event_sources did not return a json array");
				}

				m_extract_event_sources.insert(j.asString());
			}
		}

		// A plugin with source capability
		// must extract event from its source
		if (m_caps & CAP_SOURCING)
		{
			m_extract_event_sources.insert(m_event_source);
		}
	}
	else
	{
		m_api.get_fields = NULL;
		m_api.extract_fields = NULL;
	}

	return true;
}

std::string sinsp_plugin::get_init_schema(ss_plugin_schema_type& schema_type) const
{
	schema_type = SS_PLUGIN_SCHEMA_NONE;
	if (m_api.get_init_schema != NULL)
	{
		return str_from_alloc_charbuf(m_api.get_init_schema(&schema_type));
	}
	return std::string("");
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

void sinsp_plugin::destroy_handle(sinsp_plugin_handle handle)
{
	if (handle)
	{
#ifdef _WIN32
		FreeLibrary(handle);
#else
		dlclose(handle);
#endif
	}
}

/** Event Source CAP **/

scap_source_plugin& sinsp_plugin::as_scap_source()
{
	if (!(caps() & CAP_SOURCING))
	{
		throw sinsp_exception("Can't create scap_source_plugin from a plugin without CAP_SOURCING capability.");
	}

	m_scap_source_plugin.state = m_state;
	m_scap_source_plugin.name = m_name.c_str();
	m_scap_source_plugin.id = m_id;
	m_scap_source_plugin.open = m_api.open;
	m_scap_source_plugin.close = m_api.close;
	m_scap_source_plugin.get_last_error = m_api.get_last_error;
	m_scap_source_plugin.next_batch = m_api.next_batch;
	return m_scap_source_plugin;
}

uint32_t sinsp_plugin::id() const
{
	return m_id;
}

const std::string &sinsp_plugin::event_source() const
{
	return m_event_source;
}

std::string sinsp_plugin::get_progress(uint32_t &progress_pct) const
{
	std::string ret;
	progress_pct = 0;

	if(!m_api.get_progress || !m_scap_source_plugin.handle)
	{
		return ret;
	}

	uint32_t ppct;
	ret = str_from_alloc_charbuf(m_api.get_progress(m_state, m_scap_source_plugin.handle, &ppct));

	progress_pct = ppct;

	return ret;
}

std::string sinsp_plugin::event_to_string(sinsp_evt* evt) const
{
	string ret = "";
	auto datalen = evt->get_param(1)->m_len;
	auto data = (const uint8_t *) evt->get_param(1)->m_val;
	if (m_state && m_api.event_to_string)
	{
		ss_plugin_event pevt;
		pevt.evtnum = evt->get_num();
		pevt.data = data;
		pevt.datalen = datalen;
		pevt.ts = evt->get_ts();
		ret = str_from_alloc_charbuf(m_api.event_to_string(m_state, &pevt));
	}
	if (ret.empty())
	{
		ret += "datalen=";
		ret += std::to_string(datalen);
		ret += " data=";
		for (size_t i = 0; i < MIN(datalen, 50); ++i)
		{
			if (!std::isprint(data[i]))
			{
				ret += "<binary>";
				return ret;
			}
		}
		ret.append((char*) data, MIN(datalen, 50));
		if (datalen > 50)
		{
			ret += "...";
		}
	}
	return ret;
}

std::vector<sinsp_plugin_cap_sourcing::open_param> sinsp_plugin::list_open_params() const
{
	std::vector<sinsp_plugin_cap_sourcing::open_param> list;
	if(m_state && m_api.list_open_params)
	{
		ss_plugin_rc rc;
		string jsonString = str_from_alloc_charbuf(m_api.list_open_params(m_state, &rc));
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

/** Extractor CAP **/

const std::set<std::string> &sinsp_plugin::extract_event_sources() const
{
	return m_extract_event_sources;
}

const std::vector<filtercheck_field_info>& sinsp_plugin::fields() const
{
	return m_fields;
}

sinsp_filter_check* sinsp_plugin::new_filtercheck(std::shared_ptr<sinsp_plugin> plugin)
{
	return new sinsp_filter_check_plugin(plugin);
}

bool sinsp_plugin::extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const
{
	if(!m_state)
	{
		return false;
	}

	return m_api.extract_fields(m_state, &evt, num_fields, fields) == SS_PLUGIN_SUCCESS;
}

bool sinsp_plugin::is_source_compatible(const std::string &source) const
{
	if (m_extract_event_sources.size() == 0)
	{
		if (m_caps & CAP_SOURCING)
		{
			//
			// If this is a plugin with event sourcing capabilities, reject events that have
			// not been generated by a plugin with this id specifically.
			//
			return source == m_event_source;
		}
		return true;
	}
	return m_extract_event_sources.find(source) != m_extract_event_sources.end();
}

/** **/