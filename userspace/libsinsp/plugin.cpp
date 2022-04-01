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

#ifndef _WIN32
#include <dlfcn.h>
// This makes inttypes.h define PRIu32 (ISO C99 plus older g++ versions)
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <sstream>
#endif
#include <numeric>
#include <json/json.h>
#include <valijson/adapters/jsoncpp_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "plugin.h"

using namespace std;

// Used below--set a std::string from the provided allocated charbuf and free() the charbuf.
static std::string str_from_alloc_charbuf(const char* charbuf)
{
	std::string str;

	if(charbuf != NULL)
	{
		str = charbuf;
	}

	return str;
}

///////////////////////////////////////////////////////////////////////////////
// source_plugin filter check implementation
// This class implements a dynamic filter check that acts as a bridge to the
// plugin simplified field extraction implementations
///////////////////////////////////////////////////////////////////////////////

static std::set<uint16_t> s_all_plugin_event_types = {PPME_PLUGINEVENT_E};


class sinsp_filter_check_plugin : public sinsp_filter_check
{
public:
	sinsp_filter_check_plugin()
	{
		m_info.m_name = "plugin";
		m_info.m_fields = NULL;
		m_info.m_nfields = 0;
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugin(std::shared_ptr<sinsp_plugin> plugin)
	{
		m_info.m_name = plugin->name() + string(" (plugin)");
		if (!(plugin->caps() & CAP_EXTRACTION))
		{
			throw sinsp_exception("Creating a sinsp_filter_check_plugin with a non extraction-capable plugin.\n");
		}

		m_eplugin = static_cast<sinsp_plugin_cap_extraction*>(plugin.get());
		m_info.m_fields = m_eplugin->fields();
		m_info.m_nfields = m_eplugin->nfields();
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugin(const sinsp_filter_check_plugin &p)
	{
		m_eplugin = p.m_eplugin;
		m_info = p.m_info;
	}

	virtual ~sinsp_filter_check_plugin()
	{
	}

	const std::set<uint16_t> &evttypes()
	{
		return s_all_plugin_event_types;
	}

	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
	{
		int32_t res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);

		m_argstr.clear();

		if(res != -1)
		{
			m_arg_present = false;
			m_arg_key = NULL;
			m_arg_index = 0;
			// Read from str to the end-of-string, or first space
			string val(str);
			size_t val_end = val.find_first_of(' ', 0);
			if(val_end != string::npos)
			{
				val = val.substr(0, val_end);
			}

			size_t pos1 = val.find_first_of('[', 0);
			if(pos1 != string::npos)
			{
				size_t argstart = pos1 + 1;
				if(argstart < val.size())
				{
					m_argstr = val.substr(argstart);
					size_t pos2 = m_argstr.find_first_of(']', 0);
					if(pos2 != string::npos)
					{
						m_argstr = m_argstr.substr(0, pos2);
						if (!(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_ALLOWED
								|| m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED))
						{
							throw sinsp_exception(string("filter ") + string(str) + string(" ")
								+ m_field->m_name + string(" does not allow nor require an argument but one is provided: " + m_argstr));
						}

						m_arg_present = true;

						if(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_INDEX)
						{
							extract_arg_index(str);
						}

						if(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_KEY)
						{
							extract_arg_key();
						}

						return pos1 + pos2 + 2;
					}
				}
				throw sinsp_exception(string("filter ") + string(str) + string(" ") + m_field->m_name + string(" has a badly-formatted argument"));
			}
			if (m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED)
			{
				throw sinsp_exception(string("filter ") + string(str) + string(" ") + m_field->m_name + string(" requires an argument but none provided"));
			}
		}

		return res;
	}

	sinsp_filter_check* allocate_new()
	{
		return new sinsp_filter_check_plugin(*this);
	}

	bool extract(sinsp_evt *evt, OUT vector<extract_value_t>& values, bool sanitize_strings = true)
	{
		//
		// Reject any event that is not generated by a plugin
		//
		if(evt->get_type() != PPME_PLUGINEVENT_E)
		{
			return false;
		}

		sinsp_evt_param *parinfo;

		// Check that the current plugin is source compatible with the event source plugin
		parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int32_t));
		uint32_t pgid = *(int32_t *) parinfo->m_val;

		// We know that plugin has source capabilities because it has an id and is sending events
		std::shared_ptr<sinsp_plugin> plugin = m_inspector->get_plugin_by_id(pgid);
		if (!plugin || !m_eplugin->source_compatible(plugin->event_source()))
		{
			return false;
		}

		//
		// Get the event payload
		//
		parinfo = evt->get_param(1);

		ppm_param_type type = m_info.m_fields[m_field_id].m_type;

		ss_plugin_event pevt;
		pevt.evtnum = evt->get_num();
		pevt.data = (uint8_t *) parinfo->m_val;
		pevt.datalen = parinfo->m_len;
		pevt.ts = evt->get_ts();

		uint32_t num_fields = 1;
		ss_plugin_extract_field efield;
		efield.field_id = m_field_id;
		efield.field = m_info.m_fields[m_field_id].m_name;
		efield.arg_key = m_arg_key;
		efield.arg_index = m_arg_index;
		efield.arg_present = m_arg_present;
		efield.ftype = type;
		efield.flist = m_info.m_fields[m_field_id].m_flags & EPF_IS_LIST;
		if (!m_eplugin->extract_fields(pevt, num_fields, &efield) || efield.res_len == 0)
		{
			return false;
		}

		values.clear();
		switch(type)
		{
			case PT_CHARBUF:
			{
				if (m_res_str_storage.size() < efield.res_len)
				{
					m_res_str_storage.resize(efield.res_len);
				}
				break;
			}
			case PT_UINT64:
			{
				if (m_res_u64_storage.size() < efield.res_len)
				{
					m_res_u64_storage.resize(efield.res_len);
				}
				break;
			}
			default:
				break;
		}
		for (uint32_t i = 0; i < efield.res_len; ++i)
		{
			extract_value_t res;
			switch(type)
			{
				case PT_CHARBUF:
				{
					m_res_str_storage[i] = efield.res.str[i];
					res.len = m_res_str_storage[i].size();
					res.ptr = (uint8_t*) m_res_str_storage[i].c_str();
					break;
				}
				case PT_UINT64:
				{
					m_res_u64_storage[i] = efield.res.u64[i];
					res.len = sizeof(uint64_t);
					res.ptr = (uint8_t*) &m_res_u64_storage[i];
					break;
				}
				default:
					ASSERT(false);
					throw sinsp_exception("plugin extract error: unsupported field type " + to_string(type));
					break;
			}
			values.push_back(res);
		}

		return true;
	}

	string m_argstr;
	char* m_arg_key;
	uint64_t m_arg_index;
	bool m_arg_present;

	vector<std::string> m_res_str_storage;
	vector<uint64_t> m_res_u64_storage;

private:
	sinsp_plugin_cap_extraction *m_eplugin;

	// extract_arg_index() extracts a valid index from the argument if 
	// format is valid, otherwise it throws an exception.
	// `full_field_name` has the format "field[argument]" and it is necessary
	// to throw an exception.
	void extract_arg_index(const char* full_field_name)
	{
		int length = m_argstr.length();
		bool is_valid = true;
		std::string message = "";
		
		// Please note that numbers starting with `0` (`01`, `02`, `0003`, ...) are not indexes. 
		if(length == 0 || (length > 1 && m_argstr[0] == '0'))
		{
			is_valid = false;
			message = " has an invalid index argument starting with 0: ";
		}
		
		// The index must be composed only by digits (0-9).
		for(int j = 0; j < length; j++)
		{
			if(!isdigit(m_argstr[j]))
			{
				is_valid = false;
				message = " has an invalid index argument not composed only by digits: ";
				break;
			}
		}

		// If the argument is valid we can convert it with `stoul`.
		// Please note that `stoul` alone is not enough, since it also consider as valid 
		// strings like "0123 i'm a number", converting them into '0123'. This is why in the 
		// previous step we check that every character is a digit.
		if(is_valid)
		{
			try
			{
				m_arg_index = std::stoul(m_argstr);
				return;
			} 
			catch(...)
			{
				message = " has an invalid index argument not representable on 64 bit: ";
			}
		}
		throw sinsp_exception(string("filter ") + string(full_field_name) + string(" ")
										+ m_field->m_name + message + m_argstr);
	}

	// extract_arg_key() extracts a valid string from the argument. If we pass
	// a numeric argument, it will be converted to string. 
	void extract_arg_key()
	{
		m_arg_key = (char*)m_argstr.c_str();
	}
};

///////////////////////////////////////////////////////////////////////////////
// sinsp_plugin implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_plugin::version::version()
	: m_valid(false)
{
}

sinsp_plugin::version::version(const std::string &version_str)
	: m_valid(false)
{
	m_valid = (sscanf(version_str.c_str(), "%" PRIu32 ".%" PRIu32 ".%" PRIu32,
			  &m_version_major, &m_version_minor, &m_version_patch) == 3);
}

sinsp_plugin::version::~version()
{
}

std::string sinsp_plugin::version::as_string() const
{
	return std::to_string(m_version_major) + "." +
		std::to_string(m_version_minor) + "." +
		std::to_string(m_version_patch);
}

bool sinsp_plugin::version::check(version &requested) const
{
	if(this->m_version_major != requested.m_version_major)
	{
		// major numbers disagree
		return false;
	}

	if(this->m_version_minor < requested.m_version_minor)
	{
		// framework's minor version is < requested one
		return false;
	}
	if(this->m_version_minor == requested.m_version_minor && this->m_version_patch < requested.m_version_patch)
	{
		// framework's patch level is < requested one
		return false;
	}
	return true;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create_plugin(string &filepath,
														  const char* config,
														  std::string &errstr,
														  filter_check_list &available_checks)
{
	std::shared_ptr<sinsp_plugin> ret;

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
		return ret;
	}
#endif

	auto plugin = new sinsp_plugin(handle);
	if (!plugin->resolve_dylib_symbols(errstr))
	{
		return ret;
	}

	// Before doing anything else, check the required api
	// version. If it doesn't match, return an error.
	// This is always valid
	version frameworkVers(PLUGIN_API_VERSION_STR);
	if(!frameworkVers.check(plugin->m_required_api_version))
	{
		errstr = string("Unsupported plugin required api version ") + plugin->m_required_api_version.as_string();
		return ret;
	}

	if (plugin->m_caps == 0)
	{
		errstr = "Desired plugin has no capability.";
		delete plugin;
		return ret;
	}

	errstr = "";
	ret.reset(plugin);

	// Initialize the plugin
	std::string conf = str_from_alloc_charbuf(config);
	ret->validate_init_config(conf);
	if (!ret->init(conf.c_str()))
	{
		errstr = string("Could not initialize plugin: " + ret->get_last_error());
		ret = NULL;
	}

	// Only add the gen_event filter checks for plugins with event sourcing capabilities.
	// Plugins woth extractor capabilities don't deal with event
	// timestamps/etc and don't need these checks (They were
	// probably added by the associated source plugins anyway).
	if(ret->caps() & CAP_SOURCING)
	{
		auto evt_filtercheck = new sinsp_filter_check_gen_event();
		available_checks.add_filter_check(evt_filtercheck);
	}

	if (ret->caps() & CAP_EXTRACTION)
	{
		auto filtercheck = new sinsp_filter_check_plugin(ret);
		available_checks.add_filter_check(filtercheck);
	}

	return ret;
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

ss_plugin_caps sinsp_plugin::caps()
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
	: m_handle(handle)
{
	memset(&m_api, 0, sizeof(m_api));
	m_id = -1;
	m_nfields = 0;
}

sinsp_plugin::~sinsp_plugin()
{
	destroy();
	destroy_handle(m_handle);
}

bool sinsp_plugin::init(const char *config)
{
	if (!m_api.init)
	{
		return false;
	}

	ss_plugin_rc rc;

	ss_plugin_t *state = m_api.init(config, &rc);
	if (state != NULL)
	{
		// Plugins can return a state even if the result code is
		// SS_PLUGIN_FAILURE, which can be useful to set an init
		// error that can later be retrieved through get_last_error().
		m_state = state;
	}

	return rc == SS_PLUGIN_SUCCESS;
}

void sinsp_plugin::destroy()
{
	if(m_state && m_api.destroy)
	{
		m_api.destroy(m_state);
		m_state = NULL;
	}
}

std::string sinsp_plugin::get_last_error()
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

const std::string &sinsp_plugin::name()
{
	return m_name;
}

const std::string &sinsp_plugin::description()
{
	return m_description;
}

const std::string &sinsp_plugin::contact()
{
	return m_contact;
}

const sinsp_plugin::version &sinsp_plugin::plugin_version()
{
	return m_plugin_version;
}

const sinsp_plugin::version &sinsp_plugin::required_api_version()
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
	/** Common plugin API **/
	// Some functions are required and return false if not found.
	if((*(void **) (&(m_api.get_required_api_version)) = getsym("plugin_get_required_api_version", errstr)) == NULL ||
	   (*(void **) (&(m_api.get_last_error)) = getsym("plugin_get_last_error", errstr)) == NULL ||
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
	m_plugin_version = sinsp_plugin::version(version_str);
	if(!m_plugin_version.m_valid)
	{
		errstr = string("Could not parse version string from ") + version_str;
		return false;
	}

	// The required api version was already checked in
	// create_plugin to be valid and compatible. This just saves it for info/debugging.
	version_str = str_from_alloc_charbuf(m_api.get_required_api_version());
	m_required_api_version = sinsp_plugin::version(version_str);
	if(!m_required_api_version.m_valid)
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

		filtercheck_field_info *fields = new filtercheck_field_info[root.size()];
		if (fields == NULL) {
			throw sinsp_exception(string("error in plugin ") + name() + ": could not allocate memory");
		}

		// Take ownership of the pointer right away so it can't be leaked.
		m_fields.reset(fields);
		m_nfields = root.size();

		for (Json::Value::ArrayIndex j = 0; j < root.size(); j++) {
			filtercheck_field_info &tf = m_fields.get()[j];
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

				if (jvIsList.asBool() == true) {
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

				for (Json::Value::ArrayIndex k = 0; k < jvProperties.size(); k++) {
					const Json::Value &prop = jvProperties[k];

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
		}

		if (m_api.get_extract_event_sources != NULL) {
			std::string esources = str_from_alloc_charbuf(m_api.get_extract_event_sources());

			if (esources.length() == 0)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources returned an empty string");
			}

			Json::Value root;
			if (Json::Reader().parse(esources, root) == false || root.type() != Json::arrayValue)
			{
				throw sinsp_exception(string("error in plugin ") + name() +
				                      ": get_extract_event_sources did not return a json array");
			}

			for (Json::Value::ArrayIndex j = 0; j < root.size(); j++)
			{
				if (!root[j].isConvertibleTo(Json::stringValue))
				{
					throw sinsp_exception(string("error in plugin ") + name() +
					                      ": get_extract_event_sources did not return a json array");
				}

				m_extract_event_sources.insert(root[j].asString());
			}
		}
	}
	else
	{
		m_api.get_fields = NULL;
		m_api.extract_fields = NULL;
	}
	/** **/

	return true;
}

std::string sinsp_plugin::get_init_schema(ss_plugin_schema_type& schema_type)
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
	if (schema.size() > 0 && schema_type != SS_PLUGIN_SCHEMA_NONE)
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

void sinsp_plugin::destroy_handle(sinsp_plugin_handle handle) {
#ifdef _WIN32
	FreeLibrary(handle);
#else
	dlclose(handle);
#endif
}

/** Event Source CAP **/

scap_source_plugin sinsp_plugin::sp;

scap_source_plugin *sinsp_plugin::as_scap_source()
{
	if (!(caps() & CAP_SOURCING))
	{
		throw sinsp_exception("Can't create scap_source_plugin from a plugin without CAP_SOURCING capability.");
	}

	sp.state = m_state;
	sp.name = m_name.c_str();
	sp.id = m_id;

	sp.open = m_api.open;
	sp.close = m_api.close;
	sp.get_last_error = m_api.get_last_error;
	sp.next_batch = m_api.next_batch;
	return &sp;
}

uint32_t sinsp_plugin::id()
{
	return m_id;
}

const std::string &sinsp_plugin::event_source()
{
	return m_event_source;
}

std::string sinsp_plugin::get_progress(uint32_t &progress_pct)
{
	std::string ret;
	progress_pct = 0;

	if(!m_api.get_progress || !sp.handle)
	{
		return ret;
	}

	uint32_t ppct;
	ret = str_from_alloc_charbuf(m_api.get_progress(m_state, sp.handle, &ppct));

	progress_pct = ppct;

	return ret;
}

std::string sinsp_plugin::event_to_string(const uint8_t *data, uint32_t datalen)
{
	std::string ret = "<NA>";

	if (!m_state || !m_api.event_to_string)
	{
		return ret;
	}

	ret = str_from_alloc_charbuf(m_api.event_to_string(m_state, data, datalen));

	return ret;
}

std::vector<sinsp_plugin_cap_sourcing::open_param> sinsp_plugin::list_open_params()
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
				list.push_back(param);
			}
		}
	}

	return list;
}

/** End of Event Source CAP **/

/** Extractor CAP **/

const std::set<std::string> &sinsp_plugin::extract_event_sources()
{
	return m_extract_event_sources;
}

bool sinsp_plugin::source_compatible(const std::string &source)
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

const filtercheck_field_info *sinsp_plugin::fields()
{
	return m_fields.get();
}

uint32_t sinsp_plugin::nfields()
{
	return m_nfields;
}

bool sinsp_plugin::extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	if(!m_state)
	{
		return false;
	}

	return m_api.extract_fields(m_state, &evt, num_fields, fields) == SS_PLUGIN_SUCCESS;
}

/** **/