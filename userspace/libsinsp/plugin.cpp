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
#include <inttypes.h>
#include <string.h>
#include <vector>
#include <sstream>
#endif
#include <json/json.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "plugin.h"

#include <third-party/tinydir.h>

using namespace std;

extern sinsp_filter_check_list g_filterlist;

///////////////////////////////////////////////////////////////////////////////
// source_plugin filter check implementation
// This class implements a dynamic filter check that acts as a bridge to the
// plugin simplified field extraction implementations
///////////////////////////////////////////////////////////////////////////////

const filtercheck_field_info sinsp_filter_check_plugininfo_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.pluginname", "if the event comes from a plugin, the name of the plugin that generated it."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.plugininfo", "if the event comes from a plugin, a summary of the event as formatted by the plugin."},
};

class sinsp_filter_check_plugininfo : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PLUGINNAME = 0,
		TYPE_PLUGININFO = 1,
	};

	sinsp_filter_check_plugininfo()
	{
		m_info.m_name = "plugininfo";
		m_info.m_fields = sinsp_filter_check_plugininfo_fields;
		m_info.m_nfields = sizeof(sinsp_filter_check_plugininfo_fields) / sizeof(sinsp_filter_check_plugininfo_fields[0]);
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugininfo(std::shared_ptr<sinsp_plugin> plugin)
		: m_plugin(plugin)
	{
		m_info.m_name = plugin->name() + string(" (plugininfo)");
		m_info.m_fields = sinsp_filter_check_plugininfo_fields;
		m_info.m_nfields = sizeof(sinsp_filter_check_plugininfo_fields) / sizeof(sinsp_filter_check_plugininfo_fields[0]);
		m_info.m_flags = filter_check_info::FL_NONE;
	}

	sinsp_filter_check_plugininfo(const sinsp_filter_check_plugininfo &p)
	{
		m_plugin = p.m_plugin;
		m_info = p.m_info;
	}

	virtual ~sinsp_filter_check_plugininfo()
	{
	}

	sinsp_filter_check* allocate_new()
	{
		return new sinsp_filter_check_plugininfo(*this);
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
	{
		//
		// Only extract if the event is a plugin event and if
		// this plugin is a source plugin.
		//
		if(!(evt->get_type() == PPME_PLUGINEVENT_E &&
		     m_plugin->type() == TYPE_SOURCE_PLUGIN))
		{
			return NULL;
		}

		//
		// Only extract if the event plugin id matches this plugin's id.
		//
		sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(m_plugin.get());

		sinsp_evt_param *parinfo;
		parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int32_t));
		uint32_t pgid = *(int32_t *)parinfo->m_val;
		if(pgid != splugin->id())
		{
			return NULL;
		}

		switch(m_field_id)
		{
		case TYPE_PLUGINNAME:
			m_strstorage = splugin->name();
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
			break;
		case TYPE_PLUGININFO:
			parinfo = evt->get_param(1);
			m_strstorage = splugin->event_to_string((const uint8_t *) parinfo->m_val, parinfo->m_len);
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
		default:
			return NULL;
		}

		return NULL;
	}

	std::string m_strstorage;

	std::shared_ptr<sinsp_plugin> m_plugin;
};

class sinsp_filter_check_plugin : public sinsp_filter_check
{
public:
	sinsp_filter_check_plugin()
	{
		m_info.m_name = "plugin";
		m_info.m_fields = NULL;
		m_info.m_nfields = 0;
		m_info.m_flags = filter_check_info::FL_NONE;
		m_cnt = 0;
	}

	sinsp_filter_check_plugin(std::shared_ptr<sinsp_plugin> plugin)
		: m_plugin(plugin)
	{
		m_info.m_name = plugin->name() + string(" (plugin)");
		m_info.m_fields = plugin->fields();
		m_info.m_nfields = plugin->nfields();
		m_info.m_flags = filter_check_info::FL_NONE;
		m_cnt = 0;
	}

	sinsp_filter_check_plugin(const sinsp_filter_check_plugin &p)
	{
		m_plugin = p.m_plugin;
		m_info = p.m_info;
	}

	virtual ~sinsp_filter_check_plugin()
	{
	}

	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
	{
		int32_t res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);

		if(res != -1)
		{
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
					m_argstr = m_argstr.substr(0, pos2);
					m_arg = (char*)m_argstr.c_str();
					return pos1 + pos2 + 2;
				}
			}
		}

		return res;
	}

	sinsp_filter_check* allocate_new()
	{
		return new sinsp_filter_check_plugin(*this);
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
	{
		//
		// Reject any event that is not generated by a plugin
		//
		if(evt->get_type() != PPME_PLUGINEVENT_E)
		{
			return NULL;
		}

		//
		// If this is a source plugin, reject events that have
		// not been generated by a plugin with this id specifically.
		//
		// XXX/mstemm this should probably check the version as well.
		//
		sinsp_evt_param *parinfo;
		if(m_plugin->type() == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(m_plugin.get());
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t pgid = *(int32_t *)parinfo->m_val;
			if(pgid != splugin->id())
			{
				return NULL;
			}
		}

		//
		// If this is an extractor plugin, only attempt to
		// extract if the source is compatible with the event
		// source.
		//
		if(m_plugin->type() == TYPE_EXTRACTOR_PLUGIN)
		{
			sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(m_plugin.get());
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t pgid = *(int32_t *)parinfo->m_val;

			std::shared_ptr<sinsp_plugin> plugin = m_inspector->get_plugin_by_id(pgid);

			if(!plugin)
			{
				return NULL;
			}

			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());

			if(!eplugin->source_compatible(splugin->event_source()))
			{
				return NULL;
			}
		}

		//
		// Get the event payload
		//
		parinfo = evt->get_param(1);
		*len = 0;

		ppm_param_type type = m_info.m_fields[m_field_id].m_type;

		ss_plugin_event pevt;
		pevt.evtnum = evt->get_num();
		pevt.data = (uint8_t *) parinfo->m_val;
		pevt.datalen = parinfo->m_len;
		pevt.ts = evt->get_ts();

		sinsp_plugin::ext_field field;
		field.field = m_info.m_fields[m_field_id].m_name;
		if(m_arg != NULL)
		{
			field.arg = m_arg;
		}
		field.ftype = type;

		if (!m_plugin->extract_field(pevt, field) ||
		    ! field.field_present)
		{
			return NULL;
		}

		switch(type)
		{
		case PT_CHARBUF:
		{
			m_strstorage = field.res_str;
			*len = m_strstorage.size();
			return (uint8_t*) m_strstorage.c_str();
		}
		case PT_UINT64:
		{
			m_u64_res = field.res_u64;
			return (uint8_t *)&m_u64_res;
		}
		default:
			ASSERT(false);
			throw sinsp_exception("plugin extract error: unsupported field type " + to_string(type));
			break;
		}

		return NULL;
	}

	// XXX/mstemm m_cnt unused so far.
	uint64_t m_cnt;
	string m_argstr;
	char* m_arg = NULL;

	std::string m_strstorage;
	uint64_t m_u64_res;

	std::shared_ptr<sinsp_plugin> m_plugin;
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

std::shared_ptr<sinsp_plugin> sinsp_plugin::register_plugin(sinsp* inspector, string filepath, char* config)
{
	string errstr;
	std::shared_ptr<sinsp_plugin> plugin = create_plugin(filepath, config, errstr);

	if (!plugin)
	{
		throw sinsp_exception("cannot load plugin " + filepath + ": " + errstr.c_str());
	}

	try
	{
		inspector->add_plugin(plugin);
	}
	catch(sinsp_exception const& e)
	{
		throw sinsp_exception("cannot add plugin " + filepath + " to inspector: " + e.what());
	}

	//
	// Create and register the filter checks associated to this plugin
	//
	auto info_filtercheck = new sinsp_filter_check_plugininfo(plugin);
	g_filterlist.add_filter_check(info_filtercheck);

	auto filtercheck = new sinsp_filter_check_plugin(plugin);
	g_filterlist.add_filter_check(filtercheck);

	return plugin;
}

std::shared_ptr<sinsp_plugin> sinsp_plugin::create_plugin(string &filepath, char* config, std::string &errstr)
{
	std::shared_ptr<sinsp_plugin> ret;

#ifdef _WIN32
	HINSTANCE handle = LoadLibrary(filepath.c_str());
#else
	void* handle = dlopen(filepath.c_str(), RTLD_LAZY);
#endif
	if(handle == NULL)
	{
		errstr = "error loading plugin " + filepath + ": " + strerror(errno);
		return ret;
	}

	// Get the plugin's free() function, and return an error if it
	// doesn't exist.
	void (*free_mem)(void *ptr);
	*(void **) (&free_mem) = getsym(handle, "plugin_free_mem", errstr);
	if(free_mem == NULL)
	{
		errstr = string("Could not resolve plugin_free_mem function");
		return ret;
	}

	// Before doing anything else, check the required api
	// version. If it doesn't match, return an error.

	// The pointer indirection and reference is because c++ doesn't
	// strictly allow casting void * to a function pointer. (See
	// http://www.open-std.org/jtc1/sc22/wg21/docs/cwg_defects.html#195).
	char * (*get_required_api_version)();
	*(void **) (&get_required_api_version) = getsym(handle, "plugin_get_required_api_version", errstr);
	if(get_required_api_version == NULL)
	{
		errstr = string("Could not resolve plugin_get_required_api_version function");
		return ret;
	}

	char *version_cstr = get_required_api_version();
	std::string version_str = version_cstr;
	free_mem(version_cstr);
	version v(version_str);
	if(!v.m_valid)
	{
		errstr = string("Could not parse version string from ") + version_str;
		return ret;
	}

	if(v.m_version_major != PLUGIN_API_VERSION_MAJOR)
	{
		errstr = string("Unsupported plugin required api version ") + version_str;
		return ret;
	}

	uint32_t (*get_type)();
	*(void **) (&get_type) = getsym(handle, "plugin_get_type", errstr);
	if(get_type == NULL)
	{
		errstr = string("Could not resolve plugin_get_type function");
		return ret;
	}

	uint32_t plugin_type = get_type();

	sinsp_source_plugin *splugin;
	sinsp_extractor_plugin *eplugin;

	switch(plugin_type)
	{
	case TYPE_SOURCE_PLUGIN:
		splugin = new sinsp_source_plugin();
		if(!splugin->resolve_dylib_symbols(handle, errstr))
		{
			delete splugin;
			return ret;
		}
		ret.reset(splugin);
		break;
	case TYPE_EXTRACTOR_PLUGIN:
		eplugin = new sinsp_extractor_plugin();
		if(!eplugin->resolve_dylib_symbols(handle, errstr))
		{
			delete eplugin;
			return ret;
		}
		ret.reset(eplugin);
		break;
	}

	errstr = "";

	// Initialize the plugin
	if (!ret->init(config))
	{
		ret = NULL;
	}

	return ret;
}

std::list<sinsp_plugin::info> sinsp_plugin::plugin_infos(sinsp* inspector)
{
	std::list<sinsp_plugin::info> ret;

	for(auto p : inspector->get_plugins())
	{
		sinsp_plugin::info info;
		info.name = p->name();
		info.description = p->description();
		info.contact = p->contact();
		info.plugin_version = p->plugin_version();
		info.required_api_version = p->required_api_version();

		if(p->type() == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *sp = static_cast<sinsp_source_plugin *>(p.get());
			info.id = sp->id();
		}
		ret.push_back(info);
	}

	return ret;
}

sinsp_plugin::sinsp_plugin()
	: m_nfields(0)
{
}

sinsp_plugin::~sinsp_plugin()
{
}

bool sinsp_plugin::init(char *config)
{
	if (!m_plugin_info.init)
	{
		return false;
	}

	int32_t rc;

	ss_plugin_t *state = m_plugin_info.init(config, &rc);
	if(rc != SCAP_SUCCESS)
	{
		// Not calling get_last_error here because there was
		// no valid ss_plugin_t struct returned from init.
		return false;
	}

	set_plugin_state(state);

	return true;
}

void sinsp_plugin::destroy()
{
	if(plugin_state() && m_plugin_info.destroy)
	{
		m_plugin_info.destroy(plugin_state());
		set_plugin_state(NULL);
	}
}

std::string sinsp_plugin::get_last_error()
{
	std::string ret;

	if(plugin_state() && m_plugin_info.get_last_error)
	{
		ret = str_from_alloc_charbuf(m_plugin_info.get_last_error(plugin_state()));
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

const filtercheck_field_info *sinsp_plugin::fields()
{
	return m_fields.get();
}

uint32_t sinsp_plugin::nfields()
{
	return m_nfields;
}

bool sinsp_plugin::extract_field(ss_plugin_event &evt, sinsp_plugin::ext_field &field)
{
	if(!m_plugin_info.extract_fields || !plugin_state())
	{
		return false;
	}

	uint32_t num_fields = 1;
	ss_plugin_extract_field efield;
	efield.field = field.field.c_str();
	efield.arg = field.arg.c_str();
	efield.ftype = field.ftype;

	int32_t rc;

	rc = m_plugin_info.extract_fields(plugin_state(), &evt, num_fields, &efield);

	if (rc != SCAP_SUCCESS)
	{
		return false;
	}

	field.field_present = efield.field_present;
	switch(field.ftype)
	{
	case PT_CHARBUF:
		field.res_str = str_from_alloc_charbuf(efield.res_str);
		break;
	case PT_UINT64:
		field.res_u64 = efield.res_u64;
		break;
	default:
		ASSERT(false);
		throw sinsp_exception("plugin extract error: unsupported field type " + to_string(field.ftype));
		break;
	}

	return true;
}

void* sinsp_plugin::getsym(void* handle, const char* name, std::string &errstr)
{
	void *ret;

#ifdef _WIN32
	ret = GetProcAddress((HINSTANCE)handle, name);
#else
	ret = dlsym(handle, name);
#endif

	if(ret == NULL)
	{
		errstr = string("Dynamic library symbol ") + name + " not present";
	} else {
		errstr = "";
	}

	return ret;
}

// Used below--set a std::string from the provided allocated charbuf and free() the charbuf.
std::string sinsp_plugin::str_from_alloc_charbuf(char *charbuf)
{
	std::string str;

	if(charbuf != NULL)
	{
		str = charbuf;
		m_plugin_info.free_mem(charbuf);
	}

	return str;
}

bool sinsp_plugin::resolve_dylib_symbols(void *handle, std::string &errstr)
{
	// Some functions are required and return false if not found.
	if((*(void **) (&(m_plugin_info.get_required_api_version)) = getsym(handle, "plugin_get_required_api_version", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.free_mem)) = getsym(handle, "plugin_free_mem", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.get_last_error)) = getsym(handle, "plugin_get_last_error", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.get_name)) = getsym(handle, "plugin_get_name", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.get_description)) = getsym(handle, "plugin_get_description", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.get_contact)) = getsym(handle, "plugin_get_contact", errstr)) == NULL ||
	   (*(void **) (&(m_plugin_info.get_version)) = getsym(handle, "plugin_get_version", errstr)) == NULL)
	{
		return false;
	}

	// Others are not and the values will be checked when needed.
	(*(void **) (&m_plugin_info.init)) = getsym(handle, "plugin_init", errstr);
	(*(void **) (&m_plugin_info.destroy)) = getsym(handle, "plugin_destroy", errstr);
	(*(void **) (&m_plugin_info.get_fields)) = getsym(handle, "plugin_get_fields", errstr);
	(*(void **) (&m_plugin_info.extract_fields)) = getsym(handle, "plugin_extract_fields", errstr);

	m_name = str_from_alloc_charbuf(m_plugin_info.get_name());
	m_description = str_from_alloc_charbuf(m_plugin_info.get_description());
	m_contact = str_from_alloc_charbuf(m_plugin_info.get_contact());
	std::string version_str = str_from_alloc_charbuf(m_plugin_info.get_version());
	m_plugin_version = sinsp_plugin::version(version_str);
	if(!m_plugin_version.m_valid)
	{
		errstr = string("Could not parse version string from ") + version_str;
		return false;
	}

	// The required api version was already checked in
	// create_plugin to be valid and compatible. This just saves it for info/debugging.
	version_str = str_from_alloc_charbuf(m_plugin_info.get_required_api_version());
	m_required_api_version = sinsp_plugin::version(version_str);

	//
	// If filter fields are exported by the plugin, get the json from get_fields(),
	// parse it, create our list of fields, and create a filtercheck from the fields.
	//
	if(m_plugin_info.get_fields)
	{
		char* sfields = m_plugin_info.get_fields();
		if(sfields == NULL)
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": get_fields returned a null string");
		}
		string json(sfields);
		SINSP_DEBUG("Parsing Fields JSON=%s", json.c_str());
		Json::Value root;
		if(Json::Reader().parse(json, root) == false || root.type() != Json::arrayValue)
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": get_fields returned an invalid JSON");
		}

		filtercheck_field_info *fields = new filtercheck_field_info[root.size()];
		if(fields == NULL)
		{
			throw sinsp_exception(string("error in plugin ") + m_name + ": could not allocate memory");
		}

		// Take ownership of the pointer right away so it can't be leaked.
		m_fields.reset(fields);
		m_nfields = root.size();

		for(Json::Value::ArrayIndex j = 0; j < root.size(); j++)
		{
			filtercheck_field_info &tf = m_fields.get()[j];
			tf.m_flags = EPF_NONE;

			const Json::Value &jvtype = root[j]["type"];
			string ftype = jvtype.asString();
			if(ftype == "")
			{
				throw sinsp_exception(string("error in plugin ") + m_name + ": field JSON entry has no type");
			}
			const Json::Value &jvname = root[j]["name"];
			string fname = jvname.asString();
			if(fname == "")
			{
				throw sinsp_exception(string("error in plugin ") + m_name + ": field JSON entry has no name");
			}
			const Json::Value &jvdesc = root[j]["desc"];
			string fdesc = jvdesc.asString();
			if(fdesc == "")
			{
				throw sinsp_exception(string("error in plugin ") + m_name + ": field JSON entry has no desc");
			}

			strncpy(tf.m_name, fname.c_str(), sizeof(tf.m_name));
			strncpy(tf.m_description, fdesc.c_str(), sizeof(tf.m_description));
			tf.m_print_format = PF_DEC;
			if(ftype == "string")
			{
				tf.m_type = PT_CHARBUF;
			}
			else if(ftype == "uint64")
			{
				tf.m_type = PT_UINT64;
			}
			// XXX/mstemm are these actually supported?
			else if(ftype == "int64")
			{
				tf.m_type = PT_INT64;
			}
			else if(ftype == "float")
			{
				tf.m_type = PT_DOUBLE;
			}
			else
			{
				throw sinsp_exception(string("error in plugin ") + m_name + ": invalid field type " + ftype);
			}
			const Json::Value &jvargRequired = root[j].get("argRequired", Json::Value::null);
			if (!jvargRequired.isNull())
			{
				if (!jvargRequired.isBool())
				{
					throw sinsp_exception(string("error in plugin ") + m_name + ": field " + fname + " argRequired property is not boolean ");
				}

				if (jvargRequired.asBool() == true)
				{
					tf.m_flags = filtercheck_field_flags::EPF_REQUIRES_ARGUMENT;
				}
			}
		}

	}

	return true;
}

sinsp_source_plugin::sinsp_source_plugin()
{
	memset(&m_source_plugin_info, 0, sizeof(m_source_plugin_info));
}

sinsp_source_plugin::~sinsp_source_plugin()
{
	close();
	destroy();
}

uint32_t sinsp_source_plugin::id()
{
	return m_id;
}

const std::string &sinsp_source_plugin::event_source()
{
	return m_event_source;
}

source_plugin_info *sinsp_source_plugin::plugin_info()
{
	return &m_source_plugin_info;
}

bool sinsp_source_plugin::open(char *params, int32_t &rc)
{
	int32_t orc;

	if(!plugin_state())
	{
		return false;
	}

	m_source_plugin_info.handle = m_source_plugin_info.open(plugin_state(), params, &orc);

	rc = orc;

	return (m_source_plugin_info.handle != NULL);
}

void sinsp_source_plugin::close()
{
	if(!plugin_state() || !m_source_plugin_info.handle)
	{
		return;
	}

	m_source_plugin_info.close(plugin_state(), m_source_plugin_info.handle);
}

std::string sinsp_source_plugin::get_progress(uint32_t &progress_pct)
{
	std::string ret;
	progress_pct = 0;

	if(!m_source_plugin_info.get_progress || !m_source_plugin_info.handle)
	{
		return ret;
	}

	uint32_t ppct;
	ret = str_from_alloc_charbuf(m_source_plugin_info.get_progress(plugin_state(), m_source_plugin_info.handle, &ppct));

	progress_pct = ppct;

	return ret;
}

std::string sinsp_source_plugin::event_to_string(const uint8_t *data, uint32_t datalen)
{
	std::string ret = "<NA>";

	if (!m_source_plugin_info.event_to_string)
	{
		return ret;
	}

	ret = str_from_alloc_charbuf(m_source_plugin_info.event_to_string(plugin_state(), data, datalen));

	return ret;
}

void sinsp_source_plugin::set_plugin_state(ss_plugin_t *state)
{
	m_source_plugin_info.state = state;
}

ss_plugin_t *sinsp_source_plugin::plugin_state()
{
	return m_source_plugin_info.state;
}

bool sinsp_source_plugin::resolve_dylib_symbols(void *handle, std::string &errstr)
{
	if (!sinsp_plugin::resolve_dylib_symbols(handle, errstr))
	{
		return false;
	}

	// We resolve every symbol, even those that are not actually
	// used by this derived class, just to ensure that
	// m_source_plugin_info is complete. (The struct can be passed
	// down to libscap when reading/writing capture files).
	//
	// Some functions are required and return false if not found.
	if((*(void **) (&(m_source_plugin_info.get_required_api_version)) = getsym(handle, "plugin_get_required_api_version", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.free_mem)) = getsym(handle, "plugin_free_mem", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.init)) = getsym(handle, "plugin_init", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.destroy)) = getsym(handle, "plugin_destroy", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_last_error)) = getsym(handle, "plugin_get_last_error", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_type)) = getsym(handle, "plugin_get_type", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_id)) = getsym(handle, "plugin_get_id", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_name)) = getsym(handle, "plugin_get_name", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_description)) = getsym(handle, "plugin_get_description", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_contact)) = getsym(handle, "plugin_get_contact", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_version)) = getsym(handle, "plugin_get_version", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.get_event_source)) = getsym(handle, "plugin_get_event_source", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.open)) = getsym(handle, "plugin_open", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.close)) = getsym(handle, "plugin_close", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.next)) = getsym(handle, "plugin_next", errstr)) == NULL ||
	   (*(void **) (&(m_source_plugin_info.event_to_string)) = getsym(handle, "plugin_event_to_string", errstr)) == NULL)
	{
		return false;
	}

	// Others are not.
	(*(void **) (&m_source_plugin_info.get_fields)) = getsym(handle, "plugin_get_fields", errstr);
	(*(void **) (&m_source_plugin_info.get_progress)) = getsym(handle, "plugin_get_progress", errstr);
	(*(void **) (&m_source_plugin_info.event_to_string)) = getsym(handle, "plugin_event_to_string", errstr);
	(*(void **) (&m_source_plugin_info.extract_fields)) = getsym(handle, "plugin_extract_fields", errstr);
	(*(void **) (&m_source_plugin_info.next_batch)) = getsym(handle, "plugin_next_batch", errstr);

	m_id = m_source_plugin_info.get_id();
	m_event_source = str_from_alloc_charbuf(m_source_plugin_info.get_event_source());

	return true;
}

sinsp_extractor_plugin::sinsp_extractor_plugin()
{
	memset(&m_extractor_plugin_info, 0, sizeof(m_extractor_plugin_info));
}

sinsp_extractor_plugin::~sinsp_extractor_plugin()
{
	destroy();
}

const std::set<std::string> &sinsp_extractor_plugin::extract_event_sources()
{
	return m_extract_event_sources;
}

bool sinsp_extractor_plugin::source_compatible(const std::string &source)
{
	return(m_extract_event_sources.size() == 0 ||
	       m_extract_event_sources.find(source) != m_extract_event_sources.end());
}

void sinsp_extractor_plugin::set_plugin_state(ss_plugin_t *state)
{
	m_extractor_plugin_info.state = state;
}

ss_plugin_t *sinsp_extractor_plugin::plugin_state()
{
	return m_extractor_plugin_info.state;
}

bool sinsp_extractor_plugin::resolve_dylib_symbols(void *handle, std::string &errstr)
{
	if (!sinsp_plugin::resolve_dylib_symbols(handle, errstr))
	{
		return false;
	}

	// We resolve every symbol, even those that are not actually
	// used by this derived class, just to ensure that
	// m_extractor_plugin_info is complete. (The struct can be passed
	// down to libscap when reading/writing capture files).
	//
	// Some functions are required and return false if not found.
	if((*(void **) (&(m_extractor_plugin_info.get_required_api_version)) = getsym(handle, "plugin_get_required_api_version", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.free_mem)) = getsym(handle, "plugin_free_mem", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.init)) = getsym(handle, "plugin_init", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.destroy)) = getsym(handle, "plugin_destroy", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_last_error)) = getsym(handle, "plugin_get_last_error", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_type)) = getsym(handle, "plugin_get_type", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_name)) = getsym(handle, "plugin_get_name", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_description)) = getsym(handle, "plugin_get_description", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_contact)) = getsym(handle, "plugin_get_contact", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_version)) = getsym(handle, "plugin_get_version", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.get_fields)) = getsym(handle, "plugin_get_fields", errstr)) == NULL ||
	   (*(void **) (&(m_extractor_plugin_info.extract_fields)) = getsym(handle, "plugin_extract_fields", errstr)) == NULL)
	{
		return false;
	}

	// Others are not.
	(*(void **) (&m_extractor_plugin_info.get_extract_event_sources)) = getsym(handle, "plugin_get_extract_event_sources", errstr);

	if (m_extractor_plugin_info.get_extract_event_sources != NULL)
	{
		std::string esources = str_from_alloc_charbuf(m_extractor_plugin_info.get_extract_event_sources());

		if (esources.length() == 0)
		{
			throw sinsp_exception(string("error in plugin ") + name() + ": get_extract_event_sources returned an empty string");
		}

		Json::Value root;
		if(Json::Reader().parse(esources, root) == false || root.type() != Json::arrayValue)
		{
			throw sinsp_exception(string("error in plugin ") + name() + ": get_extract_event_sources did not return a json array");
		}

		for(Json::Value::ArrayIndex j = 0; j < root.size(); j++)
		{
			if(! root[j].isConvertibleTo(Json::stringValue))
			{
				throw sinsp_exception(string("error in plugin ") + name() + ": get_extract_event_sources did not return a json array");
			}

			m_extract_event_sources.insert(root[j].asString());
		}
	}

	return true;
}


