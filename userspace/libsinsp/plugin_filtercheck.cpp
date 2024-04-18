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

#include <libsinsp/plugin_filtercheck.h>
#include <libsinsp/plugin_manager.h>

using namespace std;

sinsp_filter_check_plugin::sinsp_filter_check_plugin()
{
	m_info.m_name = "plugin";
	m_info.m_fields = NULL;
	m_info.m_nfields = 0;
	m_info.m_flags = filter_check_info::FL_NONE;
	m_eplugin = nullptr;
}

sinsp_filter_check_plugin::sinsp_filter_check_plugin(std::shared_ptr<sinsp_plugin> plugin)
{
	if (!(plugin->caps() & CAP_EXTRACTION))
	{
		throw sinsp_exception("Creating a sinsp_filter_check_plugin with a non extraction-capable plugin.");
	}

	m_eplugin = plugin;
	m_info.m_name = plugin->name() + string(" (plugin)");
	m_info.m_fields = &m_eplugin->fields()[0]; // we use a vector so this should be safe
	m_info.m_nfields = m_eplugin->fields().size();
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check_plugin::sinsp_filter_check_plugin(const sinsp_filter_check_plugin &p)
{
	m_eplugin = p.m_eplugin;
	m_info = p.m_info;
	m_compatible_plugin_sources_bitmap = p.m_compatible_plugin_sources_bitmap;
}

int32_t sinsp_filter_check_plugin::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);

	m_arg_present = false;
	m_arg_key = NULL;
	m_arg_index = 0;
	m_argstr.clear();

	// the field is parsed successfully
	if(res != -1)
	{
		string val(str);
		size_t val_end = val.find_first_of(' ', 0);
		if(val_end != string::npos)
		{
			val = val.substr(0, val_end);
		}
		trim(val);

		// search for the field's argument
		size_t arg_len = 0;
		size_t arg_pos = val.find_first_of('[', 0);
		if(arg_pos != string::npos)
		{
			if (res != (int32_t) arg_pos)
			{
				// check that we matched the whole field string and not just its prefix
				return -1;
			}

			// extract the argument string with proper boundary checks
			size_t argstart = arg_pos + 1;
			if(argstart >= val.size())
			{
				throw sinsp_exception(string("filter '") + str + string("': ") + m_field->m_name + string(" terminates with incomplete argument brackets"));
			}
			m_argstr = val.substr(argstart);
			arg_len = m_argstr.find_first_of(']', 0);
			if(arg_len == string::npos)
			{
				throw sinsp_exception(string("filter '") + str + string("': ") + m_field->m_name + string(" has unbalanced argument brackets"));
			}
			m_argstr = m_argstr.substr(0, arg_len);
			m_arg_present = true;

			// we have an argument, check if the field is supposed not to have one
			if (!(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_ALLOWED
					|| m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED))
			{
				throw sinsp_exception(string("filter '") + string(str) + string("': ")
					+ m_field->m_name + string(" does not allow nor require an argument but one is provided: " + m_argstr));
			}

			// parse the argument content, which can either be an index or a key
			if(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_INDEX)
			{
				extract_arg_index(str);
			}
			if(m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_KEY)
			{
				extract_arg_key();
			}

			// update the parsed len taking into account both the name and the argument
			res = arg_pos + arg_len + 2;
		}

		if (!m_arg_present && (m_info.m_fields[m_field_id].m_flags & filtercheck_field_flags::EPF_ARG_REQUIRED))
		{
			throw sinsp_exception(string("filter '") + string(str) + string("': ") + m_field->m_name + string(" requires an argument but none provided"));
		}
	}

	return res;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_plugin::allocate_new()
{
	return std::make_unique<sinsp_filter_check_plugin>(*this);
}

bool sinsp_filter_check_plugin::extract(sinsp_evt *evt, OUT vector<extract_value_t>& values, bool sanitize_strings)
{
	// reject the event if it comes from an unknown event source
	if (evt->get_source_idx() == sinsp_no_event_source_idx)
	{
		return false;
	}

	// reject the event if its type is not compatible with the plugin
	if (!m_eplugin->extract_event_codes().contains((ppm_event_code) evt->get_type()))
	{
		return false;
	}

	// lazily populate the event source compatibility bitmap
	while (m_compatible_plugin_sources_bitmap.size() <= evt->get_source_idx())
	{
		auto src_idx = m_compatible_plugin_sources_bitmap.size();
		m_compatible_plugin_sources_bitmap.push_back(false);
		ASSERT(src_idx < m_inspector->event_sources().size());
		const auto& source = m_inspector->event_sources()[src_idx];
		auto compatible = sinsp_plugin::is_source_compatible(m_eplugin->extract_event_sources(), source);
		m_compatible_plugin_sources_bitmap[src_idx] = compatible;
	}

	// reject the event if its event source is not compatible with the plugin
	if (!m_compatible_plugin_sources_bitmap[evt->get_source_idx()])
	{
		return false;
	}

	auto type = m_info.m_fields[m_field_id].m_type;

	// here we want to extract just one field
	uint32_t num_fields = 1;

	// populate the field to extract for the plugin
	ss_plugin_extract_field efield;
	efield.field_id = m_field_id;
	efield.field = m_info.m_fields[m_field_id].m_name;
	efield.arg_key = m_arg_key;
	efield.arg_index = m_arg_index;
	efield.arg_present = m_arg_present;
	efield.ftype = type;
	efield.flist = m_info.m_fields[m_field_id].m_flags & EPF_IS_LIST;
	if (!m_eplugin->extract_fields(evt, num_fields, &efield) || efield.res_len == 0)
	{
		return false;
	}

	values.clear();
	for (uint32_t i = 0; i < efield.res_len; ++i)
	{
		extract_value_t res;
		switch(type)
		{
			case PT_UINT64:
			case PT_RELTIME:
			case PT_ABSTIME:
			{
				res.len = sizeof(uint64_t);
				res.ptr = (uint8_t*) &efield.res.u64[i];
				break;
			}
			case PT_IPADDR:
			case PT_IPNET:
			{
				res.len = (uint32_t) efield.res.buf[i].len;
				res.ptr = (uint8_t*) efield.res.buf[i].ptr;
				break;
			}
			case PT_CHARBUF:
			{
				res.len = strlen(efield.res.str[i]);
				res.ptr = (uint8_t*) efield.res.str[i];
				break;
			}
			case PT_BOOL:
			{
				res.len = sizeof(ss_plugin_bool);
				res.ptr = (uint8_t*) &efield.res.boolean[i];
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

void sinsp_filter_check_plugin::extract_arg_index(const char* full_field_name)
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
void sinsp_filter_check_plugin::extract_arg_key()
{
	m_arg_key = (char*)m_argstr.c_str();
}
