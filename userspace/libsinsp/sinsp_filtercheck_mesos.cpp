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

#include <libsinsp/sinsp_filtercheck_mesos.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_mesos_fields[] =
{
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "mesos.task.name", "Task Name", "Mesos task name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "mesos.task.id", "Task ID", "Mesos task id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "mesos.task.label", "Task Label", "Mesos task label. E.g. 'mesos.task.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "mesos.task.labels", "Task Labels", "Mesos task comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "mesos.framework.name", "Framework Name", "Mesos framework name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "mesos.framework.id", "Framework ID", "Mesos framework id."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "marathon.app.name", "App Name", "Marathon app name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "marathon.app.id", "App ID", "Marathon app id."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "marathon.app.label", "App Label", "Marathon app label. E.g. 'marathon.app.label.foo'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "marathon.app.labels", "App Labels", "Marathon app comma-separated key/value labels. E.g. 'foo1:bar1,foo2:bar2'."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "marathon.group.name", "Group Name", "Marathon group name."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "marathon.group.id", "Group ID", "Marathon group id."},
};

sinsp_filter_check_mesos::sinsp_filter_check_mesos()
{
	m_info.m_name = "mesos";
	m_info.m_desc = "Mesos related context.";
	m_info.m_fields = sinsp_filter_check_mesos_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_mesos_fields) / sizeof(sinsp_filter_check_mesos_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check* sinsp_filter_check_mesos::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_mesos();
}

int32_t sinsp_filter_check_mesos::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);

	if(STR_MATCH("mesos.task.label") &&
		!STR_MATCH("mesos.task.labels"))
	{
		m_field_id = TYPE_MESOS_TASK_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("mesos.task.label", val);
	}
	else if(STR_MATCH("marathon.app.label") &&
		!STR_MATCH("marathon.app.labels"))
	{
		m_field_id = TYPE_MARATHON_APP_LABEL;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("marathon.app.label", val);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
}

int32_t sinsp_filter_check_mesos::extract_arg(const string& fldname, const string& val)
{
	int32_t parsed_len = 0;

	if(val[fldname.size()] == '.')
	{
		size_t endpos;
		for(endpos = fldname.size() + 1; endpos < val.length(); ++endpos)
		{
			if(!isalnum(val[endpos])
				&& val[endpos] != '/'
				&& val[endpos] != '_'
				&& val[endpos] != '-'
				&& val[endpos] != '.')
			{
				break;
			}
		}

		parsed_len = (uint32_t)endpos;
		m_argname = val.substr(fldname.size() + 1, endpos - fldname.size() - 1);
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len;
}

uint8_t* sinsp_filter_check_mesos::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	// note: all mesos fields are deprecated since removing them from the codebase
	*len = 0;
	return NULL;
}

