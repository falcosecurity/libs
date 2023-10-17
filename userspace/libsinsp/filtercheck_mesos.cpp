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

#include "filtercheck_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"

using namespace std;

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)

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
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
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

mesos_task::ptr_t sinsp_filter_check_mesos::find_task_for_thread(const sinsp_threadinfo* tinfo)
{
	ASSERT(m_inspector && tinfo);
	if(tinfo)
	{
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}

		if(m_inspector && m_inspector->m_mesos_client)
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info || container_info->m_mesos_task_id.empty())
			{
				return NULL;
			}
			const mesos_state_t& mesos_state = m_inspector->m_mesos_client->get_state();
			return mesos_state.get_task(container_info->m_mesos_task_id);
		}
	}

	return NULL;
}

const mesos_framework* sinsp_filter_check_mesos::find_framework_by_task(mesos_task::ptr_t task)
{
	if(task && m_inspector && m_inspector->m_mesos_client)
	{
		const mesos_state_t& mesos_state = m_inspector->m_mesos_client->get_state();
		return mesos_state.get_framework_for_task(task->get_uid());
	}
	return NULL;
}

marathon_app::ptr_t sinsp_filter_check_mesos::find_app_by_task(mesos_task::ptr_t task)
{
	if(m_inspector && m_inspector->m_mesos_client)
	{
		return m_inspector->m_mesos_client->get_state().get_app(task);
	}
	return NULL;
}

marathon_group::ptr_t sinsp_filter_check_mesos::find_group_by_task(mesos_task::ptr_t task)
{
	if(m_inspector && m_inspector->m_mesos_client)
	{
		return m_inspector->m_mesos_client->get_state().get_group(task);
	}
	return NULL;
}

void sinsp_filter_check_mesos::concatenate_labels(const mesos_pair_list& labels, string* s)
{
	for(const mesos_pair_t& label_pair : labels)
	{
		if(!s->empty())
		{
			s->append(", ");
		}

		s->append(label_pair.first);
		if(!label_pair.second.empty())
		{
			s->append(":" + label_pair.second);
		}
	}
}

bool sinsp_filter_check_mesos::find_label(const mesos_pair_list& labels, const string& key, string* value)
{
	for(const mesos_pair_t& label_pair : labels)
	{
		if(label_pair.first == key)
		{
			*value = label_pair.second;
			return true;
		}
	}

	return false;
}

uint8_t* sinsp_filter_check_mesos::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	if(!m_inspector || !m_inspector->m_mesos_client)
	{
		return NULL;
	}

	if(!evt)
	{
		ASSERT(false);
		return NULL;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(!tinfo)
	{
		return NULL;
	}

	mesos_task::ptr_t task = find_task_for_thread(tinfo);
	if(!task)
	{
		return NULL;
	}

	m_tstr.clear();

	switch(m_field_id)
	{
	case TYPE_MESOS_TASK_NAME:
		m_tstr = task->get_name();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_MESOS_TASK_ID:
		m_tstr = task->get_uid();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_MESOS_TASK_LABEL:
		if(find_label(task->get_labels(), m_argname, &m_tstr))
		{
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_MESOS_TASK_LABELS:
		concatenate_labels(task->get_labels(), &m_tstr);
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_MESOS_FRAMEWORK_NAME:
	{
		const mesos_framework* fw = find_framework_by_task(task);
		if(fw)
		{
			m_tstr = fw->get_name();
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	case TYPE_MESOS_FRAMEWORK_ID:
	{
		const mesos_framework* fw = find_framework_by_task(task);
		if(fw)
		{
			m_tstr = fw->get_uid();
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	case TYPE_MARATHON_APP_NAME:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app != NULL)
		{
			m_tstr = app->get_name();
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	case TYPE_MARATHON_APP_ID:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app != NULL)
		{
			m_tstr = app->get_id();
			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	}
	case TYPE_MARATHON_APP_LABEL:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app && find_label(app->get_labels(), m_argname, &m_tstr))
		{
			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	}
	case TYPE_MARATHON_APP_LABELS:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app)
		{
			concatenate_labels(app->get_labels(), &m_tstr);
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	case TYPE_MARATHON_GROUP_NAME:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app)
		{
			m_tstr = app->get_group_id();
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	case TYPE_MARATHON_GROUP_ID:
	{
		marathon_app::ptr_t app = find_app_by_task(task);
		if(app)
		{
			m_tstr = app->get_group_id();
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	}
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}

#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
