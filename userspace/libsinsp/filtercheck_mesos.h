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

#pragma once

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)

#include "sinsp_filtercheck.h"
#include "mesos.h"

class sinsp_filter_check_mesos : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_MESOS_TASK_NAME = 0,
		TYPE_MESOS_TASK_ID,
		TYPE_MESOS_TASK_LABEL,
		TYPE_MESOS_TASK_LABELS,
		TYPE_MESOS_FRAMEWORK_NAME,
		TYPE_MESOS_FRAMEWORK_ID,
		TYPE_MARATHON_APP_NAME,
		TYPE_MARATHON_APP_ID,
		TYPE_MARATHON_APP_LABEL,
		TYPE_MARATHON_APP_LABELS,
		TYPE_MARATHON_GROUP_NAME,
		TYPE_MARATHON_GROUP_ID,
	};

	sinsp_filter_check_mesos();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:

	int32_t extract_arg(const std::string& fldname, const std::string& val);
	mesos_task::ptr_t find_task_for_thread(const sinsp_threadinfo* tinfo);
	const mesos_framework* find_framework_by_task(mesos_task::ptr_t task);
	marathon_app::ptr_t find_app_by_task(mesos_task::ptr_t task);
	marathon_group::ptr_t find_group_by_task(mesos_task::ptr_t task);
	void concatenate_labels(const mesos_pair_list& labels, std::string* s);
	bool find_label(const mesos_pair_list& labels, const std::string& key, std::string* value);

	std::string m_argname;
	std::string m_tstr;
};

#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
