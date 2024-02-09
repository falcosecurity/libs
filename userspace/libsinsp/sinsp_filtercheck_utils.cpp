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

#include <libsinsp/sinsp_filtercheck_utils.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

static const filtercheck_field_info sinsp_filter_check_utils_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_ID, "util.cnt", "Counter", "incremental counter."},
};

sinsp_filter_check_utils::sinsp_filter_check_utils()
{
	m_info.m_name = "util";
	m_info.m_desc = "";
	m_info.m_fields = sinsp_filter_check_utils_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_utils_fields) / sizeof(sinsp_filter_check_utils_fields[0]);
	m_info.m_flags = filter_check_info::FL_HIDDEN;
	m_cnt = 0;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_utils::allocate_new()
{
	return std::make_unique<sinsp_filter_check_utils>();
}

uint8_t* sinsp_filter_check_utils::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	switch(m_field_id)
	{
	case TYPE_CNT:
		m_cnt++;
		RETURN_EXTRACT_VAR(m_cnt);
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
