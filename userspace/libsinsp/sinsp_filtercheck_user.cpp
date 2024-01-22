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

#include <libsinsp/sinsp_filtercheck_user.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

#define RETURN_EXTRACT_CSTR(x) do {             \
        if((x))                                 \
        {                                       \
                *len = strlen((char *) ((x)));  \
        }                                       \
        return (uint8_t*) ((x));                \
} while(0)

static const filtercheck_field_info sinsp_filter_check_user_fields[] =
{
	{PT_UINT32, EPF_NONE, PF_ID, "user.uid", "User ID", "user ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.name", "User Name", "user name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.homedir", "Home Directory", "home directory of the user."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.shell", "Shell", "user's shell."},
	{PT_INT64, EPF_NONE, PF_ID, "user.loginuid", "Login User ID", "audit user id (auid), internally the loginuid is of type `uint32_t`. However, if an invalid uid corresponding to UINT32_MAX is encountered, it is returned as -1 to support familiar filtering conditions."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.loginname", "Login User Name", "audit user name (auid)."},
};

sinsp_filter_check_user::sinsp_filter_check_user()
{
	m_info.m_name = "user";
	m_info.m_desc = "Information about the user executing the specific event.";
	m_info.m_fields = sinsp_filter_check_user_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_user_fields) / sizeof(sinsp_filter_check_user_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check* sinsp_filter_check_user::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_user();
}

uint8_t* sinsp_filter_check_user::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	// For container events, use the user from the container metadata instead.
	if(m_field_id == TYPE_NAME &&
	   (evt->get_type() == PPME_CONTAINER_JSON_E || evt->get_type() == PPME_CONTAINER_JSON_2_E))
	{
		const sinsp_container_info::ptr_t container_info =
			m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		if(!container_info)
		{
			return NULL;
		}

		RETURN_EXTRACT_STRING(container_info->m_container_user);
	}

	switch(m_field_id)
	{
	case TYPE_UID:
		RETURN_EXTRACT_VAR(tinfo->m_user.uid);
	case TYPE_NAME:
		RETURN_EXTRACT_CSTR(tinfo->m_user.name);
	case TYPE_HOMEDIR:
		RETURN_EXTRACT_CSTR(tinfo->m_user.homedir);
	case TYPE_SHELL:
		RETURN_EXTRACT_CSTR(tinfo->m_user.shell);
	case TYPE_LOGINUID:
		m_s64val = (int64_t)-1;
		if(tinfo->m_loginuser.uid < UINT32_MAX)
		{
			m_s64val = (int64_t)tinfo->m_loginuser.uid;
		}
		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_LOGINNAME:
		RETURN_EXTRACT_CSTR(tinfo->m_loginuser.name);
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
