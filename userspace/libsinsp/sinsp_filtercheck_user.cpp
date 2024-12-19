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

#define RETURN_EXTRACT_VAR(x)  \
	do {                       \
		*len = sizeof((x));    \
		return (uint8_t*)&(x); \
	} while(0)

#define RETURN_EXTRACT_STRING(x)      \
	do {                              \
		*len = (x).size();            \
		return (uint8_t*)(x).c_str(); \
	} while(0)

static const filtercheck_field_info sinsp_filter_check_user_fields[] = {
        {PT_UINT32, EPF_NONE, PF_ID, "user.uid", "User ID", "user ID."},
        {PT_CHARBUF, EPF_NONE, PF_NA, "user.name", "User Name", "user name."},
        {PT_CHARBUF,
         EPF_NONE,
         PF_NA,
         "user.homedir",
         "Home Directory",
         "home directory of the user."},
        {PT_CHARBUF, EPF_NONE, PF_NA, "user.shell", "Shell", "user's shell."},
        {PT_INT64,
         EPF_NONE,
         PF_ID,
         "user.loginuid",
         "Login User ID",
         "audit user id (auid), internally the loginuid is of type `uint32_t`. However, if an "
         "invalid uid corresponding to UINT32_MAX is encountered, it is returned as -1 to support "
         "familiar filtering conditions."},
        {PT_CHARBUF,
         EPF_NONE,
         PF_NA,
         "user.loginname",
         "Login User Name",
         "audit user name (auid)."},
};

sinsp_filter_check_user::sinsp_filter_check_user() {
	static const filter_check_info s_field_infos = {
	        "user",
	        "",
	        "Information about the user executing the specific event.",
	        sizeof(sinsp_filter_check_user_fields) / sizeof(sinsp_filter_check_user_fields[0]),
	        sinsp_filter_check_user_fields,
	        filter_check_info::FL_NONE,
	};
	m_info = &s_field_infos;
	memset(&m_val, 0, sizeof(m_val));
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_user::allocate_new() {
	return std::make_unique<sinsp_filter_check_user>();
}

uint8_t* sinsp_filter_check_user::extract_single(sinsp_evt* evt,
                                                 uint32_t* len,
                                                 bool sanitize_strings) {
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL) {
		return NULL;
	}

	// For container events, use the user from the container metadata instead.
	if(m_field_id == TYPE_NAME &&
	   (evt->get_type() == PPME_CONTAINER_JSON_E || evt->get_type() == PPME_CONTAINER_JSON_2_E)) {
		/* TODO
		 *const sinsp_container_info::ptr_t container_info =
		        m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		if(!container_info) {
		    return NULL;
		}

		RETURN_EXTRACT_STRING(container_info->m_container_user);*/
	}

	auto user = tinfo->get_user();
	auto loginuser = tinfo->get_loginuser();
	switch(m_field_id) {
	case TYPE_UID:
		m_val.u32 = tinfo->m_uid;
		RETURN_EXTRACT_VAR(m_val.u32);
	case TYPE_NAME:
		m_strval = user->name;
		RETURN_EXTRACT_STRING(m_strval);
	case TYPE_HOMEDIR:
		m_strval = user->homedir;
		RETURN_EXTRACT_STRING(m_strval);
	case TYPE_SHELL:
		m_strval = user->shell;
		RETURN_EXTRACT_STRING(m_strval);
	case TYPE_LOGINUID:
		m_val.s64 = (int64_t)-1;
		if(tinfo->m_loginuid < UINT32_MAX) {
			m_val.s64 = (int64_t)tinfo->m_loginuid;
		}
		RETURN_EXTRACT_VAR(m_val.s64);
	case TYPE_LOGINNAME:
		m_strval = loginuser->name;
		RETURN_EXTRACT_STRING(m_strval);
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
