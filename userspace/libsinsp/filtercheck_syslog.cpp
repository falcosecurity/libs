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

#include "filtercheck_syslog.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "protodecoder.h"

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

static const filtercheck_field_info sinsp_filter_check_syslog_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.facility.str", "Facility", "facility as a string."},
	{PT_UINT32, EPF_NONE, PF_DEC, "syslog.facility", "Numeric Facility", "facility as a number (0-23)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.severity.str", "Severity", "severity as a string. Can have one of these values: emerg, alert, crit, err, warn, notice, info, debug"},
	{PT_UINT32, EPF_NONE, PF_DEC, "syslog.severity", "Numeric Severity", "severity as a number (0-7)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.message", "Message", "message sent to syslog."},
};

sinsp_filter_check_syslog::sinsp_filter_check_syslog()
{
	m_info.m_name = "syslog";
	m_info.m_desc = "Content of Syslog messages.";
	m_info.m_fields = sinsp_filter_check_syslog_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_syslog_fields) / sizeof(sinsp_filter_check_syslog_fields[0]);
	m_decoder = NULL;
}

sinsp_filter_check* sinsp_filter_check_syslog::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_syslog();
}

int32_t sinsp_filter_check_syslog::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	if(res != -1)
	{
		m_decoder = (sinsp_decoder_syslog*)m_inspector->require_protodecoder("syslog");
	}

	return res;
}

uint8_t* sinsp_filter_check_syslog::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	const char *str;
	ASSERT(m_decoder != NULL);
	if(!m_decoder->is_data_valid())
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_FACILITY:
		RETURN_EXTRACT_VAR(m_decoder->m_facility);
	case TYPE_FACILITY_STR:
		str = m_decoder->get_facility_str();
		RETURN_EXTRACT_CSTR(str);
	case TYPE_SEVERITY:
		RETURN_EXTRACT_VAR(m_decoder->m_severity);
	case TYPE_SEVERITY_STR:
		str = m_decoder->get_severity_str();
		RETURN_EXTRACT_CSTR(str);
	case TYPE_MESSAGE:
		RETURN_EXTRACT_STRING(m_decoder->m_msg);
	default:
		ASSERT(false);
		return NULL;
	}
}
