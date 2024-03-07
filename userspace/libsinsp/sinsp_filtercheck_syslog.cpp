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

#include <libsinsp/sinsp_filtercheck_syslog.h>
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
	m_info.m_flags = filter_check_info::FL_NONE;
	m_info.m_fields = sinsp_filter_check_syslog_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_syslog_fields) / sizeof(sinsp_filter_check_syslog_fields[0]);
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_syslog::allocate_new()
{
	return std::make_unique<sinsp_filter_check_syslog>();
}

uint8_t* sinsp_filter_check_syslog::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	auto& decoder = m_inspector->get_parser()->get_syslog_decoder();
	if (!decoder.is_data_valid())
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_FACILITY:
		m_storageu32 = decoder.get_facility();
		RETURN_EXTRACT_VAR(m_storageu32);
	case TYPE_FACILITY_STR:
		mstrstorage = decoder.get_facility_str();
		RETURN_EXTRACT_STRING(mstrstorage);
	case TYPE_SEVERITY:
		m_storageu32 = decoder.get_severity();
		RETURN_EXTRACT_VAR(m_storageu32);
	case TYPE_SEVERITY_STR:
		mstrstorage = decoder.get_severity_str();
		RETURN_EXTRACT_STRING(mstrstorage);
	case TYPE_MESSAGE:
		mstrstorage = decoder.get_msg();
		RETURN_EXTRACT_STRING(mstrstorage);
	default:
		ASSERT(false);
		return NULL;
	}
}
