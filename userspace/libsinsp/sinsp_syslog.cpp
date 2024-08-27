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

#include <libsinsp/sinsp_syslog.h>
#include <libsinsp/utils.h>

#define PRI_BUF_SIZE 16

static const std::string s_syslog_severity_strings[] =
{
	"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"
};

static const std::string s_syslog_facility_strings[] =
{
	"kern",
	"user",
	"mail",
	"daemon",
	"auth",
	"syslog",
	"lpr",
	"news",
	"uucp",
	"clock",
	"authpriv",
	"ftp",
	"ntp",
	"logaudit",
	"logalert",
	"cron",
	"local0",
	"local1",
	"local2",
	"local3",
	"local4",
	"local5",
	"local6",
	"local7"
};

void sinsp_syslog_decoder::parse_data(const char *data, uint32_t len)
{
	char pri[PRI_BUF_SIZE];
	const char* tc = data + 1;
	const char* te = data + len;
	uint32_t j = 0;

	while(tc < te && *tc != '>' && *tc != '\0' && j < PRI_BUF_SIZE - 1)
	{
		pri[j++] = *tc;
		tc++;
	}

	pri[j] = 0;

	decode_message(data, len, pri, j);
}

std::string sinsp_syslog_decoder::get_severity_str() const
{
	if(!is_data_valid() || m_severity >= sizeof(s_syslog_severity_strings) / sizeof(s_syslog_severity_strings[0]))
	{
		return "<NA>";
	}
	else
	{
		return s_syslog_severity_strings[m_severity];
	}
}

std::string sinsp_syslog_decoder::get_facility_str() const
{
	if(!is_data_valid() || m_facility >= sizeof(s_syslog_facility_strings) / sizeof(s_syslog_facility_strings[0]))
	{
		return "<NA>";
	}
	else
	{
		return s_syslog_facility_strings[m_facility];
	}
}

void sinsp_syslog_decoder::decode_message(const char *data, uint32_t len, char* pristr, uint32_t pristrlen)
{
	if(len < pristrlen + 2 || pristrlen == 0)
	{
		m_priority = s_invalid_priority;
		return;
	}

	bool res = sinsp_numparser::tryparsed32_fast(pristr, pristrlen, &m_priority);

	if(!res)
	{
		m_priority = s_invalid_priority;
		return;
	}

	m_severity = m_priority & 0x07;
	m_facility = m_priority >> 3;

	m_msg.assign(data + pristrlen + 2, len - pristrlen - 2);
}

std::string sinsp_syslog_decoder::get_info_line() const
{
	if (!is_data_valid())
	{
		return "<NA>";
	}

	return "syslog sev=" + get_severity_str() + " msg=" + m_msg;
}
