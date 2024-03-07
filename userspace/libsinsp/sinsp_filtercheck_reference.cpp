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

#include <libsinsp/sinsp_filtercheck_reference.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

#define STRPROPERTY_STORAGE_SIZE	1024

using namespace std;

sinsp_filter_check_reference::sinsp_filter_check_reference()
{
	m_info.m_name = "<NA>";
	m_info.m_desc = "";
	m_info.m_fields = &m_finfo;
	m_info.m_nfields = 1;
	m_info.m_flags = filter_check_info::FL_HIDDEN;
	m_finfo.m_print_format = PF_DEC;
	m_field = &m_finfo;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_reference::allocate_new()
{
	ASSERT(false);
	return nullptr;
}

int32_t sinsp_filter_check_reference::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	ASSERT(false);
	return -1;
}

uint8_t* sinsp_filter_check_reference::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = m_len;
	return m_val;
}

//
// convert a number into a byte representation.
// E.g. 1230 becomes 1.23K
//
char* sinsp_filter_check_reference::format_bytes(double val, uint32_t str_len, bool is_int)
{
	char* pr_fmt;

	if(is_int)
	{
		pr_fmt = (char*)"%*.0lf%c";
	}
	else
	{
		pr_fmt = (char*)"%*.2lf%c";
	}

	if(val > (1024LL * 1024 * 1024 * 1024 * 1024))
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len - 1, (val) / (1024LL * 1024 * 1024 * 1024 * 1024), 'P');
	}
	else if(val > (1024LL * 1024 * 1024 * 1024))
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len - 1, (val) / (1024LL * 1024 * 1024 * 1024), 'T');
	}
	else if(val > (1024LL * 1024 * 1024))
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len - 1, (val) / (1024LL * 1024 * 1024), 'G');
	}
	else if(val > (1024 * 1024))
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len - 1, (val) / (1024 * 1024), 'M');
	}
	else if(val > 1024)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len - 1, (val) / (1024), 'K');
	}
	else
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					pr_fmt, str_len, val, 0);
	}

	uint32_t len = (uint32_t)strlen(m_getpropertystr_storage.data());

	if(len > str_len)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		memmove(m_getpropertystr_storage.data(),
			m_getpropertystr_storage.data() + len - str_len,
			str_len + 1); // include trailing \0
	}

	return m_getpropertystr_storage.data();
}

//
// convert a nanosecond time interval into a s.ns representation.
// E.g. 1100000000 becomes 1.1s
//
#define ONE_MILLISECOND_IN_NS 1000000
#define ONE_MICROSECOND_IN_NS 1000

char* sinsp_filter_check_reference::format_time(uint64_t val, uint32_t str_len)
{
	if(val >= 3600 * ONE_SECOND_IN_NS)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%.2u:%.2u:%.2u", (unsigned int)(val / (3600 * ONE_SECOND_IN_NS)),
					(unsigned int)((val / (60 * ONE_SECOND_IN_NS)) % 60 ),
					(unsigned int)((val / ONE_SECOND_IN_NS) % 60));
	}
	else if(val >= 60 * ONE_SECOND_IN_NS)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%u:%u", (unsigned int)(val / (60 * ONE_SECOND_IN_NS)), (unsigned int)((val / ONE_SECOND_IN_NS) % 60));
	}
	else if(val >= ONE_SECOND_IN_NS)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%u.%02us", (unsigned int)(val / ONE_SECOND_IN_NS), (unsigned int)((val % ONE_SECOND_IN_NS) / 10000000));
	}
	else if(val >= ONE_SECOND_IN_NS / 100)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%ums", (unsigned int)(val / (ONE_SECOND_IN_NS / 1000)));
	}
	else if(val >= ONE_SECOND_IN_NS / 1000)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%u.%02ums", (unsigned int)(val / (ONE_SECOND_IN_NS / 1000)), (unsigned int)((val % ONE_MILLISECOND_IN_NS) / 10000));
	}
	else if(val >= ONE_SECOND_IN_NS / 100000)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%uus", (unsigned int)(val / (ONE_SECOND_IN_NS / 1000000)));
	}
	else if(val >= ONE_SECOND_IN_NS / 1000000)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%u.%02uus", (unsigned int)(val / (ONE_SECOND_IN_NS / 1000000)), (unsigned int)((val % ONE_MICROSECOND_IN_NS) / 10));
	}
	else
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%uns", (unsigned int)val);
	}

	uint32_t reslen = (uint32_t)strlen(m_getpropertystr_storage.data());
	if(reslen < str_len)
	{
		uint32_t padding_size = str_len - reslen;

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		memmove(m_getpropertystr_storage.data() + padding_size,
			m_getpropertystr_storage.data(),
			str_len + 1);

		for(uint32_t j = 0; j < padding_size; j++)
		{
			m_getpropertystr_storage[j] = ' ';
		}
	}

	return m_getpropertystr_storage.data();
}

char* sinsp_filter_check_reference::print_double(uint8_t* rawval, uint32_t str_len)
{
	double val;

	switch(m_field->m_type)
	{
	case PT_INT8:
		val = (double)*(int8_t*)rawval;
		break;
	case PT_INT16:
		val = (double)*(int16_t*)rawval;
		break;
	case PT_INT32:
		val = (double)*(int32_t*)rawval;
		break;
	case PT_INT64:
		val = (double)*(int64_t*)rawval;
		break;
	case PT_UINT8:
		val = (double)*(uint8_t*)rawval;
		break;
	case PT_UINT16:
		val = (double)*(uint16_t*)rawval;
		break;
	case PT_UINT32:
		val = (double)*(uint32_t*)rawval;
		break;
	case PT_UINT64:
		val = (double)*(uint64_t*)rawval;
		break;
	default:
		ASSERT(false);
		val = 0;
		break;
	}

	if(m_cnt > 1)
	{
		val /= m_cnt;
	}

	if(m_print_format == PF_ID)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%*lf", str_len, val);
		return m_getpropertystr_storage.data();
	}
	else
	{
		return format_bytes(val, str_len, false);
	}

}

char* sinsp_filter_check_reference::print_int(uint8_t* rawval, uint32_t str_len)
{
	int64_t val;

	switch(m_field->m_type)
	{
	case PT_INT8:
		val = (int64_t)*(int8_t*)rawval;
		break;
	case PT_INT16:
		val = (int64_t)*(int16_t*)rawval;
		break;
	case PT_INT32:
		val = (int64_t)*(int32_t*)rawval;
		break;
	case PT_INT64:
		val = (int64_t)*(int64_t*)rawval;
		break;
	case PT_UINT8:
		val = (int64_t)*(uint8_t*)rawval;
		break;
	case PT_UINT16:
		val = (int64_t)*(uint16_t*)rawval;
		break;
	case PT_UINT32:
		val = (int64_t)*(uint32_t*)rawval;
		break;
	case PT_UINT64:
		val = (int64_t)*(uint64_t*)rawval;
		break;
	default:
		ASSERT(false);
		val = 0;
		break;
	}

	if(m_cnt > 1)
	{
		val /= (int64_t)m_cnt;
	}

	if(m_print_format == PF_ID)
	{
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%*" PRId64, str_len, val);
		return m_getpropertystr_storage.data();
	}
	else
	{
		return format_bytes((double)val, str_len, true);
	}

}

char* sinsp_filter_check_reference::tostring_nice(sinsp_evt* evt,
	uint32_t str_len,
	uint64_t time_delta)
{
	uint32_t len;
	// note: this uses the single-value extract because this filtercheck
	// class does not support multi-valued extraction
	uint8_t* rawval = extract(evt, &len);

	if(rawval == NULL)
	{
		return NULL;
	}

	if(time_delta != 0)
	{
		m_cnt = (double)time_delta / ONE_SECOND_IN_NS;
	}

	if(m_field->m_type >= PT_INT8 && m_field->m_type <= PT_UINT64)
	{
		if(m_print_format == PF_ID || m_cnt == 1 || m_cnt == 0)
		{
			return print_int(rawval, str_len);
		}
		else
		{
			return print_double(rawval, str_len);
		}
	}
	else if(m_field->m_type == PT_RELTIME)
	{
		double val = (double)*(uint64_t*)rawval;

		if(m_cnt > 1)
		{
			val /= m_cnt;
		}

		return format_time((int64_t)val, str_len);
	}
	else if(m_field->m_type == PT_DOUBLE)
	{
		double dval = (double)*(double*)rawval;

		if(m_cnt > 1)
		{
			dval /= m_cnt;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
					STRPROPERTY_STORAGE_SIZE,
					"%*.2lf", str_len, dval);
		return m_getpropertystr_storage.data();
	}
	else
	{
		return rawval_to_string(rawval, m_field->m_type, m_field->m_print_format, len);
	}
}

Json::Value sinsp_filter_check_reference::tojson(sinsp_evt* evt,
	uint32_t str_len,
	uint64_t time_delta)
{
	uint32_t len;
	// note: this uses the single-value extract because this filtercheck
	// class does not support multi-valued extraction
	uint8_t* rawval = extract(evt, &len);

	if(rawval == NULL)
	{
		return "";
	}

	if(time_delta != 0)
	{
		m_cnt = (double)time_delta / ONE_SECOND_IN_NS;
	}

	if(m_field->m_type == PT_RELTIME)
	{
		double val = (double)*(uint64_t*)rawval;

		if(m_cnt > 1)
		{
			val /= m_cnt;
		}

		return format_time((int64_t)val, str_len);
	}
	else if(m_field->m_type == PT_DOUBLE)
	{
		double dval = (double)*(double*)rawval;

		if(m_cnt > 1)
		{
			dval /= m_cnt;
		}

		return dval;
	}
	else
	{
		return rawval_to_json(rawval, m_field->m_type, m_field->m_print_format, len);
	}
}
