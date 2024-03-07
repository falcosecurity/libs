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

#include <libsinsp/sinsp_filtercheck_rawstring.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

static const filtercheck_field_info rawstring_check_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "NA", "NA", "INTERNAL."},
};

rawstring_check::rawstring_check(string text)
{
	m_field = rawstring_check_fields;
	m_info.m_flags = filter_check_info::FL_HIDDEN;
	m_field_id = 0;
	set_text(text);
}

std::unique_ptr<sinsp_filter_check> rawstring_check::allocate_new()
{
	ASSERT(false);
	return nullptr;
}

void rawstring_check::set_text(string text)
{
	m_text_len = (uint32_t)text.size();
	m_text = text;
}

int32_t rawstring_check::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	ASSERT(false);
	return -1;
}

uint8_t* rawstring_check::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = m_text_len;
	return (uint8_t*)m_text.c_str();
}
