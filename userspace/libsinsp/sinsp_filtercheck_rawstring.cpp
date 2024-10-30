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

static const filtercheck_field_info rawstring_check_fields[] = {
        {PT_CHARBUF, EPF_NONE, PF_NA, "NA", "NA", "INTERNAL."},
};

rawstring_check::rawstring_check(const string& text) {
	static const filter_check_info s_field_infos = {
	        "",
	        "",
	        "",
	        sizeof(rawstring_check_fields) / sizeof(rawstring_check_fields[0]),
	        rawstring_check_fields,
	        filter_check_info::FL_HIDDEN,
	};
	m_field = rawstring_check_fields;
	m_info = &s_field_infos;
	m_field_id = 0;
	m_text = text;
}

std::unique_ptr<sinsp_filter_check> rawstring_check::allocate_new() {
	ASSERT(false);
	return nullptr;
}

int32_t rawstring_check::parse_field_name(std::string_view,
                                          bool alloc_state,
                                          bool needed_for_filtering) {
	ASSERT(false);
	return -1;
}

uint8_t* rawstring_check::extract_single(sinsp_evt* evt, uint32_t* len, bool sanitize_strings) {
	*len = m_text.size();
	return (uint8_t*)m_text.c_str();
}

// raw num

static const filtercheck_field_info rawnum_check_fields[] = {
        {PT_CHARBUF, EPF_NONE, PF_NA, "NA", "NA", "INTERNAL."},
};

rawnum_check::rawnum_check(std::unique_ptr<sinsp_filter_check> chk) {
	static const filter_check_info s_field_infos = {
	        "",
	        "",
	        "",
	        sizeof(rawnum_check_fields) / sizeof(rawnum_check_fields[0]),
	        rawnum_check_fields,
	        filter_check_info::FL_HIDDEN,
	};
	m_field = rawnum_check_fields;
	m_info = &s_field_infos;
	m_field_id = 0;
	m_chk = std::move(chk);
	m_pf = m_chk->get_field_info()->m_print_format;
	m_pt = m_chk->get_field_info()->m_type;
}

std::unique_ptr<sinsp_filter_check> rawnum_check::allocate_new() {
	ASSERT(false);
	return nullptr;
}

int32_t rawnum_check::parse_field_name(std::string_view,
                                       bool alloc_state,
                                       bool needed_for_filtering) {
	ASSERT(false);
	return -1;
}

uint8_t* rawnum_check::extract_single(sinsp_evt* evt, uint32_t* len, bool sanitize_strings) {
	m_text.clear();
	std::vector<extract_value_t> values;
	m_chk->extract(evt, values, false);
	char* tmp = rawval_to_string(values[0].ptr, m_pt, m_pf, values[0].len);
	m_text = std::string(tmp);
	*len = m_text.size();
	return (uint8_t*)m_text.c_str();
}

// list

static const filtercheck_field_info list_check_fields[] = {
        {PT_CHARBUF, EPF_IS_LIST, PF_NA, "NA", "NA", "INTERNAL."},
};

list_check::list_check(const std::vector<std::string>& list) {
	static const filter_check_info s_field_infos = {
	        "",
	        "",
	        "",
	        sizeof(list_check_fields) / sizeof(list_check_fields[0]),
	        list_check_fields,
	        filter_check_info::FL_HIDDEN,
	};
	m_field = list_check_fields;
	m_info = &s_field_infos;
	m_field_id = 0;

	m_list.reserve(list.size());
	for(auto& v : list) {
		m_list.emplace_back(std::make_unique<rawstring_check>(v));
	}
}

list_check::list_check(std::vector<std::unique_ptr<sinsp_filter_check>>&& list) {
	static const filter_check_info s_field_infos = {
	        "",
	        "",
	        "",
	        sizeof(list_check_fields) / sizeof(list_check_fields[0]),
	        list_check_fields,
	        filter_check_info::FL_HIDDEN,
	};
	m_field = list_check_fields;
	m_info = &s_field_infos;
	m_field_id = 0;
	for(auto& chk : list) {
		if(chk->get_field_info()->is_numeric_type()) {
			auto p = std::make_unique<rawnum_check>(std::move(chk));
			m_list.emplace_back(std::move(p));
		} else {
			m_list.emplace_back(std::move(chk));
		}
	}
}

std::unique_ptr<sinsp_filter_check> list_check::allocate_new() {
	ASSERT(false);
	return nullptr;
}

int32_t list_check::parse_field_name(std::string_view,
                                     bool alloc_state,
                                     bool needed_for_filtering) {
	ASSERT(false);
	return -1;
}

bool list_check::extract_nocache(sinsp_evt* evt,
                                 std::vector<extract_value_t>& values,
                                 std::vector<extract_offset_t>*,
                                 bool sanitize_strings) {
	std::vector<extract_value_t> tmp;
	values.clear();
	for(auto& chk : m_list) {
		if(!chk->extract(evt, tmp, sanitize_strings)) {
			return false;
		}

		for(auto& v : tmp) {
			values.emplace_back(v);
		}
	}
	return true;
}
