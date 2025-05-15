// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <libsinsp/sinsp_filtercheck_static.h>

static const std::string s_static_prefix = "static.";

using namespace std;
sinsp_filter_check_static::sinsp_filter_check_static() {
	static const filter_check_info s_no_static_fields_info = {
	        "static",
	        "",
	        "Static, user-defined filters",
	        0,
	        nullptr,
	        filter_check_info::FL_NONE,
	};
	m_info = &s_no_static_fields_info;
}

sinsp_filter_check_static::sinsp_filter_check_static(
        const std::unordered_map<std::string, std::string> filters) {
	m_filters = filters;

	m_info_fields.resize(m_filters.size());

	int i = 0;
	for(const auto& f : m_filters) {
		// String only supported
		m_info_fields[i].m_type = ppm_param_type::PT_CHARBUF;
		// Automatically suggest it for output print format
		m_info_fields[i].m_flags = EPF_FORMAT_SUGGESTED;
		m_info_fields[i].m_print_format = ppm_print_format::PF_NA;
		// Prepend `static.` prefix
		m_info_fields[i].m_name = s_static_prefix + f.first;
		// No display name, no description

		i++;
	}

	static const filter_check_info s_static_fields_info = {
	        "static",
	        "",
	        "Static, user-defined filters",
	        (int32_t)m_filters.size(),
	        &m_info_fields[0],  // we use a vector so this should be safe
	        filter_check_info::FL_NONE,
	};
	m_info = &s_static_fields_info;
}

sinsp_filter_check_static::sinsp_filter_check_static(const sinsp_filter_check_static& p):
        sinsp_filter_check_static(p.m_filters) {}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_static::allocate_new() {
	return std::make_unique<sinsp_filter_check_static>(*this);
}

bool sinsp_filter_check_static::extract_nocache(sinsp_evt* evt,
                                                std::vector<extract_value_t>& values,
                                                std::vector<extract_offset_t>* offsets,
                                                bool sanitize_strings) {
	// note: use non-transformed type, we'll apply transformations later on
	auto type = sinsp_filter_check::get_field_info()->m_type;

	const auto& fld_name = m_info->m_fields[m_field_id].m_name;
	const auto& stripped_name = fld_name.substr(s_static_prefix.length());
	if(m_filters.find(stripped_name) == m_filters.end()) {
		return false;
	}
	const auto& val = m_filters[stripped_name];

	if(offsets) {
		offsets->clear();
	}
	values.clear();

	extract_value_t res;
	switch(type) {
	case PT_CHARBUF: {
		res.len = val.length();
		res.ptr = (uint8_t*)val.data();
		break;
	}
	default:
		ASSERT(false);
		throw sinsp_exception("static extract error: unsupported field type " + to_string(type));
		break;
	}
	values.push_back(res);

	if(offsets) {
		offsets->emplace_back(extract_offset_t{UINT32_MAX, UINT32_MAX});
	}

	return true;
}
