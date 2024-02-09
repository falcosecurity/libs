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

#pragma once

#include <libsinsp/sinsp_filtercheck.h>

class sinsp_filter_check_reference : public sinsp_filter_check
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	sinsp_filter_check_reference();
	virtual ~sinsp_filter_check_reference() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

	inline void set_val(ppm_param_type type, filtercheck_field_flags flags,
		uint8_t* val, int32_t len,
		uint32_t cnt, ppm_print_format print_format)
	{
		m_finfo.m_type = type;
		m_finfo.m_flags = flags;
		m_val = val;
		m_len = len;
		m_cnt = cnt;
		m_print_format = print_format;
	}

	char* tostring_nice(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);
	using sinsp_filter_check::tojson; // to avoid warning: "... hides overloaded virtual function"
	Json::Value tojson(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);

private:
	inline char* format_bytes(double val, uint32_t str_len, bool is_int);
	inline char* format_time(uint64_t val, uint32_t str_len);
	char* print_double(uint8_t* rawval, uint32_t str_len);
	char* print_int(uint8_t* rawval, uint32_t str_len);

	filtercheck_field_info m_finfo;
	uint8_t* m_val;
	uint32_t m_len;
	double m_cnt;		// For averages, this stores the entry count
	ppm_print_format m_print_format;
};
