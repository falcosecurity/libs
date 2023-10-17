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

#include "sinsp_filtercheck.h"

#define TEXT_ARG_ID -1000000

class sinsp_filter_check_reference;

class sinsp_filter_check_tracer : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_TIME,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_ENTERARGS,
		TYPE_ENTERARG,
		TYPE_DURATION,
		TYPE_DURATION_QUANTIZED,
		TYPE_DURATION_HUMAN,
		TYPE_TAGDURATION,
		TYPE_COUNT,
		TYPE_TAGCOUNT,
		TYPE_TAGCHILDSCOUNT,
		TYPE_IDTAG,
		TYPE_RAWTIME,
		TYPE_RAWPARENTTIME,
	};

	sinsp_filter_check_tracer();
	~sinsp_filter_check_tracer();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(std::string fldname, std::string val, OUT const struct ppm_param_info** parinfo);
	inline uint8_t* extract_duration(uint16_t etype, sinsp_tracerparser* eparser, OUT uint32_t* len);
	uint8_t* extract_args(sinsp_partial_tracer* pae, OUT uint32_t *len);
	uint8_t* extract_arg(sinsp_partial_tracer* pae, OUT uint32_t *len);

	int32_t m_argid;
	std::string m_argname;
	const char* m_cargname;
	char* m_storage;
	uint32_t m_storage_size;
	int64_t m_s64val;
	int32_t m_u32val;
	sinsp_filter_check_reference* m_converter;
	std::string m_strstorage;
};
