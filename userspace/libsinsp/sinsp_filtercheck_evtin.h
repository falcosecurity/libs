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

class sinsp_filter_check_evtin : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_P_ID,
		TYPE_P_NTAGS,
		TYPE_P_NARGS,
		TYPE_P_TAGS,
		TYPE_P_TAG,
		TYPE_P_ARGS,
		TYPE_P_ARG,
		TYPE_S_ID,
		TYPE_S_NTAGS,
		TYPE_S_NARGS,
		TYPE_S_TAGS,
		TYPE_S_TAG,
		TYPE_S_ARGS,
		TYPE_S_ARG,
		TYPE_M_ID,
		TYPE_M_NTAGS,
		TYPE_M_NARGS,
		TYPE_M_TAGS,
		TYPE_M_TAG,
		TYPE_M_ARGS,
		TYPE_M_ARG,
	};

	sinsp_filter_check_evtin();
	virtual ~sinsp_filter_check_evtin() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

private:
	int32_t extract_arg(std::string fldname, std::string val);

	std::string m_argname;
	int32_t m_argid;
};
