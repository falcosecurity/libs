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

class sinsp_filter_check_gen_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NUMBER = 0,
		TYPE_TIME = 1,
		TYPE_TIME_S = 2,
		TYPE_TIME_ISO8601 = 3,
		TYPE_DATETIME = 4,
		TYPE_DATETIME_S = 5,
		TYPE_RAWTS = 6,
		TYPE_RAWTS_S = 7,
		TYPE_RAWTS_NS = 8,
		TYPE_RELTS = 9,
		TYPE_RELTS_S = 10,
		TYPE_RELTS_NS = 11,
		TYPE_PLUGINNAME = 12,
		TYPE_PLUGININFO = 13,
		TYPE_SOURCE = 14,
		TYPE_ISASYNC = 15,
		TYPE_ASYNCTYPE = 16,
		TYPE_HOSTNAME = 17,
	};

	sinsp_filter_check_gen_event();
	virtual ~sinsp_filter_check_gen_event() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

protected:
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;
	Json::Value extract_as_js(sinsp_evt*, OUT uint32_t* len) override;

private:
	uint64_t m_u64val;
	uint32_t m_u32val;
	std::string m_strstorage;
};
