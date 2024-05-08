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

class rawstring_check : public sinsp_filter_check
{
public:
	rawstring_check(const std::string& text);
	virtual ~rawstring_check() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;
	int32_t parse_field_name(std::string_view, bool alloc_state, bool needed_for_filtering) override;
	uint8_t* extract_single(sinsp_evt*, uint32_t* len, bool sanitize_strings = true) override;

private:
	std::string m_text;
};
