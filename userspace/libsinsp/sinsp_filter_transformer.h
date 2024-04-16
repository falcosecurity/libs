// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <driver/ppm_events_public.h>
#include <libsinsp/sinsp_exception.h>

struct extract_value_t
{
	uint8_t* ptr = nullptr;
	uint32_t len = 0;
};

enum filter_transformer_type: uint8_t
{
	FTR_TOUPPER = 0,
	FTR_TOLOWER = 1,
	FTR_BASE64 = 2,
	FTR_STORAGE = 3, // This transformer is only used internally
};

static inline std::string filter_transformer_type_str(filter_transformer_type m)
{
	switch(m)
	{
	case FTR_TOUPPER:
		return "toupper";
	case FTR_TOLOWER:
		return "tolower";
	case FTR_BASE64:
		return "b64";
	case FTR_STORAGE:
		return "storage";
	default:
		throw sinsp_exception("unknown field transfomer id " + std::to_string(m));
	}
}

static inline filter_transformer_type filter_transformer_from_str(const std::string& str)
{
	if (str == "tolower")
	{
		return filter_transformer_type::FTR_TOLOWER;
	}
	if (str == "toupper")
	{
		return filter_transformer_type::FTR_TOUPPER;
	}
	if (str == "b64")
	{
		return filter_transformer_type::FTR_BASE64;
	}
	if (str == "storage")
	{
		return filter_transformer_type::FTR_STORAGE;
	}
	throw sinsp_exception("unknown field transfomer '" + str + "'");
}

class sinsp_filter_transformer
{
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_transformer(filter_transformer_type t): m_type(t) { };

	bool transform_type(ppm_param_type& t) const;

	bool transform_values(std::vector<extract_value_t>& vals, ppm_param_type& t);

private:
	using str_transformer_func_t = std::function<bool(std::string_view in, storage_t& out)>;

	bool string_transformer(std::vector<extract_value_t>& vec, ppm_param_type t, str_transformer_func_t mod);

	filter_transformer_type m_type;
	std::vector<storage_t> m_storage_values;
};
