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
#include <libsinsp/filter_cache.h>

enum filter_transformer_type : uint8_t {
	FTR_TOUPPER = 0,
	FTR_TOLOWER = 1,
	FTR_BASE64 = 2,
	FTR_STORAGE = 3,  // This transformer is only used internally
	FTR_BASENAME = 4,
	FTR_LEN = 5
};

struct filter_transformer_info {
	// The name of the transformer
	std::string name;

	// A description of the transformer
	std::string desc;
};

static const filter_transformer_info sinsp_filter_transformer_info[] = {
        {"toupper", "Converts the field to uppercase"},
        {"tolower", "Converts the field to lowercase"},
        {"b64", "Decodes the field from base64"},
        {"storage", "Stores the field in memory (internal only)"},
        {"basename", "Extracts the basename from a path"},
        {"len", "Returns the length of the field"}};

constexpr static size_t filter_transformer_len =
        sizeof(sinsp_filter_transformer_info) / sizeof(sinsp_filter_transformer_info[0]);

static inline std::string filter_transformer_type_str(filter_transformer_type m) {
	if((size_t)m >= filter_transformer_len) {
		throw sinsp_exception("unknown field transformer id " + std::to_string(m));
	}
	return sinsp_filter_transformer_info[m].name;
}

static inline filter_transformer_type filter_transformer_from_str(const std::string& str) {
	for(size_t i = 0; i < filter_transformer_len; i++) {
		if(sinsp_filter_transformer_info[i].name == str) {
			return (filter_transformer_type)i;
		}
	}
	throw sinsp_exception("unknown field transfomer '" + str + "'");
}

class sinsp_filter_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	sinsp_filter_transformer(filter_transformer_type t): m_type(t) {};

	bool transform_type(ppm_param_type& t, uint32_t& flags) const;

	bool transform_values(std::vector<extract_value_t>& vals, ppm_param_type& t, uint32_t& flags);

private:
	using str_transformer_func_t = std::function<bool(std::string_view in, storage_t& out)>;

	bool string_transformer(std::vector<extract_value_t>& vec,
	                        ppm_param_type t,
	                        str_transformer_func_t mod);

	template<class T>
	extract_value_t store_scalar(T value) {
		uint8_t* bytes = reinterpret_cast<uint8_t*>(&value);
		storage_t& stored_val = m_storage_values.emplace_back(bytes, bytes + sizeof(T));
		return {static_cast<uint8_t*>(stored_val.data()), static_cast<uint32_t>(stored_val.size())};
	}

	filter_transformer_type m_type;
	std::vector<storage_t> m_storage_values;
};
