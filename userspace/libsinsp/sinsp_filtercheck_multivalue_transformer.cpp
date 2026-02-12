//
// SPDX-License-Identifier: Apache-2.0
/*
  Copyright (C) 2026 The Falco Authors.
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

#include <libsinsp/sinsp_filtercheck_multivalue_transformer.h>
#include "driver/ppm_events_public.h"

sinsp_filter_multivalue_transformer::sinsp_filter_multivalue_transformer(
        value_type_info result,
        std::vector<std::unique_ptr<sinsp_filter_check>> args):
        m_result_type(result),
        m_arguments(std::move(args)) {}

sinsp_filter_multivalue_transformer::value_type_info
sinsp_filter_multivalue_transformer::result_type() const {
	return m_result_type;
};

const std::vector<sinsp_filter_multivalue_transformer::value_type_info>&
sinsp_filter_multivalue_transformer::argument_types() {
	// Lazily populate the argument types cache
	if(m_argument_types.empty() && !m_arguments.empty()) {
		for(const auto& arg : m_arguments) {
			const auto* field_info = arg->get_field_info();
			if(field_info) {
				m_argument_types.push_back({field_info->m_type, field_info->is_list()});
			} else {
				// Default to PT_NONE if field info is not available
				m_argument_types.push_back({PT_NONE, false});
			}
		}
	}
	return m_argument_types;
}

std::unique_ptr<sinsp_filter_multivalue_transformer> sinsp_filter_multivalue_transformer::clone()
        const {
	std::vector<std::unique_ptr<sinsp_filter_check>> new_args;
	for(auto& arg : m_arguments) {
		new_args.push_back(arg->allocate_new());
	}
	return std::make_unique<sinsp_filter_multivalue_transformer>(m_result_type,
	                                                             std::move(new_args));
}

std::string sinsp_filter_multivalue_transformer::name() const {
	return "";
};

bool sinsp_filter_multivalue_transformer::extract(sinsp_evt* evt,
                                                  std::vector<extract_value_t>& values,
                                                  bool sanitize_strings) {
	return false;
}

sinsp_filter_multivalue_transformer::~sinsp_filter_multivalue_transformer() = default;

// filter check

multivalue_transformer_filter_check::multivalue_transformer_filter_check(
        std::unique_ptr<sinsp_filter_multivalue_transformer> tr):
        m_transformer(std::move(tr)) {
	static const filter_check_info s_field_infos = {
	        "",
	        "",
	        "",
	        sizeof(multivalue_transformer_check_fields) /
	                sizeof(multivalue_transformer_check_fields[0]),
	        multivalue_transformer_check_fields,
	        filter_check_info::FL_HIDDEN,
	};
	m_field = multivalue_transformer_check_fields;
	m_info = &s_field_infos;
	m_field_id = 0;

	if(m_transformer && m_transformer->result_type().is_list) {
		m_transformed_field = std::make_unique<filtercheck_field_info>();
		m_transformed_field->m_flags = EPF_IS_LIST | EPF_ARG_ALLOWED;
		m_transformed_field->m_type = PT_CHARBUF;
		m_transformed_field->m_name = "INTERNAL";
		m_transformed_field->m_description = "NA";
		m_transformed_field->m_display = "NA";
	}
}

multivalue_transformer_filter_check::~multivalue_transformer_filter_check() = default;

const filter_check_info* multivalue_transformer_filter_check::get_fields() const {
	return m_info;
}

int32_t multivalue_transformer_filter_check::parse_field_name(std::string_view,
                                                              bool alloc_state,
                                                              bool needed_for_filtering) {
	ASSERT(false);
	return -1;
}

std::unique_ptr<sinsp_filter_check> multivalue_transformer_filter_check::allocate_new() {
	return std::make_unique<multivalue_transformer_filter_check>(m_transformer->clone());
}

// return a mock one (note, use sinsp_filter_multivalue_transformer::name)
const filtercheck_field_info* multivalue_transformer_filter_check::get_field_info() const {
	return multivalue_transformer_check_fields;
}

bool multivalue_transformer_filter_check::extract_nocache(sinsp_evt* evt,
                                                          std::vector<extract_value_t>& values,
                                                          std::vector<extract_offset_t>* offsets,
                                                          bool sanitize_strings) {
	// Extract values from the multivalue transformer
	// Outer transformers (e.g. len, b64) are applied by the base class extract()
	return m_transformer->extract(evt, values, sanitize_strings);
}

// join

sinsp_filter_multivalue_transformer_join::sinsp_filter_multivalue_transformer_join(
        std::vector<std::unique_ptr<sinsp_filter_check>> args):
        sinsp_filter_multivalue_transformer({PT_CHARBUF, false}, std::move(args)) {
	// Validate using argument_types()
	const auto& arg_types = argument_types();

	// join requires exactly 2 arguments (separator, list)
	if(arg_types.size() != 2) {
		throw sinsp_exception("join() requires exactly 2 arguments: separator and list");
	}

	// First argument (separator) must not be a list
	if(arg_types[0].is_list) {
		throw sinsp_exception(
		        "join() first argument (separator) must be a single value, not a list");
	}

	// Second argument must be a list
	if(!arg_types[1].is_list) {
		throw sinsp_exception("join() second argument must be a list");
	}
}

std::string
sinsp_filter_multivalue_transformer_join::sinsp_filter_multivalue_transformer_join::name() const {
	return "join";
}

bool sinsp_filter_multivalue_transformer_join::extract(sinsp_evt* evt,
                                                       std::vector<extract_value_t>& values,
                                                       bool sanitize_strings) {
	values.clear();
	if(!m_arguments.at(0)->extract(evt, values, sanitize_strings)) {
		return false;
	}
	std::string_view sep((char*)values[0].ptr, values[0].len);

	values.clear();
	if(!m_arguments.at(1)->extract(evt, values, sanitize_strings)) {
		return false;
	}
	m_res.clear();
	for(std::size_t i = 0; i < values.size(); i++) {
		// here we don't do this:
		// m_res.append((char*)values[i].ptr, values[i].len);
		// because, in case of transformed values, the null
		// terminator is already present and forcelly pushed
		// causing comparisons to fail.
		m_res.append((char*)values[i].ptr);
		if(i != values.size() - 1) {
			m_res.append(sep);
		}
	}

	extract_value_t val{(uint8_t*)m_res.c_str(), (uint32_t)m_res.length()};
	values.clear();
	values.push_back(val);
	return true;
}

sinsp_filter_multivalue_transformer_join::~sinsp_filter_multivalue_transformer_join() = default;

// concat

sinsp_filter_multivalue_transformer_concat::sinsp_filter_multivalue_transformer_concat(
        std::vector<std::unique_ptr<sinsp_filter_check>> args):
        sinsp_filter_multivalue_transformer({PT_CHARBUF, false}, std::move(args)) {
	// Validate using argument_types()
	const auto& arg_types = argument_types();

	// concat requires at least 2 arguments
	if(arg_types.size() < 2) {
		throw sinsp_exception("concat() requires at least 2 arguments");
	}

	for(const auto& arg_t : arg_types) {
		if(arg_t.type != PT_CHARBUF || arg_t.is_list) {
			throw sinsp_exception("concat() arguments must be strings");
		}
	}
}

std::string
sinsp_filter_multivalue_transformer_concat::sinsp_filter_multivalue_transformer_concat::name()
        const {
	return "concat";
}

bool sinsp_filter_multivalue_transformer_concat::extract(sinsp_evt* evt,
                                                         std::vector<extract_value_t>& values,
                                                         bool sanitize_strings) {
	m_res.clear();
	for(const auto& arg : m_arguments) {
		values.clear();
		if(!arg->extract(evt, values, sanitize_strings)) {
			return false;
		}
		m_res.append((char*)values[0].ptr);
	}

	extract_value_t val{(uint8_t*)m_res.c_str(), (uint32_t)m_res.length()};
	values.clear();
	values.push_back(val);
	return true;
}

sinsp_filter_multivalue_transformer_concat::~sinsp_filter_multivalue_transformer_concat() = default;

// getopt

sinsp_filter_multivalue_transformer_getopt::sinsp_filter_multivalue_transformer_getopt(
        std::vector<std::unique_ptr<sinsp_filter_check>> args):
        sinsp_filter_multivalue_transformer({PT_CHARBUF, true}, std::move(args)) {
	// Validate using argument_types()
	const auto& arg_types = argument_types();

	// getopt requires exactly 2 arguments
	if(arg_types.size() != 2) {
		throw sinsp_exception("getopt() requires exactly 2 arguments: args list and optstring");
	}

	// First argument (args) must be a list
	if(!arg_types[0].is_list) {
		throw sinsp_exception("getopt() first argument must be a list");
	}

	// Second argument (optstring) must not be a list
	if(arg_types[1].is_list) {
		throw sinsp_exception("getopt() second argument (optstring) must be a single value");
	}

	// Both arguments must be strings
	if(arg_types[0].type != PT_CHARBUF || arg_types[1].type != PT_CHARBUF) {
		throw sinsp_exception("getopt() arguments must be strings");
	}
}

std::string sinsp_filter_multivalue_transformer_getopt::name() const {
	return "getopt";
}

bool sinsp_filter_multivalue_transformer_getopt::extract(sinsp_evt* evt,
                                                         std::vector<extract_value_t>& values,
                                                         bool sanitize_strings) {
	// Extract the optstring (second argument)
	values.clear();
	if(!m_arguments.at(1)->extract(evt, values, sanitize_strings)) {
		return false;
	}
	// Copy optstring to avoid pointer invalidation when values is cleared
	std::string optstring((char*)values[0].ptr, values[0].len);

	// Build a lookup table for which options require arguments
	bool opts_with_args[256] = {};
	for(size_t i = 0; i < optstring.size(); i++) {
		unsigned char opt = static_cast<unsigned char>(optstring[i]);
		if(i + 1 < optstring.size() && optstring[i + 1] == ':') {
			opts_with_args[opt] = true;
			i++;  // Skip the ':'
		}
	}

	// Extract the arguments list (first argument)
	values.clear();
	if(!m_arguments.at(0)->extract(evt, values, sanitize_strings)) {
		return false;
	}

	// Parse the arguments following POSIX getopt conventions
	m_result_storage.clear();
	m_storage.clear();

	for(size_t arg_idx = 0; arg_idx < values.size(); arg_idx++) {
		const char* arg_ptr = (char*)values[arg_idx].ptr;
		size_t arg_len = values[arg_idx].len;

		// Stop processing at "--"
		if(arg_len == 2 && arg_ptr[0] == '-' && arg_ptr[1] == '-') {
			break;
		}

		// Skip non-option arguments (doesn't start with - or is just -)
		// Continue processing to support GNU extension (options after non-options)
		if(arg_len == 0 || arg_ptr[0] != '-' || arg_len == 1) {
			continue;
		}

		// Process each character after the '-'
		for(size_t i = 1; i < arg_len; i++) {
			unsigned char opt = static_cast<unsigned char>(arg_ptr[i]);

			// Check if this option is alphanumeric
			if(!std::isalnum(opt)) {
				continue;
			}

			// Check if this option is in the optstring
			bool found = false;
			for(size_t j = 0; j < optstring.size(); j++) {
				if(optstring[j] == static_cast<char>(opt) && optstring[j] != ':') {
					found = true;
					break;
				}
			}
			if(!found) {
				continue;
			}

			// Add the option character to result
			// Use emplace_back to construct in-place and avoid extra allocation
			m_result_storage.emplace_back(1, static_cast<char>(opt));

			// Check if this option requires an argument
			if(opts_with_args[opt]) {
				// Option value can be:
				// 1. Remainder of current argument (e.g., -ofoo same as -o foo)
				// 2. Next argument (e.g., -o foo)
				if(i + 1 < arg_len) {
					// Value is remainder of current argument
					m_result_storage.emplace_back(arg_ptr + i + 1, arg_len - i - 1);
					break;  // Done with this argument
				} else if(arg_idx + 1 < values.size()) {
					// Value is next argument
					arg_idx++;
					m_result_storage.emplace_back((char*)values[arg_idx].ptr, values[arg_idx].len);
					break;  // Done with this argument
				} else {
					// No value available, use empty string
					m_result_storage.emplace_back();
				}
			}
		}
	}

	// Convert result storage to extract_value_t format
	values.clear();
	values.reserve(m_result_storage.size());
	// Calculate exact space needed and reserve to prevent reallocation (would invalidate pointers)
	size_t total_size = 0;
	for(const auto& str : m_result_storage) {
		total_size += str.size() + 1;  // +1 for null terminator
	}
	m_storage.reserve(total_size);

	for(const auto& str : m_result_storage) {
		size_t offset = m_storage.size();
		m_storage.insert(m_storage.end(), str.begin(), str.end());
		m_storage.push_back('\0');
		values.emplace_back(extract_value_t{&m_storage[offset], static_cast<uint32_t>(str.size())});
	}

	return true;
}

sinsp_filter_multivalue_transformer_getopt::~sinsp_filter_multivalue_transformer_getopt() = default;

std::unique_ptr<sinsp_filter_check> sinsp_filter_multivalue_transformer::create_transformer(
        const std::string& name,
        std::vector<std::unique_ptr<sinsp_filter_check>> args) {
	if(name == "join") {
		return std::make_unique<multivalue_transformer_filter_check>(
		        std::make_unique<sinsp_filter_multivalue_transformer_join>(std::move(args)));
	} else if(name == "concat") {
		return std::make_unique<multivalue_transformer_filter_check>(
		        std::make_unique<sinsp_filter_multivalue_transformer_concat>(std::move(args)));
	} else if(name == "getopt") {
		return std::make_unique<multivalue_transformer_filter_check>(
		        std::make_unique<sinsp_filter_multivalue_transformer_getopt>(std::move(args)));
	} else {
		throw std::runtime_error("unknown multivalue transformer");
	}
}
