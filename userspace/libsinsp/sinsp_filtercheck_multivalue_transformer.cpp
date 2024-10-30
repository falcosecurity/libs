//
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

#include <libsinsp/sinsp_filtercheck_multivalue_transformer.h>

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

std::unique_ptr<sinsp_filter_check> sinsp_filter_multivalue_transformer::create_transformer(
        const std::string& name,
        std::vector<std::unique_ptr<sinsp_filter_check>> args) {
	if(name == "join") {
		return std::make_unique<multivalue_transformer_filter_check>(
		        std::make_unique<sinsp_filter_multivalue_transformer_join>(std::move(args)));
	} else {
		throw std::runtime_error("unknown multivalue transformer");
	}
}
