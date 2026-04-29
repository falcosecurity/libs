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
#include <libsinsp/sinsp_filtercheck_rawstring.h>

#include <array>
#include <string_view>

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

bool sinsp_filter_multivalue_transformer::supports_arg() const {
	return false;
}

void sinsp_filter_multivalue_transformer::set_arg(std::optional<std::string> arg) {
	if(arg) {
		throw sinsp_exception("transformer '" + name() + "' does not support field arguments");
	}
}

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
		auto field = std::make_unique<filtercheck_field_info>();
		field->m_flags = EPF_IS_LIST;
		if(m_transformer->supports_arg()) {
			field->m_flags |= EPF_ARG_ALLOWED | EPF_ARG_KEY;
		}
		field->m_type = PT_CHARBUF;
		field->m_name = "INTERNAL";
		field->m_description = "NA";
		field->m_display = "NA";
		set_transformed_field(std::move(field));
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

	// When the optstring is a literal, the compiler materializes it as a
	// rawstring_check. Decode it once here so extract() can skip reparsing it
	// for every event.
	if(auto* raw_optstring = dynamic_cast<rawstring_check*>(m_arguments[1].get());
	   raw_optstring != nullptr) {
		uint32_t len = 0;
		auto* ptr = raw_optstring->extract_single(nullptr, &len, false);
		m_constant_optinfo =
		        parse_optstring(std::string_view(reinterpret_cast<const char*>(ptr), len));
		m_has_constant_optinfo = true;
	}
}

std::string sinsp_filter_multivalue_transformer_getopt::name() const {
	return "getopt";
}

bool sinsp_filter_multivalue_transformer_getopt::supports_arg() const {
	return true;
}

void sinsp_filter_multivalue_transformer_getopt::set_arg(std::optional<std::string> arg) {
	if(!arg) {
		m_arg = std::nullopt;
		m_result_type = {PT_CHARBUF, true};
		return;
	}
	if(arg->size() != 1) {
		throw sinsp_exception("getopt() field argument must be a single option character");
	}
	m_arg = std::move(arg);
	m_result_type = {PT_CHARBUF, false};
}

sinsp_filter_multivalue_transformer_getopt::getopt_optstring_info
sinsp_filter_multivalue_transformer_getopt::parse_optstring(std::string_view optstring) {
	getopt_optstring_info info;

	info.missing_arg_returns_colon = !optstring.empty() && optstring[0] == ':';
	size_t opt_idx = info.missing_arg_returns_colon ? 1 : 0;
	for(; opt_idx < optstring.size(); opt_idx++) {
		unsigned char opt = static_cast<unsigned char>(optstring[opt_idx]);
		if(opt == ':') {
			continue;
		}
		info.valid_opts[opt] = true;
		if(opt_idx + 1 < optstring.size() && optstring[opt_idx + 1] == ':') {
			info.opts_with_args[opt] = true;
			opt_idx++;
		}
	}

	return info;
}

const sinsp_filter_multivalue_transformer_getopt::getopt_optstring_info*
sinsp_filter_multivalue_transformer_getopt::get_optinfo(sinsp_evt* evt,
                                                        std::vector<extract_value_t>& values,
                                                        bool sanitize_strings) {
	if(m_has_constant_optinfo) {
		return &m_constant_optinfo;
	}

	values.clear();
	// getopt() needs one concrete optstring value. If extraction fails or
	// yields no values, there is nothing meaningful to parse.
	if(!m_arguments.at(1)->extract(evt, values, sanitize_strings) || values.empty()) {
		return nullptr;
	}

	std::string_view optstring(reinterpret_cast<const char*>(values[0].ptr), values[0].len);
	// For non-literal optstrings, i.e. optstrings extracted from an event field
	// instead of a constant rawstring_check, reparse only when the bytes change.
	// We copy the current string_view into owned storage before decoding so the
	// cached optinfo always refers to stable memory.
	if(!m_has_last_optinfo || m_last_optstring != optstring) {
		m_last_optstring.assign(optstring.data(), optstring.size());
		m_last_optinfo = parse_optstring(m_last_optstring);
		m_has_last_optinfo = true;
	}

	return &m_last_optinfo;
}

std::optional<std::string_view> sinsp_filter_multivalue_transformer_getopt::get_option_argument(
        size_t& arg_idx,
        size_t opt_idx,
        std::string_view arg,
        const std::vector<extract_value_t>& values) const {
	if(opt_idx + 1 < arg.size()) {
		return arg.substr(opt_idx + 1);
	}

	if(arg_idx + 1 >= values.size()) {
		return std::nullopt;
	}

	arg_idx++;
	return std::string_view(reinterpret_cast<const char*>(values[arg_idx].ptr),
	                        values[arg_idx].len);
}

std::pair<size_t, uint32_t> sinsp_filter_multivalue_transformer_getopt::append_result(
        std::string_view str) {
	size_t offset = m_storage.size();
	m_storage.insert(m_storage.end(), str.begin(), str.end());
	m_storage.push_back('\0');
	return {offset, static_cast<uint32_t>(str.size())};
}

void sinsp_filter_multivalue_transformer_getopt::emit_option_result(
        std::vector<result_ref>& results,
        std::optional<result_ref>& selected_result,
        bool has_selector,
        std::string_view option_name,
        std::optional<std::string_view> option_value) {
	if(has_selector) {
		selected_result = append_result(option_value.value_or(option_name));
		return;
	}

	results.push_back(append_result(option_name));
	if(option_value.has_value()) {
		results.push_back(append_result(*option_value));
	}
}

bool sinsp_filter_multivalue_transformer_getopt::extract(sinsp_evt* evt,
                                                         std::vector<extract_value_t>& values,
                                                         bool sanitize_strings) {
	// The second argument is the getopt(3) optstring. Extract it first and
	// decode it into two lookup tables:
	// - which option characters are valid
	// - which option characters require a following value
	//
	// We also remember whether a leading ':' is present, because that changes
	// the missing-argument error from '?' to ':'.
	const getopt_optstring_info* optinfo = get_optinfo(evt, values, sanitize_strings);
	if(optinfo == nullptr) {
		return false;
	}

	// The first argument is argv. Extract it and then scan it token-by-token
	// using getopt-like rules:
	// - stop at bare "--"
	// - skip unsupported long options like "--exec"
	// - stop at the first non-option token
	// - expand short-option clusters like "-nt"
	//
	// Results are appended directly into m_storage and recorded as offsets.
	// We build extract_value_t views only at the end, once the storage buffer
	// is stable and no further growth can invalidate pointers.
	values.clear();
	if(!m_arguments.at(0)->extract(evt, values, sanitize_strings)) {
		return false;
	}

	m_storage.clear();
	// Each result is tracked as an (offset, length) pair into m_storage until
	// we materialize the final extract_value_t views at the end of extraction.
	std::vector<std::pair<size_t, uint32_t>> results;

	// In selector mode, e.g. getopt(...)[t], we keep only the last matching
	// option/value instead of emitting the full getopt result stream.
	const bool has_selector = m_arg.has_value();
	const unsigned char selector = has_selector ? static_cast<unsigned char>((*m_arg)[0]) : 0;
	std::optional<std::pair<size_t, uint32_t>> selected_result;

	// Walk argv entries in order, applying getopt's top-level stopping rules
	// before scanning any short-option cluster inside the current token.
	for(size_t arg_idx = 0; arg_idx < values.size(); arg_idx++) {
		std::string_view arg(reinterpret_cast<const char*>(values[arg_idx].ptr),
		                     values[arg_idx].len);

		// "--" is the standard end-of-options marker.
		if(arg == "--") {
			break;
		}

		// Long options are intentionally unsupported here. Skip tokens like
		// "--exec" so they are not misparsed as clusters of short options.
		if(arg.size() > 2 && arg[0] == '-' && arg[1] == '-') {
			continue;
		}

		// getopt() stops as soon as it reaches the first non-option argument.
		if(arg.empty() || arg[0] != '-' || arg.size() == 1) {
			break;
		}

		// Consume one short option at a time from a token like "-ntvalue".
		for(size_t i = 1; i < arg.size(); i++) {
			unsigned char opt = static_cast<unsigned char>(arg[i]);
			const bool valid_opt = opt != ':' && optinfo->valid_opts[opt];

			// Unknown options yield '?' in list mode. In selector mode they are
			// irrelevant because only one requested option can match.
			if(!valid_opt) {
				if(!has_selector) {
					results.push_back(append_result("?"));
				}
				continue;
			}

			// Normalize the current short option into the pieces used below:
			// whether it matches the requested selector, whether it expects an
			// argument, and its one-character textual representation.
			const bool selector_match = !has_selector || opt == selector;
			const bool option_requires_arg = optinfo->opts_with_args[opt];
			std::string_view option_name = arg.substr(i, 1);

			// Options without arguments emit just their option character.
			if(selector_match && !option_requires_arg) {
				emit_option_result(results,
				                   selected_result,
				                   has_selector,
				                   option_name,
				                   std::nullopt);
			}

			if(!option_requires_arg) {
				continue;
			}

			// Options requiring an argument accept either the rest of the current
			// token (e.g. "-tvalue") or the next argv entry (e.g. "-t value").
			auto option_value = get_option_argument(arg_idx, i, arg, values);
			if(!option_value.has_value()) {
				if(selector_match) {
					// Missing arguments are represented as an empty value. This
					// keeps selector mode useful for scalar comparisons like
					// getopt(...)[t] != "" while preserving real attached values
					// such as -t? and -t: as non-empty strings.
					emit_option_result(results, selected_result, has_selector, "", std::nullopt);
				}
				break;
			}

			// In list mode we emit both the option and its value, matching the
			// existing transformer contract. In selector mode we keep only the
			// selected value, with last-match-wins semantics handled below.
			if(selector_match) {
				emit_option_result(results,
				                   selected_result,
				                   has_selector,
				                   option_name,
				                   *option_value);
			}
			break;
		}
	}

	// Selector mode behaves like a keyed lookup: only the last matching value
	// is observable. If the selected option was absent, extraction fails so
	// scalar comparisons do not evaluate against an empty result vector.
	if(has_selector && !selected_result.has_value()) {
		values.clear();
		return false;
	}
	if(has_selector) {
		results.clear();
		results.push_back(*selected_result);
	}

	// Finally, convert the stored offsets into extract_value_t views.
	values.clear();
	values.reserve(results.size());
	for(const auto& [offset, len] : results) {
		values.emplace_back(extract_value_t{&m_storage[offset], len});
	}

	return true;
}

sinsp_filter_multivalue_transformer_getopt::~sinsp_filter_multivalue_transformer_getopt() = default;

std::unique_ptr<sinsp_filter_check> sinsp_filter_multivalue_transformer::create_transformer(
        const std::string& name,
        std::vector<std::unique_ptr<sinsp_filter_check>> args,
        const std::optional<std::string>& arg) {
	std::unique_ptr<sinsp_filter_multivalue_transformer> transformer;
	if(name == "join") {
		transformer = std::make_unique<sinsp_filter_multivalue_transformer_join>(std::move(args));
	} else if(name == "concat") {
		transformer = std::make_unique<sinsp_filter_multivalue_transformer_concat>(std::move(args));
	} else if(name == "getopt") {
		transformer = std::make_unique<sinsp_filter_multivalue_transformer_getopt>(std::move(args));
	} else {
		throw std::runtime_error("unknown multivalue transformer");
	}

	transformer->set_arg(arg);
	return std::make_unique<multivalue_transformer_filter_check>(std::move(transformer));
}
