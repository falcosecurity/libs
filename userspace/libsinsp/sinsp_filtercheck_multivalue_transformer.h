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

#pragma once

#include <array>
#include <optional>
#include <string_view>

#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/sinsp_filter_transformers.h>

static const filtercheck_field_info multivalue_transformer_check_fields[] = {
        {PT_CHARBUF, EPF_NONE, PF_NA, "NA", "NA", "INTERNAL."},
};

class sinsp_filter_multivalue_transformer {
public:
	using storage_t = std::vector<uint8_t>;

	struct value_type_info {
		ppm_param_type type;
		bool is_list;
	};

	static std::unique_ptr<sinsp_filter_check> create_transformer(
	        const std::string& name,
	        std::vector<std::unique_ptr<sinsp_filter_check>> args,
	        const std::optional<std::string>& arg = std::nullopt);

	sinsp_filter_multivalue_transformer(value_type_info result,
	                                    std::vector<std::unique_ptr<sinsp_filter_check>> args);
	virtual ~sinsp_filter_multivalue_transformer();

	value_type_info result_type() const;

	const std::vector<value_type_info>& argument_types();

	virtual std::unique_ptr<sinsp_filter_multivalue_transformer> clone() const;

	virtual std::string name() const;
	virtual bool supports_arg() const;
	virtual void set_arg(std::optional<std::string> arg);

	virtual bool extract(sinsp_evt* evt,
	                     std::vector<extract_value_t>& values,
	                     bool sanitize_strings = true);

protected:
	value_type_info m_result_type;
	std::vector<std::unique_ptr<sinsp_filter_check>> m_arguments;
	std::vector<value_type_info> m_argument_types;
};

class multivalue_transformer_filter_check : public sinsp_filter_check {
public:
	multivalue_transformer_filter_check(std::unique_ptr<sinsp_filter_multivalue_transformer> tr);
	virtual ~multivalue_transformer_filter_check();

	const filter_check_info* get_fields() const override;
	int32_t parse_field_name(std::string_view,
	                         bool alloc_state,
	                         bool needed_for_filtering) override;

	bool has_filtercheck_value() const override { return false; }

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

	// return a mock one (note, use sinsp_filter_multivalue_transformer::name)
	const filtercheck_field_info* get_field_info() const override;

protected:
	bool extract_nocache(sinsp_evt* evt,
	                     std::vector<extract_value_t>& values,
	                     std::vector<extract_offset_t>* offsets,
	                     bool sanitize_strings = true) override;

private:
	std::unique_ptr<sinsp_filter_multivalue_transformer> m_transformer;
};

// join
class sinsp_filter_multivalue_transformer_join : public sinsp_filter_multivalue_transformer {
public:
	sinsp_filter_multivalue_transformer_join(std::vector<std::unique_ptr<sinsp_filter_check>> args);
	~sinsp_filter_multivalue_transformer_join() override;

	std::string name() const override;

	bool extract(sinsp_evt* evt,
	             std::vector<extract_value_t>& values,
	             bool sanitize_strings = true) override;

private:
	std::string m_res;
};

// concat
class sinsp_filter_multivalue_transformer_concat : public sinsp_filter_multivalue_transformer {
public:
	sinsp_filter_multivalue_transformer_concat(
	        std::vector<std::unique_ptr<sinsp_filter_check>> args);
	~sinsp_filter_multivalue_transformer_concat() override;

	std::string name() const override;

	bool extract(sinsp_evt* evt,
	             std::vector<extract_value_t>& values,
	             bool sanitize_strings = true) override;

private:
	std::string m_res;
};

// getopt
// Parses short options following POSIX getopt(3) conventions.
// Non-alphanumeric option characters (e.g. '@', '+') are accepted as an
// intentional extension beyond strict POSIX, which only defines alphanumeric
// option characters.
// GNU extensions like optional arguments (double-colon '::' in optstring) are
// intentionally unsupported; a second ':' is silently ignored during parsing.
class sinsp_filter_multivalue_transformer_getopt : public sinsp_filter_multivalue_transformer {
public:
	sinsp_filter_multivalue_transformer_getopt(
	        std::vector<std::unique_ptr<sinsp_filter_check>> args);
	~sinsp_filter_multivalue_transformer_getopt() override;

	std::string name() const override;
	bool supports_arg() const override;
	void set_arg(std::optional<std::string> arg) override;

	bool extract(sinsp_evt* evt,
	             std::vector<extract_value_t>& values,
	             bool sanitize_strings = true) override;

private:
	struct getopt_optstring_info {
		bool missing_arg_returns_colon = false;
		std::array<bool, 256> valid_opts = {};
		std::array<bool, 256> opts_with_args = {};
	};

	using result_ref = std::pair<size_t, uint32_t>;

	static getopt_optstring_info parse_optstring(std::string_view optstring);
	const getopt_optstring_info* get_optinfo(sinsp_evt* evt,
	                                         std::vector<extract_value_t>& values,
	                                         bool sanitize_strings);
	std::optional<std::string_view> get_option_argument(
	        size_t& arg_idx,
	        size_t opt_idx,
	        std::string_view arg,
	        const std::vector<extract_value_t>& values) const;
	std::pair<size_t, uint32_t> append_result(std::string_view str);
	void emit_option_result(std::vector<result_ref>& results,
	                        std::optional<result_ref>& selected_result,
	                        bool has_selector,
	                        std::string_view option_name,
	                        std::optional<std::string_view> option_value);

	std::optional<std::string> m_arg;
	storage_t m_storage;
	bool m_has_constant_optinfo = false;
	getopt_optstring_info m_constant_optinfo;
	bool m_has_last_optinfo = false;
	std::string m_last_optstring;
	getopt_optstring_info m_last_optinfo;
};
