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

#pragma once

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
	        std::vector<std::unique_ptr<sinsp_filter_check>> args);

	sinsp_filter_multivalue_transformer(value_type_info result,
	                                    std::vector<std::unique_ptr<sinsp_filter_check>> args);
	virtual ~sinsp_filter_multivalue_transformer();

	value_type_info result_type() const;

	const std::vector<value_type_info>& argument_types();

	virtual std::unique_ptr<sinsp_filter_multivalue_transformer> clone() const;

	virtual std::string name() const;

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
	virtual ~sinsp_filter_multivalue_transformer_join();

	std::string name() const;

	virtual bool extract(sinsp_evt* evt,
	                     std::vector<extract_value_t>& values,
	                     bool sanitize_strings = true);

private:
	std::string m_res;
};
