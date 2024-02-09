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

#include <memory>
#include <string>
#include <vector>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/version.h>
#include <libsinsp/filter.h>
#include <libsinsp/sinsp_filtercheck.h>

/**
	\brief This class implements a dynamic filter check that acts as a
	bridge to the plugin simplified field extraction implementations
 */
class sinsp_filter_check_plugin : public sinsp_filter_check
{
public:
	sinsp_filter_check_plugin();

	explicit sinsp_filter_check_plugin(std::shared_ptr<sinsp_plugin> plugin);

	explicit sinsp_filter_check_plugin(const sinsp_filter_check_plugin &p);

	virtual ~sinsp_filter_check_plugin() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

	int32_t parse_field_name(
		const char* str,
		bool alloc_state,
		bool needed_for_filtering) override;

	bool extract(
		sinsp_evt *evt,
		OUT std::vector<extract_value_t>& values,
		bool sanitize_strings = true) override;

private:
	std::string m_argstr;
	char* m_arg_key;
	uint64_t m_arg_index;
	bool m_arg_present;

	// This vector is an optimization to avoid a linear search
	// in the plugin source set.
	std::vector<bool> m_compatible_plugin_sources_bitmap;
	std::shared_ptr<sinsp_plugin> m_eplugin;

	// extract_arg_index() extracts a valid index from the argument if 
	// format is valid, otherwise it throws an exception.
	// `full_field_name` has the format "field[argument]" and it is necessary
	// to throw an exception.
	void extract_arg_index(const char* full_field_name);

	// extract_arg_key() extracts a valid string from the argument. If we pass
	// a numeric argument, it will be converted to string. 
	void extract_arg_key();
};
