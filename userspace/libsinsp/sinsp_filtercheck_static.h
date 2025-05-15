// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
#include <map>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/version.h>
#include <libsinsp/filter.h>
#include <libsinsp/sinsp_filtercheck.h>

/**
    \brief This class implements a dynamic filter check that is
    loaded with user-defined filterchecks (a key-value map of filters)
 */
class sinsp_filter_check_static : public sinsp_filter_check {
public:
	sinsp_filter_check_static();

	explicit sinsp_filter_check_static(const std::map<std::string, std::string> filters);

	explicit sinsp_filter_check_static(const sinsp_filter_check_static& p);

	virtual ~sinsp_filter_check_static() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override;

protected:
	bool extract_nocache(sinsp_evt* evt,
	                     std::vector<extract_value_t>& values,
	                     std::vector<extract_offset_t>* offsets = nullptr,
	                     bool sanitize_strings = true) override;

private:
	std::map<std::string, std::string> m_filters;
	std::vector<filtercheck_field_info> m_info_fields;
};
