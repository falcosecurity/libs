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

#include <string>
#include <vector>
#include <memory>

class sinsp_filter_check;
class filter_check_info;
class sinsp;

//
// Global class that stores the list of filtercheck plugins and offers
// functions to work with it.
//
class filter_check_list
{
public:
	filter_check_list() = default;
	virtual ~filter_check_list() = default;

	void add_filter_check(std::unique_ptr<sinsp_filter_check> filter_check);
	void get_all_fields(std::vector<const filter_check_info*>&) const;
	std::unique_ptr<sinsp_filter_check> new_filter_check_from_fldname(const std::string& name, sinsp* inspector, bool do_exact_check) const;

protected:
	std::vector<std::unique_ptr<sinsp_filter_check>> m_check_list;
};

//
// This bakes in the "default" set of filterchecks that work with syscalls
class sinsp_filter_check_list : public filter_check_list
{
public:
	sinsp_filter_check_list();
	virtual ~sinsp_filter_check_list() = default;
};
