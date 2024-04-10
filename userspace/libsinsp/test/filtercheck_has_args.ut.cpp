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

#include <gtest/gtest.h>

#include <sinsp.h>
#include <filter_check_list.h>
#include <sinsp_filtercheck.h>

TEST(filtercheck_has_args, has_args)
{
	sinsp_filter_check_list sinsp_filter_checks;
	sinsp inspector;

	std::vector<const filter_check_info *> checks_info;

	sinsp_filter_checks.get_all_fields(checks_info);

	for(auto& check_info : checks_info)
	{
		for(int32_t i = 0; i < check_info->m_nfields; i++)
		{
			const filtercheck_field_info *field_info = &(check_info->m_fields[i]);
			std::string field_str = field_info->m_name;
			bool expected = false;

			if((field_info->m_flags & EPF_DEPRECATED))
			{
				continue;
			}

			if((field_info->m_flags & EPF_ARG_REQUIRED) ||
			   (field_info->m_flags & EPF_ARG_ALLOWED))
			{
				expected = true;

				// A few fields explicitly require
				// .xxx arguments. For others, just
				// use a generic bracket based
				// argument.
				if(field_str == "evt.type.is")
				{
					field_str += ".open";
				}
				else if (field_str == "evt.arg" ||
					field_str == "evt.rawarg")
				{
					field_str += ".res";
				}
				else if (field_str == "thread.cgroup")
				{
					field_str += ".cpuacct";
				}
				else
				{
					field_str += "[1]";
				}
			}

			bool alloc_state = true;
			bool needed_for_filtering = true;

			std::unique_ptr<sinsp_filter_check> filtercheck(
				sinsp_filter_checks.new_filter_check_from_fldname(field_str, &inspector, false));

			filtercheck->parse_field_name(field_str.c_str(), alloc_state, needed_for_filtering);

			EXPECT_EQ(expected, filtercheck->get_field_info()->is_arg_supported()) << "Field " + field_str + " did not return expected value " + std::to_string(expected) + " for is_arg_supported()";
		}
	}
}
