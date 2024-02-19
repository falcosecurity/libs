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

#include <libsinsp/sinsp.h>
#include <libsinsp/eventformatter.h>

#include <gtest/gtest.h>

#include <memory>
#include <vector>
#include <string>
#include <iostream>

using namespace std;

TEST(eventformatter, get_field_names)
{
	sinsp inspector;
	sinsp_filter_check_list filterlist;
	string output = "this is a sample output %proc.name %fd.type %proc.pid";
	sinsp_evt_formatter fmt(&inspector, output, filterlist);
	vector<string> output_fields;
	fmt.get_field_names(output_fields);
	ASSERT_EQ(output_fields.size(), 3);
	ASSERT_NE(find(output_fields.begin(), output_fields.end(), "proc.name"), output_fields.end());
	ASSERT_NE(find(output_fields.begin(), output_fields.end(), "fd.type"), output_fields.end());
	ASSERT_NE(find(output_fields.begin(), output_fields.end(), "proc.pid"), output_fields.end());
}
