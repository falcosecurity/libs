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

#include <test/helpers/threads_helpers.h>

constexpr const char *name = "/tmp/random/dir...///../../name/";
constexpr const char *resolved_name = "/tmp/name";

TEST_F(sinsp_with_test_input, FSPATH_FILTER_open) {
	add_default_init_thread();
	open_inspector();
	auto evt = generate_open_event(sinsp_test_input::open_params{
	        .path = name,
	});
	ASSERT_EQ(get_field_as_string(evt, "fs.path.name"), resolved_name);
	ASSERT_EQ(get_field_as_string(evt, "fs.path.nameraw"), name);
	ASSERT_FALSE(field_has_value(evt, "fs.path.source"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.sourceraw"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.target"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.targetraw"));
}
