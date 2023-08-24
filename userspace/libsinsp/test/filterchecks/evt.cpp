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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, EVT_FILTER_is_open_create)
{
	add_default_init_thread();

	open_inspector();

	std::string path = "/home/file.txt";
	int64_t fd = 3;

	// In the enter event we don't send the `PPM_O_F_CREATED`
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, path.c_str(),
					      (uint32_t)PPM_O_RDWR | PPM_O_CREAT, (uint32_t)0);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_open_create"), "false");

	// The `fdinfo` is not populated in the enter event
	ASSERT_FALSE(evt->m_fdinfo);

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, path.c_str(),
				   (uint32_t)PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED, (uint32_t)0, (uint32_t)5,
				   (uint64_t)123);
	ASSERT_EQ(get_field_as_string(evt, "evt.is_open_create"), "true");
	ASSERT_TRUE(evt->m_fdinfo);

	ASSERT_EQ(evt->m_fdinfo->m_openflags, PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED);
}
