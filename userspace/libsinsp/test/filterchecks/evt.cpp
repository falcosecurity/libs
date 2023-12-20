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

#include <test/sinsp_with_test_input.h>

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

// Check all filterchecks `evt.arg*`
TEST_F(sinsp_with_test_input, EVT_FILTER_check_evt_arg)
{
	add_default_init_thread();
	open_inspector();

	std::string target = "sym";
	std::string linkpath = "/new/sym";
	int64_t err = 3;

	auto evt = add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_SYMLINK_X, 3, err, target.c_str(),
					linkpath.c_str());
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "symlink");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.res"), std::to_string(err));
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), std::to_string(err));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.res"), std::to_string(err));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.target"), target);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), target);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.target"), target);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.linkpath"), linkpath);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), linkpath);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.linkpath"), linkpath);

	// These fields should always have an argument
	ASSERT_THROW(field_exists(evt, "evt.arg"), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "evt.rawarg"), sinsp_exception);

	// If the field is not contained in the event table we throw an exception
	ASSERT_THROW(field_exists(evt, "evt.arg.not_exists"), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "evt.rawarg.not_exists"), sinsp_exception);

	// The validation is not during the argument extraction because we cannot access the event
	// So here we return true.
	ASSERT_TRUE(field_exists(evt, "evt.arg[126]"));
	// Here we try to extract the field so we return an exception
	ASSERT_THROW(field_has_value(evt, "evt.arg[126]"), sinsp_exception);

	// If the field is contained in the thread table but is not associated with this event we throw an
	// exception during the extraction of the field, but we don't fail during the extraction of the argument.
	// `.newpath` is not associated with `PPME_SYSCALL_SYMLINK_X` event.
	ASSERT_TRUE(field_exists(evt, "evt.arg.newpath"));
	ASSERT_THROW(field_has_value(evt, "evt.arg.newpath"), sinsp_exception);

	ASSERT_TRUE(field_exists(evt, "evt.rawarg.newpath"));
	ASSERT_THROW(field_has_value(evt, "evt.rawarg.newpath"), sinsp_exception);

	// All the args of an event
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "res=3 target=sym linkpath=/new/sym");
}
