// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License"));
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
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, signed_int_compare)
{
	add_default_init_thread();

	open_inspector();

	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE_X, 1, (uint64_t)-22);

	EXPECT_EQ(get_field_as_string(evt, "evt.cpu"), "1");

	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 300"));
	EXPECT_FALSE(eval_filter(evt, "evt.cpu > 300"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 2"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu > -500"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 500"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu <= 500"));

	EXPECT_TRUE(eval_filter(evt, "evt.cpu <= 1025"));
	EXPECT_FALSE(eval_filter(evt, "evt.cpu >= 1025"));

	EXPECT_FALSE(eval_filter(evt, "evt.rawarg.res > 0"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res < 0"));
	EXPECT_FALSE(eval_filter(evt, "evt.rawarg.res > 4294967295"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res < -1"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res > -65535"));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_NONE, 0666);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (int64_t)(-1), "/tmp/the_file", PPM_O_NONE, 0666, 123, (uint64_t)456);

	EXPECT_FALSE(eval_filter(evt, "fd.num >= 0"));
	EXPECT_FALSE(eval_filter(evt, "fd.num > 0"));
	EXPECT_TRUE(eval_filter(evt, "fd.num < 0"));
	EXPECT_FALSE(eval_filter(evt, "fd.num > 4294967295"));
	EXPECT_FALSE(eval_filter(evt, "fd.num < -1"));
	EXPECT_TRUE(eval_filter(evt, "fd.num > -65535"));
}
