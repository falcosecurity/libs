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

#include <libsinsp/sinsp.h>
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, contains_icontains)
{
	add_default_init_thread();

	open_inspector();

	int64_t fd = 1;
	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, "/opt/dir/SUBDIR/file.txt", PPM_O_RDWR | PPM_O_CREAT, 0, 0, (uint64_t) 0);

	EXPECT_TRUE(eval_filter(evt, "evt.arg.flags contains O_CREAT"));
	EXPECT_FALSE(eval_filter(evt, "evt.arg.flags contains O_TMPFILE"));
	EXPECT_TRUE(eval_filter(evt, "evt.arg.flags icontains O_CREAT"));
	EXPECT_TRUE(eval_filter(evt, "fd.name contains /dir"));
	EXPECT_TRUE(eval_filter(evt, "fd.name icontains /subdir"));
	EXPECT_FALSE(eval_filter(evt, "fd.name icontains notthis"));
}
