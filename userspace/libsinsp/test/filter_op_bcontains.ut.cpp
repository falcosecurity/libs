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
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, bcontains_bstartswith) {
	add_default_init_thread();

	open_inspector();

	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_READ_X,
	                                      4,
	                                      (int64_t)0,
	                                      scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                                      (int64_t)0,
	                                      (uint32_t)0);

	// test filters with bcontains
	EXPECT_FALSE(filter_compiles("evt.buffer bcontains"));
	EXPECT_FALSE(filter_compiles("evt.buffer bcontains 2"));
	EXPECT_FALSE(filter_compiles("evt.buffer bcontains 2g"));

	EXPECT_TRUE(eval_filter(evt, "evt.buffer bcontains 68656c6c6f"));
	EXPECT_TRUE(eval_filter(evt, "evt.buffer bcontains 656c6C"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bcontains 20"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bcontains 656c6cAA"));

	// test filters with bstartswith
	EXPECT_FALSE(filter_compiles("evt.buffer bstartswith"));
	EXPECT_FALSE(filter_compiles("evt.buffer bstartswith 2"));
	EXPECT_FALSE(filter_compiles("evt.buffer bstartswith 2g"));

	EXPECT_TRUE(eval_filter(evt, "evt.buffer bstartswith 68"));
	EXPECT_TRUE(eval_filter(evt, "evt.buffer bstartswith 68656c6c6f"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bstartswith 65"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bstartswith 656c6C"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bstartswith 20"));
	EXPECT_FALSE(eval_filter(evt, "evt.buffer bstartswith 656c6cAA"));
}
