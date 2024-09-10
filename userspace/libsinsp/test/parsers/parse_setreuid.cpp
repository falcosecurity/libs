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

#include "driver/ppm_events_public.h"
#include <helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, SETREUID_failure) {
	/* Instantiate the default tree */
	DEFAULT_TREE

	add_event_advance_ts(increasing_ts(),
	                     p2_t2_tid,
	                     PPME_SYSCALL_SETREUID_X,
	                     3,
	                     (uint64_t)1,
	                     (uint32_t)0,
	                     (uint32_t)0);

	sinsp_threadinfo* ti = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_TRUE(ti);
	ASSERT_TRUE(ti->m_user.uid() == 0);
}

TEST_F(sinsp_with_test_input, SETREUID_success) {
	/* Instantiate the default tree */
	DEFAULT_TREE

	add_event_advance_ts(increasing_ts(),
	                     p2_t2_tid,
	                     PPME_SYSCALL_SETREUID_X,
	                     3,
	                     (uint64_t)0,
	                     (uint32_t)1337,
	                     (uint32_t)1337);

	sinsp_threadinfo* ti = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_TRUE(ti);
	ASSERT_TRUE(ti->m_user.uid() == 1337);
}
