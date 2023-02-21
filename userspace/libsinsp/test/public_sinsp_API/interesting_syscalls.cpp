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
#include <sys/syscall.h>
#include "../test_utils.h"
// We need to include syscall compat tables
#ifdef __x86_64__
#include "syscall_compat_x86_64.h"
#elif __aarch64__
#include "syscall_compat_aarch64.h"
#elif __s390x__
#include "syscall_compat_s390x.h"
#endif /* __x86_64__ */

/* This test asserts that `sinsp_state_sc_set` is of expected length.
 * Please note this set must be kept in sync if we update the sinsp internal
 * state set, otherwise some of the following checks will fail.
 */
TEST(interesting_syscalls, sinsp_state_sc_set)
{
	auto sinsp_state_sc_set = libsinsp::events::sinsp_state_sc_set();
	ASSERT_EQ(sinsp_state_sc_set.size(), 53);
}

/* This test asserts that `enforce_simple_sc_set` correctly merges
 * the provided set with the `libsinsp` state set.
 */
TEST(interesting_syscalls, enforce_simple_sc_set_with_additions)
{
	libsinsp::events::set<ppm_sc_code> additional_syscalls;

#ifdef __NR_kill
	additional_syscalls.insert(PPM_SC_KILL);
#endif

#ifdef __NR_read
	additional_syscalls.insert(PPM_SC_READ);
#endif

	auto sinsp_state_set = libsinsp::events::sinsp_state_sc_set();
	auto ppm_sc_final_set = additional_syscalls.merge(sinsp_state_set);
	auto intersection = ppm_sc_final_set.intersect(additional_syscalls);
	ASSERT_EQ(sinsp_state_set.size(), ppm_sc_final_set.size() - 2);
	ASSERT_EQ(intersection.size(), 2);
}

/* This test asserts that `io_sc_set` correctly retrieves the expected
 * number of corresponding sycalls.
 */
TEST(interesting_syscalls, io_sc_set)
{
	auto io_sc_set = libsinsp::events::io_sc_set();
	ASSERT_EQ(io_sc_set.size(), 15);
}

/// TODO: we can add also some tests for `enforce_io_ppm_sc_set`, `enforce_net_ppm_sc_set`, ... here.

/* This test asserts that `get_event_set_from_ppm_sc_set` correctly returns the events
 * associated with the provided `ppm_sc_set`.
 */
TEST(interesting_syscalls, get_event_set_from_ppm_sc_set)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set = {
#ifdef __NR_kill
	PPM_SC_KILL,
#endif

#ifdef __NR_sendto
	PPM_SC_SENDTO,
#endif

#ifdef __NR_alarm
	PPM_SC_ALARM,
#endif
	};

	libsinsp::events::set<ppm_event_code> event_set = {
#ifdef __NR_kill
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
#endif

#ifdef __NR_sendto
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
#endif

#ifdef __NR_alarm
	PPME_GENERIC_E,
	PPME_GENERIC_X,
#endif
	};

	auto final_evt_set = libsinsp::events::sc_set_to_event_set(ppm_sc_set);

	ASSERT_TRUE(final_evt_set.equals(event_set));
}

/* This test asserts that `get_all_ppm_sc` correctly retrieves all the available syscalls
 */
TEST(interesting_syscalls, get_all_ppm_sc)
{
	auto ppm_sc_set = libsinsp::events::all_sc_set();

	/* Assert that all the syscalls are taken */
	ASSERT_EQ(ppm_sc_set.size(), PPM_SC_MAX);
}

/* This test asserts that `get_syscalls_names` correctly retrieves all the syscalls names
 */
TEST(interesting_syscalls, get_syscalls_names)
{
	std::set<std::string> orderd_syscall_names_matching_set;
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;

	/* Here we don't need ifdefs, our ppm_sc codes are always defined. */
	ppm_sc_set.insert(PPM_SC_KILL);
	orderd_syscall_names_matching_set.insert("kill");

	ppm_sc_set.insert(PPM_SC_READ);
	orderd_syscall_names_matching_set.insert("read");

	auto syscall_names_final_set = libsinsp::events::sc_set_to_names(ppm_sc_set);

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(orderd_syscall_names_matching_set.size(), syscall_names_final_set.size());

	auto ordered_syscall_names_final_set = test_utils::unordered_set_to_ordered(syscall_names_final_set);

	auto final = ordered_syscall_names_final_set.begin();
	auto matching = orderd_syscall_names_matching_set.begin();

	for(; final != ordered_syscall_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}

/* This test asserts that `get_events_names` correctly retrieves all the events names
 */
TEST(interesting_syscalls, get_events_names)
{
	std::set<std::string> orderd_events_names_matching_set;
	libsinsp::events::set<ppm_event_code> events_set;

	/* Here we don't need ifdefs, our events are always defined. */
	events_set.insert(PPME_SYSCALL_KILL_E);
	events_set.insert(PPME_SYSCALL_KILL_X);
	/* Please note the name of the 2 events should be the same: "kill" */
	orderd_events_names_matching_set.insert("kill");

	events_set.insert(PPME_SYSCALL_DUP_1_E);
	events_set.insert(PPME_SYSCALL_DUP_1_X);
	orderd_events_names_matching_set.insert("dup");

	auto events_names_final_set = libsinsp::events::event_set_to_names(events_set);

	/* Assert that the 2 sets have the same size */
	ASSERT_EQ(events_names_final_set.size(), orderd_events_names_matching_set.size());

	auto ordered_events_names_final_set = test_utils::unordered_set_to_ordered(events_names_final_set);

	auto final = ordered_events_names_final_set.begin();
	auto matching = orderd_events_names_matching_set.begin();

	for(; final != ordered_events_names_final_set.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}
