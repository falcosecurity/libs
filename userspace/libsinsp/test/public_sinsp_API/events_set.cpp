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
#include <libsinsp/sinsp.h>
#include "../test_utils.h"

TEST(events_set, check_size)
{
	auto sc_set = libsinsp::events::set<ppm_sc_code>();
	ASSERT_EQ(sc_set.size(), 0);
	ASSERT_TRUE(sc_set.empty());

	sc_set.insert(PPM_SC_ACCEPT);
	ASSERT_EQ(sc_set.size(), 1);

	sc_set.insert(PPM_SC_ACCEPT);
	ASSERT_EQ(sc_set.size(), 1);

	sc_set.remove(PPM_SC_ACCEPT4);
	ASSERT_EQ(sc_set.size(), 1);

	sc_set.insert(PPM_SC_ACCEPT4);
	ASSERT_EQ(sc_set.size(), 2);

	sc_set.clear();
	ASSERT_EQ(sc_set.size(), 0);
	ASSERT_TRUE(sc_set.empty());
}

TEST(events_set, check_equal)
{
	auto sc_set = libsinsp::events::set<ppm_sc_code>();
	sc_set.insert(PPM_SC_ACCEPT);
	sc_set.insert(PPM_SC_ACCEPT4);

	auto other_set = libsinsp::events::set<ppm_sc_code>();
	ASSERT_FALSE(sc_set.equals(other_set));

	other_set.insert(PPM_SC_ACCEPT);
	ASSERT_FALSE(sc_set.equals(other_set));

	other_set.insert(PPM_SC_ACCEPT4);
	ASSERT_TRUE(sc_set.equals(other_set));

	sc_set.clear();
	ASSERT_FALSE(sc_set.equals(other_set));
	other_set.clear();
	ASSERT_TRUE(sc_set.equals(other_set));
	ASSERT_TRUE(sc_set.equals(libsinsp::events::set<ppm_sc_code>()));
	ASSERT_TRUE(other_set.equals(libsinsp::events::set<ppm_sc_code>()));
}

TEST(events_set, set_check_merge)
{
	auto merge_vec = std::vector<uint8_t>{1,2,3,4,5};
	auto intersect_vector = std::vector<uint8_t>{1,2,3,4,5};
	auto difference_vector = std::vector<uint8_t>{1,2,3,4,5};

	auto sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	sc_set_1.insert((ppm_sc_code)1);
	sc_set_1.insert((ppm_sc_code)4);

	auto sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	sc_set_2.insert((ppm_sc_code)1);
	sc_set_2.insert((ppm_sc_code)2);
	sc_set_2.insert((ppm_sc_code)3);
	sc_set_2.insert((ppm_sc_code)5);

	auto sc_set_merge = sc_set_1.merge(sc_set_2);
	for (auto val : merge_vec) {
		ASSERT_EQ(sc_set_merge.data()[val], 1);
	}
}

TEST(events_set, set_check_intersect)
{
	auto int_vec = std::vector<uint8_t>{1,4};

	auto sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	sc_set_1.insert((ppm_sc_code)1);
	sc_set_1.insert((ppm_sc_code)4);

	auto sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	sc_set_2.insert((ppm_sc_code)1);
	sc_set_2.insert((ppm_sc_code)2);
	sc_set_2.insert((ppm_sc_code)4);
	sc_set_2.insert((ppm_sc_code)5);

	auto sc_set_int = sc_set_1.intersect(sc_set_2);
	for (auto val : int_vec) {
		ASSERT_EQ(sc_set_int.data()[val], 1);
	}
}

TEST(events_set, set_check_diff)
{
	auto diff_vec = std::vector<uint8_t>{2,3};

	auto sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	sc_set_1.insert((ppm_sc_code)1);
	sc_set_1.insert((ppm_sc_code)2);
	sc_set_1.insert((ppm_sc_code)3);
	sc_set_1.insert((ppm_sc_code)4);

	auto sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	sc_set_2.insert((ppm_sc_code)1);
	sc_set_2.insert((ppm_sc_code)4);

	auto sc_set_diff = sc_set_1.diff(sc_set_2);
	for (auto val : diff_vec) {
		ASSERT_TRUE(sc_set_diff.contains((ppm_sc_code)val));
	}
}

TEST(events_set, names_to_event_set)
{
	auto event_set = libsinsp::events::names_to_event_set(std::unordered_set<std::string>{"openat","execveat"});
	libsinsp::events::set<ppm_event_code> event_set_truth = {PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X, PPME_SYSCALL_EXECVEAT_E, PPME_SYSCALL_EXECVEAT_X};
	ASSERT_PPM_EVENT_CODES_EQ(event_set_truth, event_set);
	ASSERT_EQ(event_set.size(), 6); // enter/exit events for each event name, special case "openat" has 4 PPME instead of 2

	// generic event case
	event_set = libsinsp::events::names_to_event_set(std::unordered_set<std::string>{"openat","execveat","syncfs"});
	event_set_truth = {PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
	PPME_SYSCALL_EXECVEAT_E, PPME_SYSCALL_EXECVEAT_X, PPME_GENERIC_E, PPME_GENERIC_X};
	ASSERT_PPM_EVENT_CODES_EQ(event_set_truth, event_set);
	ASSERT_EQ(event_set.size(), 8); // enter/exit events for each event name, special case "openat" has 4 PPME instead of 2
}

// Tests that no generic ppm sc is mapped to an event too
// basically, avoid that someone added a new event mapping a once-generic syscall,
// and forgot to update libscap/linux/scap_ppm_sc.c::g_events_to_sc_map.
TEST(events_set, generic_no_events)
{
	auto generic_ev_set_truth = libsinsp::events::set<ppm_event_code>({PPME_GENERIC_E, PPME_GENERIC_X});
	auto generic_sc_set = libsinsp::events::event_set_to_sc_set(generic_ev_set_truth);
	auto final_ev_set = libsinsp::events::sc_set_to_event_set(generic_sc_set);
	ASSERT_PPM_EVENT_CODES_EQ(final_ev_set, generic_ev_set_truth);
}

TEST(events_set, non_syscalls_events)
{
	auto ev_set_truth = libsinsp::events::set<ppm_event_code>({PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X,
								   PPME_SIGNALDELIVER_E, PPME_SIGNALDELIVER_X,
								   PPME_PROCINFO_E, PPME_PROCINFO_X});
	auto sc_set = libsinsp::events::event_set_to_sc_set(ev_set_truth);

	auto final_ev_set = libsinsp::events::sc_set_to_event_set(sc_set);

	// POLL_{E,X} are syscalls driven events, therefore they are correctly mapped back.
	ASSERT_TRUE(final_ev_set.contains(PPME_SYSCALL_POLL_E));
	ASSERT_TRUE(final_ev_set.contains(PPME_SYSCALL_POLL_X));
	ASSERT_TRUE(final_ev_set.contains(PPME_SIGNALDELIVER_E));
	// PPME_PROCINFO_{E,X} are never sent, therefore they are mapped to NULL in scap_ppm_sc table
	// Same goes for PPME_SIGNALDELIVER_X.
	ASSERT_FALSE(final_ev_set.contains(PPME_PROCINFO_E));
	ASSERT_FALSE(final_ev_set.contains(PPME_PROCINFO_X));
}

TEST(events_set, event_set_to_names_generic_events)
{
	static libsinsp::events::set<ppm_event_code> generic_event_set = {PPME_GENERIC_E, PPME_GENERIC_X};
	auto names = libsinsp::events::event_set_to_names(generic_event_set);
	/* Negative assertions. */
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"execve"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"accept"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"mprotect"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"mmap"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"container"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"procexit"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"umount2"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"eventfd2"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"syscall"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"init_module"}).empty());
	/* Random checks for some generic sc events. */
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"syncfs"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"perf_event_open"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"timer_create"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"lsetxattr"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"getsid"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"sethostname"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"readlinkat"}).empty());

	/* Solely check for some conservative lower bound to roughly ensure
	 * we are getting a whole bunch of generic sc events.
	 * At the time of writing we have about 234 generic sc syscalls as defined
	 * by not having a dedicated PPME_SYSCALL_* or PPME_SOCKET_* definition.
	*/
	ASSERT_GT(names.size(), 180);
}

TEST(events_set, event_set_to_names_no_generic_events1)
{
	static std::set<std::string> names_truth = {"kill", "dup", "umount", "eventfd", "procexit", "container"};
	auto names_unordered = libsinsp::events::event_set_to_names(libsinsp::events::set<ppm_event_code>{PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X,
	PPME_SYSCALL_DUP_1_E, PPME_SYSCALL_DUP_1_X, PPME_SYSCALL_UMOUNT_E, PPME_SYSCALL_UMOUNT_X, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X, PPME_PROCEXIT_E, PPME_CONTAINER_E});
	auto names = test_utils::unordered_set_to_ordered(names_unordered);
	ASSERT_NAMES_EQ(names_truth, names);
	ASSERT_TRUE(unordered_set_intersection(names_unordered, std::unordered_set<std::string> {"syncfs"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names_unordered, std::unordered_set<std::string> {"eventfd2"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names_unordered, std::unordered_set<std::string> {"container"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names_unordered, std::unordered_set<std::string> {"eventfd"}).empty());
}

TEST(events_set, event_set_to_names_no_generic_events2)
{
	auto names = libsinsp::events::event_set_to_names(libsinsp::events::all_event_set(), false);
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"execve"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"accept"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"mprotect"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"mmap"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"container"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"procexit"}).empty());
	ASSERT_FALSE(unordered_set_intersection(names, std::unordered_set<std::string> {"init_module"}).empty());

	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"syncfs"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"perf_event_open"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"timer_create"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"lsetxattr"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"getsid"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"sethostname"}).empty());
	ASSERT_TRUE(unordered_set_intersection(names, std::unordered_set<std::string> {"readlinkat"}).empty());
}

TEST(events_set, sc_set_to_event_set)
{
	libsinsp::events::set<ppm_sc_code> sc_set = {
	PPM_SC_KILL,
	PPM_SC_SENDTO,
	PPM_SC_SETRESUID, // note: corner case PPM_SC_SETRESUID32 would fail
	PPM_SC_ALARM,
	};

	libsinsp::events::set<ppm_event_code> event_set_truth = {
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	PPME_SYSCALL_SETRESUID_E,
	PPME_SYSCALL_SETRESUID_X,
	PPME_GENERIC_E,
	PPME_GENERIC_X,
	};

	auto event_set = libsinsp::events::sc_set_to_event_set(sc_set);
	ASSERT_PPM_EVENT_CODES_EQ(event_set_truth, event_set);
}

TEST(events_set, all_non_generic_sc_event_set)
{
	auto event_set = libsinsp::events::all_event_set().filter([&](ppm_event_code e) { return libsinsp::events::is_syscall_event(e); })\
	.diff(libsinsp::events::set<ppm_event_code>{PPME_GENERIC_E, PPME_GENERIC_X});
	/* No generic sc events expected. */
	ASSERT_FALSE(event_set.contains(PPME_GENERIC_E));
	ASSERT_FALSE(event_set.contains(PPME_GENERIC_X));
	/* No non sc events expected. */
	ASSERT_FALSE(event_set.contains(PPME_CONTAINER_E));
	ASSERT_FALSE(event_set.contains(PPME_CONTAINER_X));
	ASSERT_FALSE(event_set.contains(PPME_PROCEXIT_E));
	ASSERT_FALSE(event_set.contains(PPME_PROCEXIT_X));
}

TEST(events_set, all_non_sc_event_set)
{
	auto event_set = libsinsp::events::all_event_set().filter([&](ppm_event_code e) { return !libsinsp::events::is_syscall_event(e); });
	/* No sc events at all expected. */
	ASSERT_FALSE(event_set.contains(PPME_GENERIC_E));
	ASSERT_FALSE(event_set.contains(PPME_GENERIC_X));
	ASSERT_FALSE(event_set.contains(PPME_SOCKET_ACCEPT_E));
	ASSERT_FALSE(event_set.contains(PPME_SOCKET_ACCEPT_X));
	ASSERT_FALSE(event_set.contains(PPME_SYSCALL_OPENAT2_E));
	ASSERT_FALSE(event_set.contains(PPME_SYSCALL_OPENAT2_X));
	/* Some critical expected non sc events. */
	ASSERT_TRUE(event_set.contains(PPME_CONTAINER_E));
	ASSERT_TRUE(event_set.contains(PPME_CONTAINER_X));
	ASSERT_TRUE(event_set.contains(PPME_PROCEXIT_E));
	ASSERT_TRUE(event_set.contains(PPME_PROCEXIT_X));
}
