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
#include "events/sinsp_events.h"

TEST(events_set, check_size)
{
	auto sc_set = libsinsp::events::set<ppm_sc_code>();
	ASSERT_EQ(sc_set.size(), 0);
	ASSERT_TRUE(sc_set.empty());

	sc_set.insert(PPM_SC_ACCEPT);
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

	auto ppm_sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_1.insert((ppm_sc_code)1);
	ppm_sc_set_1.insert((ppm_sc_code)4);

	auto ppm_sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_2.insert((ppm_sc_code)1);
	ppm_sc_set_2.insert((ppm_sc_code)2);
	ppm_sc_set_2.insert((ppm_sc_code)3);
	ppm_sc_set_2.insert((ppm_sc_code)5);

	auto ppm_sc_set_merge = ppm_sc_set_1.merge(ppm_sc_set_2);
	for (auto val : merge_vec) {
		ASSERT_EQ(ppm_sc_set_merge.data()[val], 1);
	}
}

TEST(events_set, set_check_intersect)
{
	auto int_vec = std::vector<uint8_t>{1,4};

	auto ppm_sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_1.insert((ppm_sc_code)1);
	ppm_sc_set_1.insert((ppm_sc_code)4);

	auto ppm_sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_2.insert((ppm_sc_code)1);
	ppm_sc_set_2.insert((ppm_sc_code)2);
	ppm_sc_set_2.insert((ppm_sc_code)4);
	ppm_sc_set_2.insert((ppm_sc_code)5);

	auto ppm_sc_set_int = ppm_sc_set_1.intersect(ppm_sc_set_2);
	for (auto val : int_vec) {
		ASSERT_EQ(ppm_sc_set_int.data()[val], 1);
	}
}

TEST(events_set, set_check_diff)
{
	auto diff_vec = std::vector<uint8_t>{2,3};

	auto ppm_sc_set_1 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_1.insert((ppm_sc_code)1);
	ppm_sc_set_1.insert((ppm_sc_code)2);
	ppm_sc_set_1.insert((ppm_sc_code)3);
	ppm_sc_set_1.insert((ppm_sc_code)4);

	auto ppm_sc_set_2 = libsinsp::events::set<ppm_sc_code>();
	ppm_sc_set_2.insert((ppm_sc_code)1);
	ppm_sc_set_2.insert((ppm_sc_code)4);

	auto ppm_sc_set_diff = ppm_sc_set_1.diff(ppm_sc_set_2);
	for (auto val : diff_vec) {
		ASSERT_TRUE(ppm_sc_set_diff.contains((ppm_sc_code)val));
	}
}

TEST(events_set, names_to_event_set)
{
	auto event_names = std::unordered_set<std::string>{"openat2", "execveat"};

	auto event_codes = libsinsp::events::names_to_event_set(event_names);
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT2_E));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_OPENAT2_X));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_EXECVEAT_E));
	ASSERT_TRUE(event_codes.contains(PPME_SYSCALL_EXECVEAT_X));
	ASSERT_FALSE(event_codes.contains(PPME_GENERIC_E));
	ASSERT_FALSE(event_codes.contains(PPME_GENERIC_X));
	ASSERT_EQ(event_codes.size(), 4); // enter/exit events for each event name

	// Now insert a syscall bound to a generic event
	event_names.insert("syncfs");
	event_codes = libsinsp::events::names_to_event_set(event_names);
	ASSERT_TRUE(event_codes.contains(PPME_GENERIC_E));
	ASSERT_TRUE(event_codes.contains(PPME_GENERIC_X));ASSERT_EQ(event_codes.size(), 6); // enter/exit events for each event name
}

// Tests that no generic ppm sc is mapped to an event too
// basically, avoid that someone added a new event mapping a once-generic syscall,
// and forgot to update libscap/linux/scap_ppm_sc.c::g_events_to_sc_map.
TEST(events_set, generic_no_events)
{
	auto generic_ev_set = libsinsp::events::set<ppm_event_code>({PPME_GENERIC_E, PPME_GENERIC_X});
	auto generic_sc_set = libsinsp::events::event_set_to_sc_set(generic_ev_set);
	auto final_ev_set = libsinsp::events::sc_set_to_event_set(generic_sc_set);
	ASSERT_EQ(final_ev_set, generic_ev_set);
}

TEST(events_set, event_set_to_sc_set)
{
	auto all_sc = libsinsp::events::all_sc_set();
	auto all_events = libsinsp::events::all_event_set();
	auto events_to_sc = libsinsp::events::event_set_to_sc_set;
	auto sc_to_events = libsinsp::events::sc_set_to_event_set;

	libsinsp::events::set<ppm_event_code> all_syscalls_tracepoints_events;
	for (auto ev_code : all_events)
	{
		if (libsinsp::events::is_tracepoint_event(ev_code) ||
		   libsinsp::events::is_syscall_event(ev_code))
		{
			all_syscalls_tracepoints_events.insert(ev_code);
		}
	}

	ASSERT_EQ(all_syscalls_tracepoints_events, sc_to_events(all_sc));
	ASSERT_EQ(all_sc, events_to_sc(all_syscalls_tracepoints_events));
	ASSERT_EQ(all_sc, events_to_sc(sc_to_events(all_sc)));
	ASSERT_EQ(all_syscalls_tracepoints_events, sc_to_events(events_to_sc(all_syscalls_tracepoints_events)));

	auto sc_to_names = libsinsp::events::sc_set_to_names;
	auto names_to_sc = libsinsp::events::names_to_sc_set;
	ASSERT_EQ(all_sc, names_to_sc(sc_to_names(all_sc)));

	auto events_to_names = libsinsp::events::event_set_to_names;
	auto names_to_events = libsinsp::events::names_to_event_set;
	ASSERT_EQ(all_syscalls_tracepoints_events, names_to_events(events_to_names(all_syscalls_tracepoints_events)));
}