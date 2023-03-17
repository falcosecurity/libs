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
#include "../test_utils.h"

TEST(interesting_syscalls, io_sc_set)
{
	libsinsp::events::set<ppm_sc_code> io_sc_set_truth;

	io_sc_set_truth.insert(PPM_SC_READ);
	io_sc_set_truth.insert(PPM_SC_RECVFROM);
	io_sc_set_truth.insert(PPM_SC_RECVMSG);
	io_sc_set_truth.insert(PPM_SC_RECVMMSG);
	io_sc_set_truth.insert(PPM_SC_READV);
	io_sc_set_truth.insert(PPM_SC_PREADV);
	io_sc_set_truth.insert(PPM_SC_WRITE);
	io_sc_set_truth.insert(PPM_SC_WRITEV);
	io_sc_set_truth.insert(PPM_SC_PWRITEV);
	io_sc_set_truth.insert(PPM_SC_SENDFILE);
	io_sc_set_truth.insert(PPM_SC_SENDTO);
	io_sc_set_truth.insert(PPM_SC_SENDMSG);
	io_sc_set_truth.insert(PPM_SC_SENDMMSG);
	io_sc_set_truth.insert(PPM_SC_PREAD64);
	io_sc_set_truth.insert(PPM_SC_PWRITE64);

	auto io_sc_set = libsinsp::events::io_sc_set();
	ASSERT_PPM_SC_CODES_EQ(io_sc_set_truth, io_sc_set);
}

TEST(interesting_syscalls, all_sc_set)
{
	auto sc_set = libsinsp::events::all_sc_set();

	/*
	 * Assert that all the syscalls are taken
	 * -> note: since some PPM_SC might be skipped because unused,
	 * max size might be lower than PPM_SC_MAX.
	 */
	ASSERT_TRUE(sc_set.size() <= PPM_SC_MAX);
}

TEST(interesting_syscalls, sc_set_to_names)
{
	// "syncfs" is a generic event / syscall
	static std::set<std::string> names_truth = {"kill", "read", "syncfs"};
	static libsinsp::events::set<ppm_sc_code> sc_set = {PPM_SC_KILL, PPM_SC_READ, PPM_SC_SYNCFS};
	auto names = test_utils::unordered_set_to_ordered(libsinsp::events::sc_set_to_names(sc_set));
	ASSERT_NAMES_EQ(names_truth, names);
}

TEST(interesting_syscalls, names_to_sc_set)
{
	static libsinsp::events::set<ppm_sc_code> sc_set_truth = {
	PPM_SC_KILL,
	PPM_SC_READ,
	PPM_SC_SYNCFS,
	PPM_SC_ACCEPT,
 	PPM_SC_ACCEPT4,
	PPM_SC_EXECVE,
	PPM_SC_SETRESUID,
 	PPM_SC_SETRESUID32,
 	PPM_SC_EVENTFD,
	PPM_SC_EVENTFD2,
 	PPM_SC_UMOUNT,
	PPM_SC_UMOUNT2,
 	PPM_SC_PIPE,
	PPM_SC_PIPE2,
 	PPM_SC_SIGNALFD,
	PPM_SC_SIGNALFD4
	};

	auto sc_set = libsinsp::events::names_to_sc_set(std::unordered_set<std::string>{
	"kill",
	"read",
	"syncfs",
 	"accept",
 	"accept4",
	"execve",
	"setresuid",
	"eventfd",
	"eventfd2",
	"umount",
	"umount2",
	"pipe",
	"pipe2",
	"signalfd",
	"signalfd4",
	});
	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
}

/* This test asserts the behavior of `names_to_sc_set` API when corner cases like `accept/accept4` are involved */
/// todo: @Andreagit97 revisit this test after new APIs to convert from event_names -> sc_set and sc_set -> event_names.
TEST(interesting_syscalls, names_sc_set_names_corner_cases)
{
	/* INCONSISTENCY: `names_to_sc_set` is converting event names to ppm_sc, but this was not its original scope, the original scope was to convert sc_names -> to sc_set  */
	std::unordered_set<std::string> event_names{"accept", "execve", "syncfs", "eventfd", "umount", "pipe", "signalfd", "umount2"};
	auto sc_set = libsinsp::events::names_to_sc_set(event_names);
	libsinsp::events::set<ppm_sc_code> expected_sc_set{PPM_SC_ACCEPT, PPM_SC_ACCEPT4, PPM_SC_EXECVE, PPM_SC_SYNCFS, PPM_SC_EVENTFD, PPM_SC_UMOUNT, PPM_SC_PIPE, PPM_SC_SIGNALFD, PPM_SC_UMOUNT2};
	ASSERT_PPM_SC_CODES_EQ(sc_set, expected_sc_set);

	/* Please note that here we are converting sc_set to sc_names not event_names! */
	auto sc_names = libsinsp::events::sc_set_to_names(sc_set);	
	static std::unordered_set<std::string> expected_sc_names = {"accept", "accept4", "execve", "syncfs", "eventfd", "umount", "pipe", "signalfd", "umount2"};
	ASSERT_NAMES_EQ(expected_sc_names, sc_names);
}

TEST(interesting_syscalls, event_set_to_sc_set)
{
	libsinsp::events::set<ppm_sc_code> sc_set_truth = {
	PPM_SC_KILL,
	PPM_SC_SENDTO,
	};

	libsinsp::events::set<ppm_event_code> event_set = {
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	};

	auto sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	ASSERT_PPM_SC_CODES_EQ(sc_set_truth, sc_set);
}

TEST(interesting_syscalls, event_set_to_sc_set_generic_events)
{

	libsinsp::events::set<ppm_event_code> event_set = {
	PPME_SYSCALL_KILL_E,
	PPME_SYSCALL_KILL_X,
	PPME_SOCKET_SENDTO_E,
	PPME_SOCKET_SENDTO_X,
	PPME_GENERIC_E,
	PPME_GENERIC_X,
	};

	auto sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	ASSERT_GT(sc_set.size(), 180);
	ASSERT_TRUE(sc_set.contains(PPM_SC_SYNCFS));
	ASSERT_TRUE(sc_set.contains(PPM_SC_KILL));
	ASSERT_TRUE(sc_set.contains(PPM_SC_SENDTO));
	/* Random checks for some generic sc events. */
	ASSERT_TRUE(sc_set.contains(PPM_SC_PERF_EVENT_OPEN));
	ASSERT_TRUE(sc_set.contains(PPM_SC_GETSID));
	ASSERT_TRUE(sc_set.contains(PPM_SC_INIT_MODULE));
	ASSERT_TRUE(sc_set.contains(PPM_SC_READLINKAT));
}
