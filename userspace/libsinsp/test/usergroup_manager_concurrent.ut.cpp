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
#include <thread>

#include <sinsp_with_test_input.h>
#include <libsinsp/user.h>

using namespace libsinsp;

class usergroup_manager_test : public sinsp_with_test_input {
	// for gtest filtering convenience,
	// add something when needed
};

// Concurrent access test: run under TSAN to validate thread-safe usergroup_manager.
// Readers: with_user, with_group, get_user, get_group, get_userlist, get_grouplist.
// Writers: add_user, add_group, rm_user, rm_group, delete_container.
TEST_F(usergroup_manager_test, USERGROUP_MANAGER_concurrent_read_write) {
	const std::string container_id("");
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};
	// Seed with initial data
	mgr.add_user(container_id, -1, 0, 0, "root", "/root", "/bin/sh", false);
	mgr.add_group(container_id, -1, 0, "root", false);
	constexpr int num_rounds = 50;
	constexpr int uid_base = 1000;
	constexpr int gid_base = 1000;

	std::thread writer_add([&]() {
		for(int r = 0; r < num_rounds; ++r) {
			for(int i = 0; i < 10; ++i) {
				uint32_t uid = uid_base + r * 10 + i;
				uint32_t gid = gid_base + r * 10 + i;
				mgr.add_user(container_id,
				             -1,
				             uid,
				             gid,
				             "user" + std::to_string(uid),
				             "/home/u",
				             "/bin/sh",
				             false);
				mgr.add_group(container_id, -1, gid, "group" + std::to_string(gid), false);
			}
		}
	});

	std::thread reader_visitor([&]() {
		for(int r = 0; r < num_rounds * 2; ++r) {
			mgr.with_user(container_id, 0, [](const scap_userinfo& u) { (void)u.name[0]; });
			mgr.with_group(container_id, 0, [](const scap_groupinfo& g) { (void)g.name[0]; });
			for(int i = 0; i < 20; ++i) {
				uint32_t uid = uid_base + (r + i) % (num_rounds * 10);
				uint32_t gid = gid_base + (r + i) % (num_rounds * 10);
				mgr.with_user(container_id, uid, [](const scap_userinfo& u) { (void)u.uid; });
				mgr.with_group(container_id, gid, [](const scap_groupinfo& g) { (void)g.gid; });
			}
		}
	});

	std::thread reader_optional([&]() {
		for(int r = 0; r < num_rounds * 2; ++r) {
			(void)mgr.get_user(container_id, 0);
			(void)mgr.get_group(container_id, 0);
			(void)mgr.get_userlist(container_id);
			(void)mgr.get_grouplist(container_id);
		}
	});

	writer_add.join();
	reader_visitor.join();
	reader_optional.join();

	// After writers finished, readers should still work
	ASSERT_TRUE(mgr.get_user(container_id, 0).has_value());
	ASSERT_TRUE(mgr.get_group(container_id, 0).has_value());
}
