// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <atomic>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#include <sinsp_with_test_input.h>
#include <libsinsp/user.h>

using namespace libsinsp;

// What a class parameterized on the single policy holds is smaller than with the concurrent one.
static_assert(sizeof(basic_usergroup_manager<sync_policy_single>) <
              sizeof(basic_usergroup_manager<sync_policy_concurrent>));

// The sinsp-owned manager is the instantiation for the default policy.
static_assert(
        std::is_base_of_v<basic_usergroup_manager<sync_policy_default>, sinsp_usergroup_manager>);

class usergroup_manager_sync_test : public sinsp_with_test_input {};

namespace {
// Note: the group names are passed as std::string_view because a string literal would select the
// add_group() overload taking `bool notify` (pointer to bool is a standard conversion).

// Run the same sequence of operations on a manager and describe what it ends up holding, so that
// the result of the different policies can be compared.
template<typename Manager>
std::string exercise(Manager &mgr) {
	const std::string container_id;
	std::string out;

	mgr.add_user(container_id, -1, 0, 0, "root", "/root", "/bin/sh");
	mgr.add_user(container_id, -1, 1000, 1000, "foo", "/home/foo", "/bin/bash");
	mgr.add_group(container_id, -1, 0, std::string_view("root"));
	mgr.add_group(container_id, -1, 1000, std::string_view("foo"));
	// updating an existing entry
	mgr.add_user(container_id, -1, 1000, 1000, "bar", "/home/bar", "/bin/zsh");

	mgr.with_user(container_id, 1000, [&](const scap_userinfo &u) {
		out += std::string(u.name) + ":" + u.homedir + ":" + u.shell + ";";
	});
	mgr.with_group(container_id, 1000, [&](const scap_groupinfo &g) {
		out += std::string(g.name) + ";";
	});
	out += std::to_string(mgr.with_user(container_id, 4242, [](const scap_userinfo &) {})) + ";";
	out += std::to_string(mgr.with_group(container_id, 4242, [](const scap_groupinfo &) {})) + ";";

	auto users = mgr.copy_userlist(container_id);
	auto groups = mgr.copy_grouplist(container_id);
	out += std::to_string(users->size()) + "," + std::to_string(groups->size()) + ";";
	out += std::to_string(mgr.get_user(container_id, 0)->uid) + ";";

	out += std::to_string(mgr.rm_user(container_id, 1000)) + ";";
	out += std::to_string(mgr.rm_user(container_id, 1000)) + ";";
	out += std::to_string(mgr.rm_group(container_id, 1000)) + ";";
	out += std::to_string(mgr.copy_userlist(container_id)->size()) + ";";

	mgr.delete_container(container_id);
	out += std::to_string(mgr.copy_userlist(container_id).has_value()) + ";";
	out += std::to_string(mgr.copy_grouplist(container_id).has_value()) + ";";
	out += std::to_string(mgr.get_user(container_id, 0) == nullptr) + ";";
	return out;
}
}  // namespace

TEST_F(usergroup_manager_sync_test, policies_give_the_same_results) {
	const timestamper ts{0};
	basic_usergroup_manager<sync_policy_single> single{&m_inspector, ts};
	basic_usergroup_manager<sync_policy_concurrent> concurrent{&m_inspector, ts};
	sinsp_usergroup_manager default_mgr{&m_inspector, ts};

	const auto expected = exercise(single);
	ASSERT_EQ(expected, "bar:/home/bar:/bin/zsh;foo;0;0;2,2;0;1;0;1;1;0;0;1;");
	ASSERT_EQ(exercise(concurrent), expected);
	ASSERT_EQ(exercise(default_mgr), expected);
}

TEST_F(usergroup_manager_sync_test, copies_do_not_follow_later_changes) {
	const timestamper ts{0};
	basic_usergroup_manager<sync_policy_concurrent> mgr{&m_inspector, ts};
	mgr.add_user("", -1, 7, 7, "seven", "/home/seven", "/bin/sh");
	mgr.add_group("", -1, 7, std::string_view("seven"));

	auto users = mgr.copy_userlist("");
	auto groups = mgr.copy_grouplist("");
	ASSERT_TRUE(users.has_value());
	ASSERT_TRUE(groups.has_value());

	mgr.rm_user("", 7);
	mgr.rm_group("", 7);

	ASSERT_EQ(users->count(7), 1u);
	ASSERT_STREQ(users->at(7).name, "seven");
	ASSERT_EQ(groups->count(7), 1u);
	ASSERT_FALSE(mgr.with_user("", 7, [](const scap_userinfo &) {}));
}

TEST_F(usergroup_manager_sync_test, concurrent_add_lookup_delete) {
	const timestamper ts{0};
	basic_usergroup_manager<sync_policy_concurrent> mgr{&m_inspector, ts};
	const std::string host;
	mgr.add_user(host, -1, 0, 0, "root", "/root", "/bin/sh");
	mgr.add_group(host, -1, 0, std::string_view("root"));

	constexpr int k_writers = 4;
	constexpr int k_readers = 3;
	constexpr uint32_t k_per_writer = 200;
	constexpr uint32_t k_stride = 1000;

	std::atomic<bool> start{false};
	std::atomic<int> writers_running{k_writers};
	std::atomic<uint64_t> torn_reads{0};
	std::atomic<uint64_t> hits{0};

	auto name_of = [](const char *prefix, uint32_t id) { return prefix + std::to_string(id); };

	std::vector<std::thread> threads;
	for(int w = 0; w < k_writers; ++w) {
		threads.emplace_back([&, w]() {
			while(!start) {
				std::this_thread::yield();
			}
			const uint32_t base = k_stride * (w + 1);
			for(uint32_t i = 0; i < k_per_writer; ++i) {
				mgr.add_user(host, -1, base + i, base + i, name_of("user", base + i), "/h", "/s");
				mgr.add_group(host, -1, base + i, name_of("group", base + i));
			}
			// remove the odd ones, keep the even ones
			for(uint32_t i = 1; i < k_per_writer; i += 2) {
				ASSERT_TRUE(mgr.rm_user(host, base + i));
				ASSERT_TRUE(mgr.rm_group(host, base + i));
			}
			--writers_running;
		});
	}
	for(int r = 0; r < k_readers; ++r) {
		threads.emplace_back([&, r]() {
			while(!start) {
				std::this_thread::yield();
			}
			uint32_t n = r;
			while(writers_running > 0) {
				const uint32_t base = k_stride * (1 + n % k_writers);
				const uint32_t id = base + (n * 7) % k_per_writer;
				// A found entry must be complete and belong to the key we asked for.
				mgr.with_user(host, id, [&](const scap_userinfo &u) {
					++hits;
					if(u.uid != id || u.name != name_of("user", id)) {
						++torn_reads;
					}
				});
				mgr.with_group(host, id, [&](const scap_groupinfo &g) {
					if(g.gid != id || g.name != name_of("group", id)) {
						++torn_reads;
					}
				});
				if(auto users = mgr.copy_userlist(host)) {
					// the copy is a consistent snapshot: root is always there
					if(users->count(0) != 1) {
						++torn_reads;
					}
				}
				(void)mgr.copy_grouplist(host);
				++n;
			}
		});
	}
	// Containers that do not exist: this only exercises the writer lock against the readers.
	threads.emplace_back([&]() {
		while(!start) {
			std::this_thread::yield();
		}
		while(writers_running > 0) {
			mgr.delete_container("no-such-container");
			mgr.rm_user("no-such-container", 1);
			mgr.rm_group("no-such-container", 1);
		}
	});

	start = true;
	for(auto &t : threads) {
		t.join();
	}

	ASSERT_EQ(torn_reads.load(), 0u);

	// What is left is exactly what the writers kept.
	auto users = mgr.copy_userlist(host);
	auto groups = mgr.copy_grouplist(host);
	ASSERT_TRUE(users.has_value());
	ASSERT_TRUE(groups.has_value());
	ASSERT_EQ(users->size(), 1u + k_writers * (k_per_writer / 2));
	ASSERT_EQ(groups->size(), 1u + k_writers * (k_per_writer / 2));
	for(int w = 0; w < k_writers; ++w) {
		const uint32_t base = k_stride * (w + 1);
		for(uint32_t i = 0; i < k_per_writer; ++i) {
			const bool kept = (i % 2 == 0);
			const auto uit = users->find(base + i);
			ASSERT_EQ(uit != users->end(), kept) << "uid " << base + i;
			if(kept) {
				ASSERT_EQ(std::string(uit->second.name), name_of("user", base + i));
				ASSERT_EQ(std::string(groups->at(base + i).name), name_of("group", base + i));
			}
		}
	}

	mgr.delete_container(host);
	ASSERT_FALSE(mgr.copy_userlist(host).has_value());
	ASSERT_FALSE(mgr.copy_grouplist(host).has_value());
}

TEST_F(usergroup_manager_sync_test, concurrent_import_users_toggle) {
	const timestamper ts{0};
	basic_usergroup_manager<sync_policy_concurrent> mgr{&m_inspector, ts};
	mgr.add_user("", -1, 0, 0, "root", "/root", "/bin/sh");

	std::atomic<bool> stop{false};
	std::thread toggler([&]() {
		bool v = false;
		while(!stop) {
			mgr.m_import_users = v;
			v = !v;
		}
	});
	std::vector<std::thread> adders;
	for(uint32_t t = 0; t < 3; ++t) {
		adders.emplace_back([&, t]() {
			for(uint32_t i = 0; i < 2000; ++i) {
				// Either goes to the tables or to the fallback entry, depending on the flag.
				auto *usr = mgr.add_user("", -1, 5000 + t * 10000 + i, 1, "n", "/h", "/s");
				ASSERT_NE(usr, nullptr);
				mgr.with_user("", 0, [](const scap_userinfo &) {});
			}
		});
	}
	for(auto &a : adders) {
		a.join();
	}
	stop = true;
	toggler.join();

	mgr.m_import_users = true;
	ASSERT_TRUE(mgr.with_user("", 0, [](const scap_userinfo &u) { ASSERT_STREQ(u.name, "root"); }));
}
