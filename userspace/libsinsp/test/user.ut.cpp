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

#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <sinsp_with_test_input.h>
#include <libsinsp/user.h>

using namespace libsinsp;

class usergroup_manager_test : public sinsp_with_test_input {
	// for gtest filtering convenience,
	// add something when needed
};

TEST_F(usergroup_manager_test, add_rm) {
	const std::string container_id{""};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};
	// no data so far
	ASSERT_FALSE(mgr.get_user(container_id, 0).has_value());
	ASSERT_FALSE(mgr.get_group(container_id, 0).has_value());
	ASSERT_FALSE(mgr.get_userlist(container_id).has_value());
	ASSERT_FALSE(mgr.get_grouplist(container_id).has_value());

	// user
	mgr.add_user(container_id, -1, 0, 0, "test", "/test", "/bin/test");
	auto user = mgr.get_user(container_id, 0);
	ASSERT_TRUE(user.has_value());
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "test");
	ASSERT_STREQ(user->homedir, "/test");
	ASSERT_STREQ(user->shell, "/bin/test");

	auto userlist = mgr.get_userlist(container_id);
	{
		ASSERT_TRUE(userlist.has_value());
		auto it = userlist->find(0);
		ASSERT_NE(it, userlist->end());
		ASSERT_EQ(it->second.uid, user->uid);
	}

	// group
	mgr.add_group(container_id, -1, 0, std::string_view("test"));
	auto group = mgr.get_group(container_id, 0);
	ASSERT_TRUE(group.has_value());
	ASSERT_EQ(group->gid, 0);
	ASSERT_STREQ(group->name, "test");

	auto grouplist = mgr.get_grouplist(container_id);
	{
		ASSERT_TRUE(grouplist.has_value());
		auto it = grouplist->find(0);
		ASSERT_NE(it, grouplist->end());
		ASSERT_EQ(it->second.gid, group->gid);
	}

	// rm
	mgr.rm_user(container_id, 0);
	ASSERT_FALSE(mgr.get_user(container_id, 0).has_value());
	mgr.rm_group(container_id, 0);
	ASSERT_FALSE(mgr.get_group(container_id, 0).has_value());
}

TEST_F(usergroup_manager_test, invalid_sentinel_uid_gid) {
	const std::string container_id{""};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	// (uint32_t)-1 is the unresolved sentinel from threadinfo init.
	// Passing it to add_user/add_group must not trigger NSS lookups
	// (which can crash with third-party NSS modules like libnss_oslogin).
	auto* usr = mgr.add_user(container_id, -1, (uint32_t)-1, 0, true);
	ASSERT_EQ(usr, nullptr);
	ASSERT_EQ(mgr.get_user(container_id, (uint32_t)-1), nullptr);

	auto* grp = mgr.add_group(container_id, -1, (uint32_t)-1, true);
	ASSERT_EQ(grp, nullptr);
	ASSERT_EQ(mgr.get_group(container_id, (uint32_t)-1), nullptr);
}

// note(jasondellaluce): emscripten has issues with getpwuid
#if !defined(__EMSCRIPTEN__)
TEST_F(usergroup_manager_test, system_lookup) {
	const std::string container_id{""};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_user(container_id, -1, 0, 0, {}, {}, {});
	auto user = mgr.get_user(container_id, 0);
	ASSERT_TRUE(user.has_value());
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "root");
#if defined(__APPLE__)
	// if the container_id is empty the user will be populated
	// with the host user. In case of macos we have to use the
	// correct root home directory.
	ASSERT_STREQ(user->homedir, "/var/root");
#else
	ASSERT_STREQ(user->homedir, "/root");
#endif
	ASSERT_EQ(std::string(user->shell).empty(), false);

	mgr.add_group(container_id, -1, 0, std::string_view{});
	auto group = mgr.get_group(container_id, 0);
	ASSERT_TRUE(group.has_value());
	ASSERT_EQ(group->gid, 0);
#if defined(__APPLE__)
	// if the container_id is empty the group will be populated
	// with the host group. In case of macos we have to use the
	// correct root group.
	ASSERT_STREQ(group->name, "wheel");
#else
	ASSERT_STREQ(group->name, "root");
#endif
}
#endif

TEST_F(usergroup_manager_test, add_no_import_users) {
	const std::string container_id{""};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};
	mgr.m_import_users = false;

	auto* added_usr = mgr.add_user(container_id, -1, 37, 15, "test", "/test", "/bin/test");
	ASSERT_NE(added_usr, nullptr);
	ASSERT_EQ(added_usr->uid, 37);
	ASSERT_EQ(added_usr->gid, 15);
	ASSERT_STREQ(added_usr->name, "<NA>");
	ASSERT_STREQ(added_usr->homedir, "<NA>");
	ASSERT_STREQ(added_usr->shell, "<NA>");

	ASSERT_FALSE(mgr.get_user(container_id, 37).has_value());

	auto* added_grp = mgr.add_group(container_id, -1, 15, std::string_view{"foo"});
	ASSERT_NE(added_grp, nullptr);
	ASSERT_EQ(added_grp->gid, 15);
	ASSERT_STREQ(added_grp->name, "<NA>");

	ASSERT_FALSE(mgr.get_group(container_id, 15).has_value());
}

// note(jasondellaluce): emscripten has issues with fgetpwent
// note(therealbobo): macos doesn't define fgetpwent
#if(defined(HAVE_PWD_H) && defined(HAVE_GRP_H)) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
class usergroup_manager_host_root_test : public sinsp_with_test_input {
protected:
	void SetUp() override {
		char pwd_buf[SCAP_MAX_PATH_SIZE];
		auto pwd = getcwd(pwd_buf, SCAP_MAX_PATH_SIZE);
		ASSERT_NE(pwd, nullptr);
		m_host_root = pwd_buf;
		m_host_root += "/host";

		ASSERT_EQ(mkdir(m_host_root.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
		m_inspector.set_host_root(m_host_root);

		std::string etc = m_host_root + "/etc";
		ASSERT_EQ(mkdir(etc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

		{
			std::ofstream ofs(etc + "/passwd");
			ofs << "toor:x:0:0:toor:/toor:/bin/ash\n"
			    << "+testuser::::::\n";
		}
		{
			std::ofstream ofs(etc + "/group");
			ofs << "toor:x:0:toor\n"
			    << "+testgroup::::::\n";
		}
	}

	void TearDown() override {
		unlink((m_host_root + "/etc/passwd").c_str());
		unlink((m_host_root + "/etc/group").c_str());
		rmdir((m_host_root + "/etc").c_str());
		rmdir(m_host_root.c_str());
	}

	std::string m_host_root;
};

TEST_F(usergroup_manager_host_root_test, host_root_lookup) {
	const std::string container_id{""};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_user(container_id, -1, 0, 0, {}, {}, {});
	auto user = mgr.get_user(container_id, 0);
	ASSERT_TRUE(user.has_value());
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "toor");
	ASSERT_STREQ(user->homedir, "/toor");
	ASSERT_STREQ(user->shell, "/bin/ash");

	mgr.add_group(container_id, -1, 0, std::string_view{});
	auto group = mgr.get_group(container_id, 0);
	ASSERT_TRUE(group.has_value());
	ASSERT_EQ(group->gid, 0);
	ASSERT_STREQ(group->name, "toor");
}

TEST_F(usergroup_manager_host_root_test, nss_user_lookup) {
	const std::string container_id;  // empty container_id means host
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};
	mgr.add_user(container_id, -1, 0, 0, {}, {}, {});
	mgr.add_user(container_id, -1, 65534, 0, {}, {}, {});

	auto* usr = mgr.add_user(container_id, -1, 0, 0, "+test_user", "", "");
	ASSERT_EQ(usr, nullptr);

	auto* grp = mgr.add_group(container_id, -1, 0, std::string_view("+test_group"));
	ASSERT_EQ(grp, nullptr);
}
#endif

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
