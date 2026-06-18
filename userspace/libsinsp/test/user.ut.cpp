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
	ASSERT_EQ(mgr.get_user(container_id, 0), nullptr);
	ASSERT_EQ(mgr.get_group(container_id, 0), nullptr);
	ASSERT_EQ(mgr.get_userlist(container_id), nullptr);
	ASSERT_EQ(mgr.get_grouplist(container_id), nullptr);

	// user
	mgr.add_user(container_id, -1, 0, 0, "test", "/test", "/bin/test");
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "test");
	ASSERT_STREQ(user->homedir, "/test");
	ASSERT_STREQ(user->shell, "/bin/test");

	auto* userlist = mgr.get_userlist(container_id);
	{
		auto it = userlist->find(0);
		ASSERT_NE(it, userlist->end());
		ASSERT_EQ(&(it->second), user);
	}

	// group
	mgr.add_group(container_id, -1, 0, std::string_view("test"));
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
	ASSERT_EQ(group->gid, 0);
	ASSERT_STREQ(group->name, "test");

	auto* grouplist = mgr.get_grouplist(container_id);
	{
		auto it = grouplist->find(0);
		ASSERT_NE(it, grouplist->end());
		ASSERT_EQ(&(it->second), group);
	}

	// rm
	mgr.rm_user(container_id, 0);
	ASSERT_EQ(mgr.get_user(container_id, 0), nullptr);
	mgr.rm_group(container_id, 0);
	ASSERT_EQ(mgr.get_group(container_id, 0), nullptr);
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
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
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
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
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

	auto* user = mgr.get_user(container_id, 37);
	ASSERT_EQ(user, nullptr);

	auto* added_grp = mgr.add_group(container_id, -1, 15, std::string_view{"foo"});
	ASSERT_NE(added_grp, nullptr);
	ASSERT_EQ(added_grp->gid, 15);
	ASSERT_STREQ(added_grp->name, "<NA>");

	auto* group = mgr.get_group(container_id, 15);
	ASSERT_EQ(group, nullptr);
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
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "toor");
	ASSERT_STREQ(user->homedir, "/toor");
	ASSERT_STREQ(user->shell, "/bin/ash");

	mgr.add_group(container_id, -1, 0, std::string_view{});
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
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

// Fixture that lets each test write its own /etc/passwd and /etc/group under a
// host root, to exercise the file-parsing edge cases in user.cpp.
class usergroup_manager_host_root_parsing_test : public sinsp_with_test_input {
protected:
	void SetUp() override {
		char pwd_buf[SCAP_MAX_PATH_SIZE];
		auto pwd = getcwd(pwd_buf, SCAP_MAX_PATH_SIZE);
		ASSERT_NE(pwd, nullptr);
		m_host_root = pwd_buf;
		m_host_root += "/host_parsing";

		ASSERT_EQ(mkdir(m_host_root.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
		m_inspector.set_host_root(m_host_root);

		m_etc = m_host_root + "/etc";
		ASSERT_EQ(mkdir(m_etc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
	}

	void TearDown() override {
		unlink((m_etc + "/passwd").c_str());
		unlink((m_etc + "/group").c_str());
		rmdir(m_etc.c_str());
		rmdir(m_host_root.c_str());
	}

	void write_passwd(const std::string& content) {
		std::ofstream ofs(m_etc + "/passwd");
		ofs << content;
	}

	void write_group(const std::string& content) {
		std::ofstream ofs(m_etc + "/group");
		ofs << content;
	}

	std::string m_host_root;
	std::string m_etc;
};

// Regression test for the infinite loop: a group with a very large member list
// produces a line far bigger than the historical 4096-byte parse buffer. The
// old fgetgrent_r loop returned ERANGE and spun forever; ensure we parse past
// it and still resolve both it and a group defined after it.
TEST_F(usergroup_manager_host_root_parsing_test, oversized_group_line_does_not_hang) {
	std::string members;
	for(int i = 0; i < 5000; i++) {
		if(i) {
			members += ",";
		}
		members += "user" + std::to_string(i);
	}
	ASSERT_GT(members.size(), 4096u);  // sanity: the line really is oversized
	write_group(
	        "root:x:0:\n"
	        "bigteam:x:4242:" +
	        members + "\n" + "after:x:4243:\n");

	const std::string container_id;
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	// A group defined *after* the oversized line must still resolve.
	mgr.add_group(container_id, -1, 4243, std::string_view{});
	auto* after = mgr.get_group(container_id, 4243);
	ASSERT_NE(after, nullptr);
	ASSERT_EQ(after->gid, 4243);
	ASSERT_STREQ(after->name, "after");

	// The oversized group itself resolves by gid, with the correct name.
	mgr.add_group(container_id, -1, 4242, std::string_view{});
	auto* big = mgr.get_group(container_id, 4242);
	ASSERT_NE(big, nullptr);
	ASSERT_EQ(big->gid, 4242);
	ASSERT_STREQ(big->name, "bigteam");
}

// A non-numeric gid must be skipped, not silently coerced to 0 (which would
// alias to root and return the wrong group name).
TEST_F(usergroup_manager_host_root_parsing_test, non_numeric_gid_is_rejected) {
	write_group(
	        "bogus:x:notanumber:\n"
	        "realroot:x:0:\n");

	const std::string container_id;
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, -1, 0, std::string_view{});
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
	ASSERT_EQ(group->gid, 0);
	ASSERT_STREQ(group->name, "realroot");
}

// Same for a non-numeric uid in /etc/passwd.
TEST_F(usergroup_manager_host_root_parsing_test, non_numeric_uid_is_rejected) {
	write_passwd(
	        "bogus:x:notanumber:0:bogus:/bogus:/bin/bogus\n"
	        "realroot:x:0:0:realroot:/root:/bin/bash\n");

	const std::string container_id;
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_user(container_id, -1, 0, 0, {}, {}, {});
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
	ASSERT_EQ(user->uid, 0);
	ASSERT_STREQ(user->name, "realroot");
	ASSERT_STREQ(user->homedir, "/root");
	ASSERT_STREQ(user->shell, "/bin/bash");
}

// A gid with trailing garbage ("5x") is only a partial number and must be
// rejected: from_chars must consume the entire field.
TEST_F(usergroup_manager_host_root_parsing_test, gid_with_trailing_garbage_is_rejected) {
	write_group(
	        "weird:x:5x:\n"
	        "normal:x:5:\n");

	const std::string container_id;
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, -1, 5, std::string_view{});
	auto* group = mgr.get_group(container_id, 5);
	ASSERT_NE(group, nullptr);
	ASSERT_STREQ(group->name, "normal");
}

// Empty and short (too few fields) lines are skipped; a gid that only appears
// on such a line is not found.
TEST_F(usergroup_manager_host_root_parsing_test, short_lines_are_skipped) {
	write_group(
	        "\n"
	        "incomplete:x\n"
	        "good:x:7:\n");

	const std::string container_id;
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, -1, 7, std::string_view{});
	auto* group = mgr.get_group(container_id, 7);
	ASSERT_NE(group, nullptr);
	ASSERT_STREQ(group->name, "good");

	mgr.add_group(container_id, -1, 999, std::string_view{});
	ASSERT_EQ(mgr.get_group(container_id, 999), nullptr);
}
#endif
