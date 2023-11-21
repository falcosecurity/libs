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

#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sinsp_with_test_input.h>
#include <libsinsp/user.h>

using namespace libsinsp;

class usergroup_manager_test : public sinsp_with_test_input
{
	// for gtest filtering convenience,
	// add something when needed
};

TEST_F(usergroup_manager_test, add_rm)
{
	std::string container_id{""};

	sinsp_usergroup_manager mgr(&m_inspector);
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
	mgr.add_group(container_id, -1, 0, "test");
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

// note(jasondellaluce): emscripten has issues with getpwuid
#if !defined(__EMSCRIPTEN__)
TEST_F(usergroup_manager_test, system_lookup)
{
	std::string container_id{""};

	sinsp_usergroup_manager mgr(&m_inspector);

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

	mgr.add_group(container_id, -1, 0, {});
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

TEST_F(usergroup_manager_test, add_no_import_users)
{
	std::string container_id{""};

	sinsp_usergroup_manager mgr(&m_inspector);
	mgr.m_import_users = false;

	auto *added_usr = mgr.add_user(container_id, -1, 37, 15, "test", "/test", "/bin/test");
	ASSERT_NE(added_usr, nullptr);
	ASSERT_EQ(added_usr->uid, 37);
	ASSERT_EQ(added_usr->gid, 15);
	ASSERT_STREQ(added_usr->name, "<NA>");
	ASSERT_STREQ(added_usr->homedir, "<NA>");
	ASSERT_STREQ(added_usr->shell, "<NA>");

	auto* user = mgr.get_user(container_id, 37);
	ASSERT_EQ(user, nullptr);

	auto *added_grp = mgr.add_group(container_id, -1, 15, "foo");
	ASSERT_NE(added_grp, nullptr);
	ASSERT_EQ(added_grp->gid, 15);
	ASSERT_STREQ(added_grp->name, "<NA>");

	auto* group = mgr.get_group(container_id, 15);
	ASSERT_EQ(group, nullptr);
}

// note(jasondellaluce): emscripten has issues with fgetpwent
// note(therealbobo): macos doesn't define fgetpwent
#if (defined(HAVE_PWD_H) &&  defined(HAVE_GRP_H)) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
class usergroup_manager_host_root_test : public sinsp_with_test_input
{
protected:
	void SetUp() override
	{
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
			ofs << "toor:x:0:0:toor:/toor:/bin/ash" << std::endl;
			ofs.close();
		}
		{
			std::ofstream ofs(etc + "/group");
			ofs << "toor:x:0:toor" << std::endl;
			ofs.close();
		}
	}

	void TearDown() override
	{
		unlink((m_host_root + "/etc/passwd").c_str());
		unlink((m_host_root + "/etc/group").c_str());
		rmdir((m_host_root + "/etc").c_str());
		rmdir(m_host_root.c_str());
	}

	std::string m_host_root;
};

TEST_F(usergroup_manager_host_root_test, host_root_lookup)
{
	std::string container_id{""};

	sinsp_usergroup_manager mgr(&m_inspector);

	mgr.add_user(container_id, -1, 0, 0, {}, {}, {});
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_STREQ(user->name, "toor");
	ASSERT_STREQ(user->homedir, "/toor");
	ASSERT_STREQ(user->shell, "/bin/ash");

	mgr.add_group(container_id, -1, 0, {});
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
	ASSERT_EQ(group->gid, 0);
	ASSERT_STREQ(group->name, "toor");
}
#endif
