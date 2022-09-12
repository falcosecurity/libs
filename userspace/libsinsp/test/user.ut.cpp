/*
Copyright (C) 2022 The Falco Authors.

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

#include "sinsp_with_test_input.h"
#include "user.h"

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
	mgr.add_user(container_id, 0, 0, "test", "/test", "/bin/test");
	auto* user = mgr.get_user(container_id, 0);
	ASSERT_NE(user, nullptr);
	ASSERT_EQ(user->uid, 0);
	ASSERT_EQ(user->gid, 0);
	ASSERT_EQ(std::string(user->name), "test");
	ASSERT_EQ(std::string(user->homedir), "/test");
	ASSERT_EQ(std::string(user->shell), "/bin/test");

	auto* userlist = mgr.get_userlist(container_id);
	{
		auto it = userlist->find(0);
		ASSERT_NE(it, userlist->end());
		ASSERT_EQ(&(it->second), user);
	}

	// group
	mgr.add_group(container_id, 0, "test");
	auto* group = mgr.get_group(container_id, 0);
	ASSERT_NE(group, nullptr);
	ASSERT_EQ(group->gid, 0);
	ASSERT_EQ(std::string(group->name), "test");

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
