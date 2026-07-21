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

// Fixture exercising the CONTAINER-pid parsing path (add_container_group/
// add_container_user), as opposed to the host path (empty container_id)
// covered above. in_own_ns_mnt()/get_pid_root() only stat() paths built from
// sinsp's host_root plus a pid, with no real process or mount namespace
// required, so a fake "/proc/<pid>/root/etc/{group,passwd}" tree under a
// temp host_root is enough to drive add_container_group/add_container_user
// directly, with the fake pid's root deliberately a different directory
// (thus a different inode) than the fake host-init "/proc/1/root".
class usergroup_manager_container_parsing_test : public sinsp_with_test_input {
protected:
	static constexpr int64_t s_container_pid = 12345;

	void SetUp() override {
		char pwd_buf[SCAP_MAX_PATH_SIZE];
		auto pwd = getcwd(pwd_buf, SCAP_MAX_PATH_SIZE);
		ASSERT_NE(pwd, nullptr);
		m_host_root = pwd_buf;
		m_host_root += "/host_container_parsing";

		ASSERT_EQ(mkdir(m_host_root.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
		m_inspector.set_host_root(m_host_root);

		const std::string proc = m_host_root + "/proc";
		ASSERT_EQ(mkdir(proc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

		// Fake host-init root (pid 1), used by ns_helper as the "still in
		// the host namespace" reference inode. Must be a different
		// directory than the container pid's root below.
		const std::string init_proc = proc + "/1";
		ASSERT_EQ(mkdir(init_proc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
		m_init_root = init_proc + "/root";
		ASSERT_EQ(mkdir(m_init_root.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

		// Fake container pid root.
		const std::string container_proc = proc + "/" + std::to_string(s_container_pid);
		ASSERT_EQ(mkdir(container_proc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
		m_container_root = container_proc + "/root";
		ASSERT_EQ(mkdir(m_container_root.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

		m_etc = m_container_root + "/etc";
		ASSERT_EQ(mkdir(m_etc.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

		// notify_group_changed/notify_user_changed no-op unless the
		// inspector is initialized; open_test_input() is the lightweight
		// way to reach that state without a real capture engine.
		open_inspector();
	}

	void TearDown() override {
		unlink((m_etc + "/passwd").c_str());
		unlink((m_etc + "/group").c_str());
		rmdir(m_etc.c_str());
		rmdir(m_container_root.c_str());
		rmdir((m_host_root + "/proc/" + std::to_string(s_container_pid)).c_str());
		rmdir(m_init_root.c_str());
		rmdir((m_host_root + "/proc/1").c_str());
		rmdir((m_host_root + "/proc").c_str());
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

	// Drains and counts every pending push in the inspector's async event
	// queue (there is no .size() on mpsc_priority_queue, only
	// empty()/try_pop()/try_pop_if()).
	int drain_async_events_queue() {
		int count = 0;
		sinsp::sinsp_evt_ptr elm;
		while(m_inspector.m_async_events_queue.try_pop(elm)) {
			count++;
		}
		return count;
	}

	std::string m_host_root;
	std::string m_init_root;
	std::string m_container_root;
	std::string m_etc;
};

// Regression test for the notify fan-out fix: the FIRST time a container's
// /etc/group is parsed, every real entry is genuinely new, so one notify per
// entry is correct and expected.
TEST_F(usergroup_manager_container_parsing_test, first_scan_notifies_once_per_entry) {
	write_group(
	        "root:x:0:\n"
	        "adm:x:4:\n"
	        "app:x:1000:\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, s_container_pid, 1000, std::string_view{}, /*notify=*/true);
	auto* group = mgr.get_group(container_id, 1000);
	ASSERT_NE(group, nullptr);
	ASSERT_STREQ(group->name, "app");

	// 3 real entries in the file, all new on this first scan: 3 notifies.
	ASSERT_EQ(drain_async_events_queue(), 3);
}

// The actual bug being fixed: a SECOND cache miss forces add_container_group
// to re-scan the whole file again (get_group's outer cache-hit check only
// short-circuits for gids it already resolved, not for a fresh miss on some
// OTHER, still-absent gid) — every line from the first scan is already
// cached by the time this happens, so the correct behavior is zero
// additional notifies. Before the fix, this second miss alone would have
// re-notified for every previously-cached line, unrelated to the miss.
TEST_F(usergroup_manager_container_parsing_test, second_scan_does_not_renotify_cached_entries) {
	write_group(
	        "root:x:0:\n"
	        "adm:x:4:\n"
	        "app:x:1000:\n"
	        "worker:x:1001:\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	// First miss: gid 1000. Populates the cache for all 4 lines, notifies 4 times.
	mgr.add_group(container_id, s_container_pid, 1000, std::string_view{}, /*notify=*/true);
	ASSERT_EQ(drain_async_events_queue(), 4);

	// Second miss: gid 9999 is NOT in the file at all, so get_group's outer
	// cache-hit check can't short-circuit — this forces genuine re-entry
	// into add_container_group, which re-scans and re-inserts all 4 lines
	// (groupinfo_map_insert always overwrites). All 4 were already cached
	// from the first scan, so the fix must produce zero notifies here.
	auto* missing =
	        mgr.add_group(container_id, s_container_pid, 9999, std::string_view{}, /*notify=*/true);
	ASSERT_EQ(missing, nullptr);
	ASSERT_EQ(mgr.get_group(container_id, 9999), nullptr);
	ASSERT_EQ(drain_async_events_queue(), 0);
}

// Same shape, for add_container_user/notify_user_changed via /etc/passwd.
TEST_F(usergroup_manager_container_parsing_test,
       second_user_scan_does_not_renotify_cached_entries) {
	write_passwd(
	        "root:x:0:0:root:/root:/bin/sh\n"
	        "app:x:1000:1000:app:/home/app:/bin/sh\n"
	        "worker:x:1001:1001:worker:/home/worker:/bin/sh\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_user(container_id, s_container_pid, 1000, 1000, {}, {}, {}, /*notify=*/true);
	ASSERT_EQ(drain_async_events_queue(), 3);

	// uid 9999 is absent from the file, so this is a genuine second miss
	// that re-enters add_container_user and re-scans all 3 already-cached
	// lines; the fix must produce zero additional notifies.
	auto* missing =
	        mgr.add_user(container_id, s_container_pid, 9999, 9999, {}, {}, {}, /*notify=*/true);
	ASSERT_EQ(missing, nullptr);
	ASSERT_EQ(mgr.get_user(container_id, 9999), nullptr);
	ASSERT_EQ(drain_async_events_queue(), 0);
}

// Final cached state must be identical regardless of the notify-dedup
// change: get_group/get_user still resolve every entry correctly, and
// repeated scans keep names fresh (groupinfo_map_insert/userinfo_map_insert
// still unconditionally overwrite on every parse).
TEST_F(usergroup_manager_container_parsing_test, cache_state_unaffected_by_dedup) {
	write_group(
	        "root:x:0:\n"
	        "app:x:1000:\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, s_container_pid, 1000, std::string_view{});
	ASSERT_NE(mgr.get_group(container_id, 0), nullptr);
	ASSERT_NE(mgr.get_group(container_id, 1000), nullptr);
	ASSERT_EQ(mgr.get_group(container_id, 4242), nullptr);

	// Re-scan (triggered by a miss on a still-unknown gid): previously
	// cached entries are still present and correct afterward.
	mgr.add_group(container_id, s_container_pid, 4242, std::string_view{});
	ASSERT_EQ(mgr.get_group(container_id, 4242), nullptr);  // not in the file
	auto* root = mgr.get_group(container_id, 0);
	ASSERT_NE(root, nullptr);
	ASSERT_STREQ(root->name, "root");
	auto* app = mgr.get_group(container_id, 1000);
	ASSERT_NE(app, nullptr);
	ASSERT_STREQ(app->name, "app");
}

// A rescan must still notify for an already-cached gid/uid whose underlying
// value (name, for groups; gid/name/home/shell, for users) changed since it
// was first cached — e.g. a rename. The cache-presence check alone
// (was_cached) is not sufficient to gate the notify: it must also compare
// against the previously cached value, or a legitimate change is silently
// swallowed even though the in-memory cache itself is updated correctly.
TEST_F(usergroup_manager_container_parsing_test, rescan_renotifies_on_value_change) {
	write_group(
	        "root:x:0:\n"
	        "app:x:1000:\n");
	write_passwd(
	        "root:x:0:0:root:/root:/bin/sh\n"
	        "app:x:1000:1000:app:/home/app:/bin/sh\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	// First scan: both files have 2 lines each ("root" + "app"), all 4
	// entries are genuinely new, all 4 notify.
	mgr.add_group(container_id, s_container_pid, 1000, std::string_view{}, /*notify=*/true);
	mgr.add_user(container_id, s_container_pid, 1000, 1000, {}, {}, {}, /*notify=*/true);
	ASSERT_EQ(drain_async_events_queue(), 4);

	// The underlying files change: gid/uid 1000's name is renamed, everything
	// else about the file (including the still-unrelated "root" line) is the
	// same. This is a value change on an already-cached key, not a new key.
	write_group(
	        "root:x:0:\n"
	        "appuser:x:1000:\n");
	write_passwd(
	        "root:x:0:0:root:/root:/bin/sh\n"
	        "appuser:x:1000:1000:appuser:/home/appuser:/bin/sh\n");

	// A miss on a still-unknown gid/uid forces add_container_group/
	// add_container_user to re-scan and re-cache every line, including the
	// renamed one, exactly the scenario that previously suppressed the
	// notify solely because gid/uid 1000 had already been seen before.
	mgr.add_group(container_id, s_container_pid, 4242, std::string_view{}, /*notify=*/true);
	mgr.add_user(container_id, s_container_pid, 4242, 4242, {}, {}, {}, /*notify=*/true);

	// The cache reflects the new name...
	auto* renamed_group = mgr.get_group(container_id, 1000);
	ASSERT_NE(renamed_group, nullptr);
	ASSERT_STREQ(renamed_group->name, "appuser");
	auto* renamed_user = mgr.get_user(container_id, 1000);
	ASSERT_NE(renamed_user, nullptr);
	ASSERT_STREQ(renamed_user->name, "appuser");

	// ...and the rename must have been notified, not silently swallowed.
	// "root" (unchanged) must NOT re-notify; only the two renamed entries do.
	ASSERT_EQ(drain_async_events_queue(), 2);
}

// sinsp_usergroup_manager::delete_container is otherwise untested. It must
// purge every cached user/group entry for a container_id, and be a safe
// no-op for a container_id that was never cached (no crash, no notify).
TEST_F(usergroup_manager_container_parsing_test, delete_container_purges_cache) {
	write_group("app:x:1000:\n");
	write_passwd("app:x:1000:1000:app:/home/app:/bin/sh\n");

	const std::string container_id{"deadbeef"};
	const timestamper timestamper{0};
	sinsp_usergroup_manager mgr{&m_inspector, timestamper};

	mgr.add_group(container_id, s_container_pid, 1000, std::string_view{});
	mgr.add_user(container_id, s_container_pid, 1000, 1000, {}, {}, {});
	ASSERT_NE(mgr.get_userlist(container_id), nullptr);
	ASSERT_NE(mgr.get_grouplist(container_id), nullptr);

	mgr.delete_container(container_id);

	ASSERT_EQ(mgr.get_userlist(container_id), nullptr);
	ASSERT_EQ(mgr.get_grouplist(container_id), nullptr);
	ASSERT_EQ(mgr.get_user(container_id, 1000), nullptr);
	ASSERT_EQ(mgr.get_group(container_id, 1000), nullptr);

	// Safe no-op for a container_id with nothing cached.
	mgr.delete_container("never-seen-container");
	ASSERT_EQ(mgr.get_userlist("never-seen-container"), nullptr);
}
#endif
