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

#ifndef FALCOSECURITY_LIBS_USER_H
#define FALCOSECURITY_LIBS_USER_H

#include <unordered_map>
#include <string>
#include <memory>
#include <libsinsp/procfs_utils.h>
#include <libsinsp/sinsp.h>

class sinsp;
namespace libsinsp {
namespace procfs_utils {
class ns_helper;
}
}  // namespace libsinsp

/*
 * Basic idea:
 * * when container_manager tries to resolve a threadinfo container, it will update
 * * its user/group informations, using following algorithm:
 * * if the thread itself is on the HOST, it will call getpwuid/getgrgid,
 * 		and store the new user/group together with informations,
 * 		eventually notifying any change in users and groups.
 * 		If no information can be retrieved, only uid/gid will be stored as informations, with "<NA>"
 * for everything else.
 * * if the thread is on a container, the new user/group will be stored using the container id as
 * key, without additional info (ie: username, homedir etc etc will be left "<NA>") because they
 * cannot be retrieved from a container. Then, a PPME_{USER,GROUP}_ADDED event is emitted, to allow
 * capture files to rebuild the state.
 *
 * * on PPME_{USER,GROUP}_ADDED, the new user/group is stored in the
 * m_{user,group}_list<container_id>, if not present.
 *
 * * Host users and groups lists are cleared once every DEFAULT_DELETED_USERS_GROUPS_SCAN_TIME_S (1
 * min by default), see sinsp::m_usergroups_purging_scan_time_ns. Then, the users and groups will be
 * refreshed as explained above, every time a threadinfo is created. This is needed to fetch deleted
 * users/groups, or overwritten ones. Note: PPME_USER_DELETED_E is never sent for host users; we
 * miss the mechanism to undestand when an user is removed (without calling scap_get_userlist and
 * comparing to the already stored one; but that is an heavy operation).
 * * Containers users and groups gets bulk deleted once the container is cleaned up and
 *      PPME_{USER,GROUP}_DELETED_E event is sent for each of them.
 *
 * * Each threadinfo stores internally its user and group informations.
 *      This is needed to avoid that eg: a threadinfo spawns on uid 1000 "foo".
 *      Then, uid 1000 is deleted, and a new uid 1000 is created, named "bar".
 *      We need to be able to tell that the threadinfo user is still "foo".
 */
class sinsp_usergroup_manager {
public:
	explicit sinsp_usergroup_manager(sinsp *inspector);
	~sinsp_usergroup_manager() = default;

	void dump_users_groups(sinsp_dumper &dumper);

	/*!
	  \brief Return the table with all the machine users.

	  \return a hash table with the user ID (UID) as the key and the user information as the data.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	*/
	const std::unordered_map<uint32_t, scap_userinfo> *get_userlist(
	        const std::string &container_id);

	/*!
	  \brief Lookup for user in the user table.

	  \return the \ref scap_userinfo object containing full user information,
	   if user not found, returns NULL.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	*/
	scap_userinfo *get_user(const std::string &container_id, uint32_t uid);

	/*!
	  \brief Return the table with all the machine user groups.

	  \return a hash table with the group ID (GID) as the key and the group
	   information as the data.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   user table is the one of the machine where the capture happened.
	*/
	const std::unordered_map<uint32_t, scap_groupinfo> *get_grouplist(
	        const std::string &container_id);

	/*!
	  \brief Lookup for group in the group table for a container.

	  \return the \ref scap_groupinfo object containing full group information,
	   if group not found, returns NULL.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   group list is the one of the machine where the capture happened.
	*/
	scap_groupinfo *get_group(const std::string &container_id, uint32_t gid);

	// Note: pid is an unused parameter when container_id is an empty string
	// ie: it is only used when adding users/groups from containers.
	scap_userinfo *add_user(const std::string &container_id,
	                        int64_t pid,
	                        uint32_t uid,
	                        uint32_t gid,
	                        std::string_view name,
	                        std::string_view home,
	                        std::string_view shell,
	                        bool notify = false);
	scap_groupinfo *add_group(const std::string &container_id,
	                          int64_t pid,
	                          uint32_t gid,
	                          std::string_view name,
	                          bool notify = false);

	bool rm_user(const std::string &container_id, uint32_t uid, bool notify = false);
	bool rm_group(const std::string &container_id, uint32_t gid, bool notify = false);

	bool clear_host_users_groups();

	void delete_container(const std::string &container_id);

	//
	// User and group tables
	//
	bool m_import_users;

private:
	scap_userinfo *add_host_user(uint32_t uid,
	                             uint32_t gid,
	                             std::string_view name,
	                             std::string_view home,
	                             std::string_view shell,
	                             bool notify);
	scap_userinfo *add_container_user(const std::string &container_id,
	                                  int64_t pid,
	                                  uint32_t uid,
	                                  bool notify);

	scap_groupinfo *add_host_group(uint32_t gid, std::string_view name, bool notify);
	scap_groupinfo *add_container_group(const std::string &container_id,
	                                    int64_t pid,
	                                    uint32_t gid,
	                                    bool notify);

	bool user_to_sinsp_event(const scap_userinfo *user,
	                         sinsp_evt *evt,
	                         const std::string &container_id,
	                         uint16_t ev_type);
	bool group_to_sinsp_event(const scap_groupinfo *group,
	                          sinsp_evt *evt,
	                          const std::string &container_id,
	                          uint16_t ev_type);

	void notify_user_changed(const scap_userinfo *user,
	                         const std::string &container_id,
	                         bool added = true);
	void notify_group_changed(const scap_groupinfo *group,
	                          const std::string &container_id,
	                          bool added = true);

	using userinfo_map = std::unordered_map<uint32_t, scap_userinfo>;
	using groupinfo_map = std::unordered_map<uint32_t, scap_groupinfo>;

	scap_userinfo *userinfo_map_insert(userinfo_map &map,
	                                   uint32_t uid,
	                                   uint32_t gid,
	                                   std::string_view name,
	                                   std::string_view home,
	                                   std::string_view shell);

	scap_groupinfo *groupinfo_map_insert(groupinfo_map &map, uint32_t gid, std::string_view name);

	std::unordered_map<std::string, userinfo_map> m_userlist;
	std::unordered_map<std::string, groupinfo_map> m_grouplist;
	uint64_t m_last_flush_time_ns;
	sinsp *m_inspector;

	// User and group used as a fallback when m_import_users is disabled
	scap_userinfo m_fallback_user;
	scap_groupinfo m_fallback_grp;

	const std::string &m_host_root;
	std::unique_ptr<libsinsp::procfs_utils::ns_helper> m_ns_helper;
};

// RAII struct to manage threadinfos automatic user/group refresh
// upon container_id updates.
struct user_group_updater {
	explicit user_group_updater(sinsp_evt *evt): m_check_cleanup(false), m_evt(nullptr) {
		switch(evt->get_type()) {
		case PPME_PROCEXIT_E:
		case PPME_PROCEXIT_1_E:
			m_check_cleanup = true;
			// falltrough
		case PPME_SYSCALL_CLONE_11_X:
		case PPME_SYSCALL_CLONE_16_X:
		case PPME_SYSCALL_CLONE_17_X:
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_FORK_X:
		case PPME_SYSCALL_FORK_17_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_X:
		case PPME_SYSCALL_VFORK_17_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE3_X:
		case PPME_SYSCALL_EXECVE_8_X:
		case PPME_SYSCALL_EXECVE_13_X:
		case PPME_SYSCALL_EXECVE_14_X:
		case PPME_SYSCALL_EXECVE_15_X:
		case PPME_SYSCALL_EXECVE_16_X:
		case PPME_SYSCALL_EXECVE_17_X:
		case PPME_SYSCALL_EXECVE_18_X:
		case PPME_SYSCALL_EXECVE_19_X:
		case PPME_SYSCALL_EXECVEAT_X:
		case PPME_SYSCALL_CHROOT_X:
			m_evt = evt;
			if(m_evt->get_tinfo() != nullptr) {
				m_container_id = m_evt->get_tinfo()->get_container_id();
			}
			break;
		default:
			break;
		}
	}

	~user_group_updater() {
		if(m_evt != nullptr && m_evt->get_tinfo() != nullptr) {
			const auto tinfo = m_evt->get_tinfo();
			const auto container_id = tinfo->get_container_id();
			if(container_id != m_container_id) {
				// Refresh user/group
				tinfo->set_group(tinfo->m_gid);
				tinfo->set_user(tinfo->m_uid);
			} else if(m_check_cleanup && !container_id.empty()) {
				if(tinfo->m_vtid == tinfo->m_vpid && tinfo->m_vpid == 1) {
					// main container process left, clean up user and groups for the container
					const auto inspector = m_evt->get_inspector();
					if(inspector->m_usergroup_manager->m_import_users &&
					   (inspector->is_live() || inspector->is_syscall_plugin())) {
						inspector->m_usergroup_manager->delete_container(container_id);
					}
				}
			}
		}
	}

	bool m_check_cleanup;
	sinsp_evt *m_evt;
	std::string m_container_id;
};

#endif  // FALCOSECURITY_LIBS_USER_H
