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
#include <optional>
#include <shared_mutex>
#include <string>
#include <memory>
#include <mutex>
#include <libsinsp/procfs_utils.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sync_policy.h>

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
 * PPME_USER_DELETED_E is never sent for host users; we
 * miss the mechanism to undestand when an user is removed (without calling scap_get_userlist and
 * comparing to the already stored one; but that is an heavy operation).
 * * Containers users and groups gets bulk deleted once the container is cleaned up and
 *      PPME_{USER,GROUP}_DELETED_E event is sent for each of them.
 *
 * * Each threadinfo stores internally its uid and gid informations that, together
 * with the container_id written by the container plugin, will be used as keys to access
 * user/group metadata cache tables.
 *
 * Thread safety is selected by the `SyncPolicy` template parameter:
 * * `sync_policy_single`: no locking at all (the lock is a no-op type), same code and layout as an
 *   unsynchronized manager. This is what `sinsp_usergroup_manager` is, unless the library is built
 *   with `LIBSINSP_SYNC_POLICY_CONCURRENT` defined.
 * * `sync_policy_concurrent`: a reader/writer lock protects the tables, so that any thread can
 *   look up, add and remove users and groups at the same time. Use `with_user()`/`with_group()` and
 *   `copy_userlist()`/`copy_grouplist()` to read: the pointers returned by `get_user()` and friends
 *   refer to the tables and are only valid while no other thread modifies them.
 */
template<typename SyncPolicy>
class basic_usergroup_manager {
public:
	explicit basic_usergroup_manager(sinsp *inspector, const timestamper &timestamper);
	~basic_usergroup_manager() = default;

	void dump_users_groups(sinsp_dumper &dumper);

	/*!
	  \brief Return the table with all the machine users.

	  \return a hash table with the user ID (UID) as the key and the user information as the data.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	  \note the returned pointer refers to the table itself: with a concurrent policy use
	   `copy_userlist()` instead.
	*/
	const std::unordered_map<uint32_t, scap_userinfo> *get_userlist(
	        const std::string &container_id);

	/*!
	  \brief Return a copy of the user table of a container, taken atomically.

	  \return the copy, or `std::nullopt` if there is no table for the container.
	*/
	std::optional<std::unordered_map<uint32_t, scap_userinfo>> copy_userlist(
	        const std::string &container_id);

	/*!
	  \brief Call `visitor(const scap_userinfo &)` with the user, if it is found, while the entry
	   cannot change. No copy and no allocation.

	  \return true if the user was found and the visitor was called, false otherwise.

	  \note the visitor must not call back into this manager.
	*/
	template<typename Visitor>
	bool with_user(const std::string &container_id, uint32_t uid, Visitor &&visitor) {
		std::shared_lock<mutex_type> lock(m_mutex);
		const scap_userinfo *usr = get_user_assuming_lock_held(container_id, uid);
		if(usr == nullptr) {
			return false;
		}
		visitor(*usr);
		return true;
	}

	/*!
	  \brief Lookup for user in the user table.

	  \return the \ref scap_userinfo object containing full user information,
	   if user not found, returns NULL.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	  \note the returned pointer refers to the table itself: with a concurrent policy use
	   `with_user()` instead.
	*/
	scap_userinfo *get_user(const std::string &container_id, uint32_t uid);

	/*!
	  \brief Return the table with all the machine user groups.

	  \return a hash table with the group ID (GID) as the key and the group
	   information as the data.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   user table is the one of the machine where the capture happened.
	  \note the returned pointer refers to the table itself: with a concurrent policy use
	   `copy_grouplist()` instead.
	*/
	const std::unordered_map<uint32_t, scap_groupinfo> *get_grouplist(
	        const std::string &container_id);

	/*!
	  \brief Return a copy of the group table of a container, taken atomically.

	  \return the copy, or `std::nullopt` if there is no table for the container.
	*/
	std::optional<std::unordered_map<uint32_t, scap_groupinfo>> copy_grouplist(
	        const std::string &container_id);

	/*!
	  \brief Call `visitor(const scap_groupinfo &)` with the group, if it is found, while the entry
	   cannot change. No copy and no allocation.

	  \return true if the group was found and the visitor was called, false otherwise.

	  \note the visitor must not call back into this manager.
	*/
	template<typename Visitor>
	bool with_group(const std::string &container_id, uint32_t gid, Visitor &&visitor) {
		std::shared_lock<mutex_type> lock(m_mutex);
		const scap_groupinfo *grp = get_group_assuming_lock_held(container_id, gid);
		if(grp == nullptr) {
			return false;
		}
		visitor(*grp);
		return true;
	}

	/*!
	  \brief Lookup for group in the group table for a container.

	  \return the \ref scap_groupinfo object containing full group information,
	   if group not found, returns NULL.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   group list is the one of the machine where the capture happened.
	  \note the returned pointer refers to the table itself: with a concurrent policy use
	   `with_group()` instead.
	*/
	scap_groupinfo *get_group(const std::string &container_id, uint32_t gid);

	// Note: pid is an unused parameter when container_id is an empty string
	// ie: it is only used when adding users/groups from containers.
	// Note: with a concurrent policy, the returned pointers refer to the tables and are only valid
	// while no other thread modifies them; callers that do not need them should ignore them.
	// Note: when container users/groups are added, the container's /etc/passwd and /etc/group are
	// read while the writer lock is held.
	scap_userinfo *add_user(const std::string &container_id,
	                        int64_t pid,
	                        uint32_t uid,
	                        uint32_t gid,
	                        bool notify = false);
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
	                          bool notify = false);
	scap_groupinfo *add_group(const std::string &container_id,
	                          int64_t pid,
	                          uint32_t gid,
	                          std::string_view name,
	                          bool notify = false);

	bool rm_user(const std::string &container_id, uint32_t uid, bool notify = false);
	bool rm_group(const std::string &container_id, uint32_t gid, bool notify = false);

	void delete_container(const std::string &container_id);

	//
	// User and group tables
	//
	typename libsinsp::sync_policy_traits<SyncPolicy>::atomic_flag m_import_users;

private:
	using mutex_type = typename libsinsp::sync_policy_traits<SyncPolicy>::shared_mutex;

	// The *_assuming_lock_held() and *_impl() methods below do not lock: they are called by the
	// public methods, that hold m_mutex (shared for lookups, exclusive for modifications). They
	// never call a public method, so that m_mutex is never taken twice by the same thread.
	scap_userinfo *get_user_assuming_lock_held(const std::string &container_id, uint32_t uid);
	scap_groupinfo *get_group_assuming_lock_held(const std::string &container_id, uint32_t gid);
	const std::unordered_map<uint32_t, scap_userinfo> *get_userlist_assuming_lock_held(
	        const std::string &container_id);
	const std::unordered_map<uint32_t, scap_groupinfo> *get_grouplist_assuming_lock_held(
	        const std::string &container_id);

	scap_userinfo *add_user_impl(const std::string &container_id,
	                             int64_t pid,
	                             uint32_t uid,
	                             uint32_t gid,
	                             std::string_view name,
	                             std::string_view home,
	                             std::string_view shell,
	                             bool notify);
	scap_groupinfo *add_group_impl(const std::string &container_id,
	                               int64_t pid,
	                               uint32_t gid,
	                               std::string_view name,
	                               bool notify);

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
	sinsp *m_inspector;
	const timestamper &m_timestamper;

	// User and group used as a fallback when m_import_users is disabled
	scap_userinfo m_fallback_user;
	scap_groupinfo m_fallback_grp;

	const std::string &m_host_root;
	std::unique_ptr<libsinsp::procfs_utils::ns_helper> m_ns_helper;

	// Protects m_userlist, m_grouplist and the fallback entries.
	mutable mutex_type m_mutex;
};

extern template class basic_usergroup_manager<sync_policy_single>;
extern template class basic_usergroup_manager<sync_policy_concurrent>;

/// The user/group manager owned by `sinsp`: it uses `sync_policy_default`.
class sinsp_usergroup_manager : public basic_usergroup_manager<sync_policy_default> {
public:
	using basic_usergroup_manager<sync_policy_default>::basic_usergroup_manager;
};

// RAII struct to manage threadinfos automatic user/group refresh
// upon container_id updates.
struct user_group_updater {
	explicit user_group_updater(sinsp_evt *const evt,
	                            plugin_tables &plugin_tables,
	                            const bool must_notify_user_update,
	                            const bool must_notify_group_update):
	        m_check_cleanup(false),
	        m_evt(nullptr),
	        m_plugin_tables(plugin_tables),
	        m_must_notify_user_update{must_notify_user_update},
	        m_must_notify_group_update{must_notify_group_update} {
		switch(evt->get_type()) {
		case PPME_PROCEXIT_1_E:
			m_check_cleanup = true;
			// falltrough
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE3_X:
		case PPME_SYSCALL_EXECVE_19_X:
		case PPME_SYSCALL_EXECVEAT_X:
		case PPME_SYSCALL_CHROOT_X:
			m_evt = evt;
			if(m_evt->get_tinfo() != nullptr) {
				m_container_id = plugin_tables.get_container_id(*m_evt->get_tinfo());
			}
			break;
		default:
			break;
		}
	}

	~user_group_updater() {
		if(m_evt != nullptr && m_evt->get_tinfo() != nullptr) {
			const auto tinfo = m_evt->get_tinfo();
			const auto container_id = m_plugin_tables.get_container_id(*tinfo);
			const auto inspector = m_evt->get_inspector();
			auto &usergroup_manager = inspector->m_usergroup_manager;
			if(container_id != m_container_id) {
				// Refresh user/group
				usergroup_manager->add_group(container_id,
				                             tinfo->m_pid,
				                             tinfo->m_gid,
				                             m_must_notify_group_update);
				usergroup_manager->add_user(container_id,
				                            tinfo->m_pid,
				                            tinfo->m_uid,
				                            tinfo->m_gid,
				                            m_must_notify_user_update);
			} else if(m_check_cleanup && !container_id.empty()) {
				if(tinfo->m_vtid == tinfo->m_vpid && tinfo->m_vpid == 1) {
					// main container process left, clean up user and groups for the container
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
	plugin_tables &m_plugin_tables;
	bool m_must_notify_user_update;
	bool m_must_notify_group_update;
};

#endif  // FALCOSECURITY_LIBS_USER_H
