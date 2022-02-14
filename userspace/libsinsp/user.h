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

#ifndef FALCOSECURITY_LIBS_USER_H
#define FALCOSECURITY_LIBS_USER_H

#include <unordered_map>
#include <string>
#include "container_info.h"
#include "scap.h"

class sinsp;
class sinsp_evt;

using namespace std;

/*
 * Basic idea:
 * * when container_manager tries to resolve a threadinfo container, it will update
 * * its user/group informations, using following algorithm:
 * * if the thread itself is on the HOST, it will call refresh_host_users_groups_list,
 * 		that will refresh scap host user/group list and reimport host users groups in this class,
 * 		eventually notifying any change in users and groups
 * * if the thread is on a container, the new user/group will be stored using the container id as key,
 * 		without additional info (ie: username, homedir etc etc will be left "<NA>")
 * 		because they cannot be retrieved from a container.
 * 		Then, a PPME_{USER,GROUP}_ADDED event is emitted, to allow capture files to rebuild the state.
 *
 * * on PPME_{USER,GROUP}_ADDED, the new user/group is stored in the m_{user,group}_list<container_id>, if not present.
 *
 * * HOST users and groups are checked once every DEFAULT_DELETED_USERS_GROUPS_SCAN_TIME_S (1 min by default),
 * 		see sinsp::m_deleted_users_groups_scan_time_ns.
 * * Containers users and groups gets bulk deleted once the container is cleaned up.
 */
class sinsp_usergroup_manager
{
public:
	explicit sinsp_usergroup_manager(sinsp* inspector);

	/*!
  	  \brief Return the table with all the machine users.

	  \return a hash table with the user ID (UID) as the key and the user information as the data.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	*/
	const unordered_map<uint32_t, scap_userinfo>* get_userlist(const string &container_id);

	/*!
	  \brief Lookup for user in the user table.

	  \return the \ref scap_userinfo object containing full user information,
	   if user not found, returns NULL.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	*/
	scap_userinfo* get_user(const string &container_id, uint32_t uid);

	/*!
	  \brief Return the table with all the machine user groups.

	  \return a hash table with the group ID (GID) as the key and the group
	   information as the data.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   user table is the one of the machine where the capture happened.
	*/
	const unordered_map<uint32_t, scap_groupinfo>* get_grouplist(const string &container_id);

	/*!
	  \brief Lookup for group in the group table for a container.

	  \return the \ref scap_groupinfo object containing full group information,
	   if group not found, returns NULL.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   group list is the one of the machine where the capture happened.
	*/
	scap_groupinfo* get_group(const string &container_id, uint32_t gid);

	void import_host_users_groups_list();
	void refresh_host_users_groups_list();

	void delete_container_users_groups(const sinsp_container_info &cinfo);

	void notify_user_changed(const scap_userinfo *user, const string &container_id, bool added = true);
	void notify_group_changed(const scap_groupinfo *group, const string &container_id, bool added = true);

	bool add_user(const string &container_id, uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell);
	bool add_group(const string &container_id, uint32_t gid, const char *name);
	bool rm_user(const string &container_id, uint32_t uid);
	bool rm_group(const string &container_id, uint32_t gid);

	bool sync_host_users_groups();

private:
	bool user_to_sinsp_event(const scap_userinfo *user, sinsp_evt* evt, const string &container_id, uint16_t ev_type);
	bool group_to_sinsp_event(const scap_groupinfo *group, sinsp_evt* evt, const string &container_id, uint16_t ev_type);

	void notify_host_diff(const unordered_map<uint32_t, scap_userinfo> &old_host_userlist,
			      const unordered_map<uint32_t, scap_groupinfo> &old_host_grplist);

	unordered_map<string, unordered_map<uint32_t, scap_userinfo>> m_userlist;
	unordered_map<string, unordered_map<uint32_t, scap_groupinfo>> m_grouplist;
	uint64_t m_last_flush_time_ns;
	sinsp *m_inspector;
};

#endif // FALCOSECURITY_LIBS_USER_H
