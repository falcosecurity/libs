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
#include "scap.h"

class sinsp;

using namespace std;

class sinsp_usergroup_manager
{
public:
	explicit sinsp_usergroup_manager(sinsp* inspector);

	/*!
  	\brief Return the table with all the machine users.

	\return a hash table with the user ID (UID) as the key and the user
									  information as the data.

	  \note this call works with file captures as well, because the user
			table is stored in the trace files. In that case, the returned
				user list is the one of the machine where the capture happened.
	*/
	const unordered_map<uint32_t, scap_userinfo*>* get_userlist();

	/*!
	  \brief Lookup for user in the user table.

	  \return the \ref scap_userinfo object containing full user information,
	   if user not found, returns NULL.

	  \note this call works with file captures as well, because the user
	   table is stored in the trace files. In that case, the returned
	   user list is the one of the machine where the capture happened.
	*/
	scap_userinfo* get_user(uint32_t uid);

	/*!
	  \brief Return the table with all the machine user groups.

	  \return a hash table with the group ID (GID) as the key and the group
	   information as the data.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   user table is the one of the machine where the capture happened.
	*/
	const unordered_map<uint32_t, scap_groupinfo*>* get_grouplist();

	/*!
	  \brief Lookup for group in the group table.

	  \return the \ref scap_groupinfo object containing full group information,
	   if group not found, returns NULL.

	  \note this call works with file captures as well, because the group
	   table is stored in the trace files. In that case, the returned
	   group list is the one of the machine where the capture happened.
	*/
	scap_groupinfo* get_group(uint32_t gid);

	void import_users_groups_list();

	void notify_user_changed(scap_userinfo *user, uint64_t tid, bool added = true);

	bool cleanup_deleted_users_groups();

private:
	unordered_map<uint32_t, scap_userinfo*> m_userlist;
	unordered_map<uint32_t, scap_groupinfo*> m_grouplist;
	uint64_t m_last_flush_time_ns;
	sinsp *m_inspector;
};

#endif // FALCOSECURITY_LIBS_USER_H
