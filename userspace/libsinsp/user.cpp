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

#include "user.h"
#include "event.h"
#include "utils.h"
#include "logger.h"
#include "sinsp.h"

sinsp_usergroup_manager::sinsp_usergroup_manager(sinsp *inspector)
{
	m_inspector = inspector;
}

void sinsp_usergroup_manager::import_users_groups_list()
{
	m_userlist.clear();

	uint32_t j;
	scap_userlist* ul = scap_get_user_list(m_inspector->m_h);

	if(ul)
	{
		for(j = 0; j < ul->nusers; j++)
		{
			memcpy(&m_userlist[ul->users[j].uid], &ul->users[j], sizeof(scap_userinfo));
		}

		for(j = 0; j < ul->ngroups; j++)
		{
			memcpy(&m_grouplist[ul->groups[j].gid], &ul->groups[j], sizeof(scap_groupinfo));
		}
	}
}

void sinsp_usergroup_manager::refresh_user_list()
{
	scap_refresh_userlist(m_inspector->m_h);
	import_users_groups_list();
}

bool sinsp_usergroup_manager::cleanup_deleted_users_groups()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts - m_inspector->m_deleted_users_groups_scan_time_ns + 30 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->m_lastevent_ts >
	   m_last_flush_time_ns + m_inspector->m_deleted_users_groups_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		refresh_user_list();

		unordered_map<uint32_t, scap_userinfo> ulist = m_userlist;
		unordered_map<uint32_t, scap_groupinfo> glist = m_grouplist;

		import_users_groups_list();

		for (auto &u : ulist) {
			if (m_userlist.find(u.first) == m_userlist.end()) {
				// TODO: fix tid once we support tid
				notify_user_changed(&u.second, -1);
			}
		}

		for (auto &g : glist) {
			if (m_grouplist.find(g.first) == m_grouplist.end()) {
				// TODO: fix tid once we support tid
				notify_group_changed(&g.second, -1);
			}
		}
	}
	return res;
}

const unordered_map<uint32_t, scap_userinfo>* sinsp_usergroup_manager::get_userlist()
{
	return &m_userlist;
}

// TODO: add_user will take container_id as first param
bool sinsp_usergroup_manager::add_user(uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell)
{
	bool res = false;
	scap_userinfo *usr = get_user(uid);
	if (!usr) {
		m_userlist[uid].uid = uid;
		m_userlist[uid].gid = gid;
		snprintf(m_userlist[uid].name, MAX_CREDENTIALS_STR_LEN, "%s", name);
		snprintf(m_userlist[uid].homedir, SCAP_MAX_PATH_SIZE, "%s", home);
		snprintf(m_userlist[uid].shell, SCAP_MAX_PATH_SIZE, "%s", shell);

		res = true;
	}
	return res;
}

// TODO: add_group will take container_id as first param
bool sinsp_usergroup_manager::add_group(uint32_t gid, const char *name)
{
	bool res = false;
	scap_groupinfo *gr = get_group(gid);
	if (!gr) {
		m_grouplist[gid].gid = gid;
		snprintf(m_grouplist[gid].name, MAX_CREDENTIALS_STR_LEN, "%s", name);

		res = true;
	}
	return res;
}

bool sinsp_usergroup_manager::rm_user(uint32_t uid)
{
	bool res = false;
	scap_userinfo *usr = get_user(uid);
	if (usr) {
		m_userlist.erase(uid);
		res = true;
	}
	return res;
}

bool sinsp_usergroup_manager::rm_group(uint32_t gid)
{
	bool res = false;
	scap_groupinfo *gr = get_group(gid);
	if (gr) {
		m_grouplist.erase(gid);
		res = true;
	}
	return res;
}

scap_userinfo* sinsp_usergroup_manager::get_user(uint32_t uid)
{
	if(uid == 0xffffffff)
	{
		return NULL;
	}

	auto it = m_userlist.find(uid);
	if(it == m_userlist.end())
	{
		return NULL;
	}

	return &it->second;
}

const unordered_map<uint32_t, scap_groupinfo>* sinsp_usergroup_manager::get_grouplist()
{
	return &m_grouplist;
}

scap_groupinfo* sinsp_usergroup_manager::get_group(uint32_t gid)
{
	if(gid == 0xffffffff)
	{
		return NULL;
	}

	auto it = m_grouplist.find(gid);
	if(it == m_grouplist.end())
	{
		return NULL;
	}

	return &it->second;
}

void sinsp_usergroup_manager::notify_user_changed(scap_userinfo *user, uint64_t tid, bool added)
{
	sinsp_evt *evt = new sinsp_evt();

	// 5 lens, uid, gid, name, home, shell
	size_t totlen = sizeof(scap_evt) + 5 * sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + strlen(user->name) + strlen(user->homedir) + strlen(user->shell);

	ASSERT(evt->m_pevt_storage == nullptr);
	evt->m_pevt_storage = new char[totlen];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	if(m_inspector->m_lastevent_ts == 0)
	{
		// This can happen at startup when containers are
		// being created as a part of the initial process
		// scan.
		scapevt->ts = sinsp_utils::get_current_time_ns();
	}
	else
	{
		scapevt->ts = m_inspector->m_lastevent_ts;
	}
	scapevt->tid = tid;
	scapevt->len = (uint32_t)totlen;
	if (added)
	{
		scapevt->type = PPME_USER_ADDED_E;
	} else
	{
		scapevt->type = PPME_USER_DELETED_E;
	}
	scapevt->nparams = 5;

	uint32_t* lens = (uint32_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint32_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = sizeof(uint32_t);
	lens[2] = strlen(user->name);
	lens[3] = strlen(user->homedir);
	lens[4] = strlen(user->shell);

	memcpy(valptr, &user->uid, lens[0]);
	memcpy(valptr, &user->gid, lens[1]);
	memcpy(valptr, user->name, lens[2]);
	memcpy(valptr, user->homedir, lens[3]);
	memcpy(valptr, user->shell, lens[4]);

	evt->init();

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_user_changed (%d): created USER event, queuing to inspector",
			user->uid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}

void sinsp_usergroup_manager::notify_group_changed(scap_groupinfo *group, uint64_t tid, bool added)
{
	sinsp_evt *evt = new sinsp_evt();

	// gid, name
	size_t totlen = sizeof(scap_evt) + 2 * sizeof(uint32_t) + sizeof(uint32_t) + strlen(group->name);

	ASSERT(evt->m_pevt_storage == nullptr);
	evt->m_pevt_storage = new char[totlen];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	if(m_inspector->m_lastevent_ts == 0)
	{
		// This can happen at startup when containers are
		// being created as a part of the initial process
		// scan.
		scapevt->ts = sinsp_utils::get_current_time_ns();
	}
	else
	{
		scapevt->ts = m_inspector->m_lastevent_ts;
	}
	scapevt->tid = tid;
	scapevt->len = (uint32_t)totlen;
	if (added)
	{
		scapevt->type = PPME_GROUP_ADDED_E;
	} else
	{
		scapevt->type = PPME_GROUP_DELETED_E;
	}
	scapevt->nparams = 2;

	uint32_t* lens = (uint32_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint32_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = strlen(group->name);

	memcpy(valptr, &group->gid, lens[0]);
	memcpy(valptr, group->name, lens[1]);

	evt->init();

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_group_changed (%d): created GROUP event, queuing to inspector",
			group->gid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}