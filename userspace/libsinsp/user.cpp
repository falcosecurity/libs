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
#include "procfs_utils.h"
#include "utils.h"
#include "logger.h"
#include "sinsp.h"
#include "strlcpy.h"
#include <sys/types.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#if defined(HAVE_PWD_H) || defined(HAVE_GRP_H)

// See fgetpwent() / fgetgrent() feature test macros:
// https://man7.org/linux/man-pages/man3/fgetpwent.3.html
// https://man7.org/linux/man-pages/man3/fgetgrent.3.html
#if defined _DEFAULT_SOURCE || defined _SVID_SOURCE
#define HAVE_FGET__ENT
#endif

#endif

#ifdef HAVE_PWD_H
static struct passwd *__getpwuid(uint32_t uid, const std::string &host_root)
{
	if(host_root.empty())
	{
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		return getpwuid(uid);
	}

	// If we have a host root and we can use fgetpwent,
	// we take the entry directly from file
#ifdef HAVE_FGET__ENT
	static std::string filename(host_root + "/etc/passwd");

	auto f = fopen(filename.c_str(), "r");
	if(f)
	{
		struct passwd *p = nullptr;
		while((p = fgetpwent(f)))
		{
			if(uid == p->pw_uid)
			{
				break;
			}
		}

		fclose(f);
		return p;
	}
#endif
	return nullptr;
}
#endif

#ifdef HAVE_GRP_H
static struct group *__getgrgid(uint32_t gid, const std::string &host_root)
{
	if(host_root.empty())
	{
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		return getgrgid(gid);
	}

	// If we have a host root and we can use fgetgrent,
	// we take the entry directly from file
#ifdef HAVE_FGET__ENT
	static std::string filename(host_root + "/etc/group");

	auto f = fopen(filename.c_str(), "r");
	if(f)
	{
		struct group *p = nullptr;
		while((p = fgetgrent(f)))
		{
			if(gid == p->gr_gid)
			{
				break;
			}
		}

		fclose(f);
		return p;
	}
#endif
	return NULL;
}
#endif

using namespace std;

// clang-format off
sinsp_usergroup_manager::sinsp_usergroup_manager(sinsp* inspector)
	: m_import_users(true)
	, m_last_flush_time_ns(0)
	, m_inspector(inspector)
	, m_host_root(m_inspector->get_host_root())
#if defined(HAVE_PWD_H) || defined(HAVE_GRP_H)
	, m_ns_helper(new libsinsp::procfs_utils::ns_helper(m_host_root))
#else
	, m_ns_helper(nullptr)
#endif
{
	strlcpy(m_fallback_user.name, "<NA>", sizeof(m_fallback_user.name));
	strlcpy(m_fallback_user.homedir, "<NA>", sizeof(m_fallback_user.homedir));
	strlcpy(m_fallback_user.shell, "<NA>", sizeof(m_fallback_user.shell));
	strlcpy(m_fallback_grp.name, "<NA>", sizeof(m_fallback_grp.name));
}

sinsp_usergroup_manager::~sinsp_usergroup_manager()
{
#if defined(HAVE_PWD_H) || defined(HAVE_GRP_H)
	delete m_ns_helper;
#endif
}
// clang-format on

void sinsp_usergroup_manager::subscribe_container_mgr()
{
	// Do nothing if subscribe_container_mgr() is called in capture mode, because
	// events shall not be sent as they will be loaded from capture file.
	if (m_import_users && !m_inspector->is_capture())
	{
		// Emplace container manager listener to delete container users upon container deletion
		m_inspector->m_container_manager.subscribe_on_remove_container([&](const sinsp_container_info &cinfo) -> void {
			delete_container_users_groups(cinfo);
		});
	}
}

void sinsp_usergroup_manager::dump_users_groups(scap_dumper_t* dumper) {
	for (const auto &it: m_userlist) {
		std::string container_id = it.first;
		auto usrlist = m_userlist[container_id];
		for (const auto &user: usrlist) {
			sinsp_evt evt;
			if (user_to_sinsp_event(&user.second, &evt, container_id, PPME_USER_ADDED_E)) {
				int32_t res = scap_dump(m_inspector->m_h, dumper, evt.m_pevt, evt.m_cpuid, 0);
				if (res != SCAP_SUCCESS) {
					throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
				}
			}
		}
	}

	for (const auto &it: m_grouplist) {
		std::string container_id = it.first;
		auto grplist = m_grouplist[container_id];
		for (const auto &group: grplist) {
			sinsp_evt evt;
			if (group_to_sinsp_event(&group.second, &evt, container_id, PPME_GROUP_ADDED_E)) {
				int32_t res = scap_dump(m_inspector->m_h, dumper, evt.m_pevt, evt.m_cpuid, 0);
				if (res != SCAP_SUCCESS) {
					throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
				}
			}
		}
	}
}

void sinsp_usergroup_manager::delete_container_users_groups(const sinsp_container_info &cinfo)
{
	auto usrlist = get_userlist(cinfo.m_id);
	if (usrlist)
	{
		for (auto &u : *usrlist)
		{
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_user_changed(&u.second, cinfo.m_id, false);
		}
	}

	auto grplist = get_grouplist(cinfo.m_id);
	if (grplist)
	{
		for (auto &g : *grplist)
		{
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_group_changed(&g.second, cinfo.m_id, false);
		}
	}

	m_userlist.erase(cinfo.m_id);
	m_grouplist.erase(cinfo.m_id);
}

bool sinsp_usergroup_manager::clear_host_users_groups()
{
	if (!m_import_users)
	{
		return false;
	}

	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts - m_inspector->m_deleted_users_groups_scan_time_ns + 60 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->m_lastevent_ts >
	   m_last_flush_time_ns + m_inspector->m_deleted_users_groups_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		// Clear everything, so that new threadinfos incoming will update
		// user and group informations
		m_userlist[""].clear();
		m_grouplist[""].clear();
	}
	return res;
}

scap_userinfo *sinsp_usergroup_manager::userinfo_map_insert(
	userinfo_map &map,
	uint32_t uid,
	uint32_t gid,
	const char *name,
	const char *home,
	const char *shell)
{
	ASSERT(name);
	ASSERT(home);
	ASSERT(shell);

	auto &usr = map[uid];
	usr.uid = uid;
	usr.gid = gid;
	strlcpy(usr.name, name, MAX_CREDENTIALS_STR_LEN);
	strlcpy(usr.homedir, home, SCAP_MAX_PATH_SIZE);
	strlcpy(usr.shell, shell, SCAP_MAX_PATH_SIZE);

	return &usr;
}

scap_groupinfo *sinsp_usergroup_manager::groupinfo_map_insert(
	groupinfo_map &map,
	uint32_t gid,
	const char *name)
{
	ASSERT(name);

	auto &grp = map[gid];
	grp.gid = gid;
	strlcpy(grp.name, name, MAX_CREDENTIALS_STR_LEN);

	return &grp;
}

scap_userinfo *sinsp_usergroup_manager::add_user(const string &container_id, int64_t pid, uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell, bool notify)
{
	if (!m_import_users)
	{
		m_fallback_user.uid = uid;
		m_fallback_user.gid = gid;
		return &m_fallback_user;
	}

	scap_userinfo *usr = get_user(container_id, uid);
	if(usr)
	{
		// Update user if it was already there
		if (name)
		{
			strlcpy(usr->name, name, MAX_CREDENTIALS_STR_LEN);
			strlcpy(usr->homedir, home, SCAP_MAX_PATH_SIZE);
			strlcpy(usr->shell, shell, SCAP_MAX_PATH_SIZE);
		}
		return usr;
	}

	if (container_id.empty())
	{
		return add_host_user(uid, gid, name, home, shell, notify);
	}
	return add_container_user(container_id, pid, uid, notify);
}

scap_userinfo *sinsp_usergroup_manager::add_host_user(uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding host user: name: %s", name);

	scap_userinfo *retval{nullptr};
	if (name)
	{
		retval = userinfo_map_insert(
			m_userlist[""],
			uid,
			gid,
			name,
			home,
			shell);
	}
	else
	{
#ifdef HAVE_PWD_H
		// On Host, try to load info from db
		auto* p = __getpwuid(uid, m_host_root);
		if (p)
		{
			retval = userinfo_map_insert(
				m_userlist[""],
				p->pw_uid,
				p->pw_gid,
				p->pw_name,
				p->pw_dir,
				p->pw_shell);
		}
#endif
	}

	if (notify && retval)
	{
		notify_user_changed(retval, "");
	}
	return retval;
}

scap_userinfo *sinsp_usergroup_manager::add_container_user(const std::string &container_id, int64_t pid, uint32_t uid, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding container [%s] user %d", container_id.c_str(), uid);

	scap_userinfo *retval{nullptr};

	//
	// When a container is running with a specific user and this
	// get called with 0, it's too early to make an attempt.
	// As a downside we won't load users for containers running as
	// root, but we will load them if e.g.docker exec -u <specific-user>.
	//
	if (uid == 0)
	{
		return retval;
	}

#if defined HAVE_PWD_H && defined HAVE_FGET__ENT

	if(!m_ns_helper->in_own_ns_mnt(pid))
	{
		return retval;
	}

	std::string path = m_ns_helper->get_pid_root(pid) + "/etc/passwd";
	auto pwd_file = fopen(path.c_str(), "r");
	if(pwd_file)
	{
		auto &userlist = m_userlist[container_id];
		while(auto p = fgetpwent(pwd_file))
		{
			// Here we cache all container users
			auto *usr = userinfo_map_insert(
				userlist,
				p->pw_uid,
				p->pw_gid,
				p->pw_name,
				p->pw_dir,
				p->pw_shell);

			if(notify)
			{
				notify_user_changed(usr, container_id);
			}

			if(uid == p->pw_uid)
			{
				retval = usr;
			}
		}
		fclose(pwd_file);
	}
#endif

	return retval;
}

bool sinsp_usergroup_manager::rm_user(const string &container_id, uint32_t uid, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"removing user: container: %s, uid: %d",
			container_id.c_str(), uid);
	bool res = false;
	scap_userinfo *usr = get_user(container_id, uid);
	if (usr)
	{
		if (notify)
		{
			notify_user_changed(usr, container_id, false);
		}
		m_userlist[container_id].erase(uid);
		res = true;
	}
	return res;
}

scap_groupinfo *sinsp_usergroup_manager::add_group(const string &container_id, int64_t pid, uint32_t gid, const char *name, bool notify)
{
	if (!m_import_users)
	{
		m_fallback_grp.gid = gid;
		return &m_fallback_grp;
	}

	scap_groupinfo *gr = get_group(container_id, gid);
	if (gr)
	{
		// Update group if it was already there
		if (name != nullptr)
		{
			strlcpy(gr->name, name, MAX_CREDENTIALS_STR_LEN);
		}
		return gr;
	}

	if (container_id.empty())
	{
		return add_host_group(gid, name, notify);
	}
	return add_container_group(container_id, pid, gid, notify);
}

scap_groupinfo *sinsp_usergroup_manager::add_host_group(uint32_t gid, const char *name, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding host group: name: %s", name);

	scap_groupinfo *gr = nullptr;
	if (name)
	{
		gr = groupinfo_map_insert(m_grouplist[""], gid, name);
	}
	else
	{
#ifdef HAVE_GRP_H
		// On Host, try to load info from db
		auto* g = __getgrgid(gid, m_host_root);
		if (g)
		{
			gr = groupinfo_map_insert(m_grouplist[""], g->gr_gid, g->gr_name);
		}
#endif
	}

	if (notify && gr)
	{
		notify_group_changed(gr, "", true);
	}
	return gr;
}

scap_groupinfo *sinsp_usergroup_manager::add_container_group(const std::string &container_id, int64_t pid, uint32_t gid, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding container [%s] group: %d", container_id.c_str(), gid);

	scap_groupinfo *retval{nullptr};

	//
	// When a container is running with a specific user and this
	// get called with 0, it's too early to make an attempt.
	// As a downside we won't load users for containers running as
	// root, but we will load them if e.g.docker exec -u <specific-user>.
	//
	if(gid == 0)
	{
		return retval;
	}

#if defined HAVE_GRP_H && defined HAVE_FGET__ENT
	if(!m_ns_helper->in_own_ns_mnt(pid))
	{
		return retval;
	}

	std::string path = m_ns_helper->get_pid_root(pid) + "/etc/group";
	auto group_file = fopen(path.c_str(), "r");
	if(group_file)
	{
		auto &grouplist = m_grouplist[container_id];
		while(auto g = fgetgrent(group_file))
		{
			// Here we cache all container groups
			auto *gr = groupinfo_map_insert(grouplist, g->gr_gid, g->gr_name);

			if(notify)
			{
				notify_group_changed(gr, container_id, true);
			}

			if(gid == g->gr_gid)
			{
				retval = gr;
			}
		}
		fclose(group_file);
	}
#endif

	return retval;
}

bool sinsp_usergroup_manager::rm_group(const string &container_id, uint32_t gid, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"removing group: container: %s, gid: %d",
			container_id.c_str(), gid);
	bool res = false;
	scap_groupinfo *gr = get_group(container_id, gid);
	if (gr)
	{
		if (notify)
		{
			notify_group_changed(gr, container_id, false);
		}
		m_grouplist[container_id].erase(gid);
		res = true;
	}
	return res;
}

const unordered_map<uint32_t, scap_userinfo>* sinsp_usergroup_manager::get_userlist(const string &container_id)
{
	if (m_userlist.find(container_id) == m_userlist.end())
	{
		return nullptr;
	}
	return &m_userlist[container_id];
}

scap_userinfo* sinsp_usergroup_manager::get_user(const string &container_id, uint32_t uid)
{
	if (m_userlist.find(container_id) == m_userlist.end())
	{
		return nullptr;
	}

	auto &userlist = m_userlist[container_id];
	auto it = userlist.find(uid);
	if(it == userlist.end())
	{
		return nullptr;
	}
	return &it->second;
}

const unordered_map<uint32_t, scap_groupinfo>* sinsp_usergroup_manager::get_grouplist(const string &container_id)
{
	if (m_grouplist.find(container_id) == m_grouplist.end())
	{
		return nullptr;
	}
	return &m_grouplist[container_id];
}

scap_groupinfo* sinsp_usergroup_manager::get_group(const std::string &container_id, uint32_t gid)
{
	if (m_grouplist.find(container_id) == m_grouplist.end())
	{
		return nullptr;
	}

	auto &grplist = m_grouplist[container_id];
	auto it = grplist.find(gid);
	if(it == grplist.end())
	{
		return nullptr;
	}
	return &it->second;
}

bool sinsp_usergroup_manager::user_to_sinsp_event(const scap_userinfo *user, sinsp_evt* evt, const string &container_id, uint16_t ev_type)
{
	// 6 lens, uid, gid, name, home, shell, container_id
	size_t totlen = sizeof(scap_evt) + 6 * sizeof(uint16_t) +
			sizeof(uint32_t) + sizeof(uint32_t) +
			strlen(user->name) + 1 +
			strlen(user->homedir) + 1 +
			strlen(user->shell) + 1 +
			container_id.length() + 1;

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
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 6;

	auto* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint16_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = sizeof(uint32_t);
	lens[2] = strlen(user->name) + 1;
	lens[3] = strlen(user->homedir) + 1;
	lens[4] = strlen(user->shell) + 1;
	lens[5] = container_id.length() + 1;

	memcpy(valptr, &user->uid, lens[0]);
	valptr += lens[0];
	memcpy(valptr, &user->gid, lens[1]);
	valptr += lens[1];
	memcpy(valptr, user->name, lens[2]);
	valptr += lens[2];
	memcpy(valptr, user->homedir, lens[3]);
	valptr += lens[3];
	memcpy(valptr, user->shell, lens[4]);
	valptr += lens[4];
	memcpy(valptr, container_id.c_str(), lens[5]);

	evt->init();
	return true;
}

bool sinsp_usergroup_manager::group_to_sinsp_event(const scap_groupinfo *group, sinsp_evt* evt, const string &container_id, uint16_t ev_type)
{
	// gid, name, container_id
	size_t totlen = sizeof(scap_evt) + 3 * sizeof(uint16_t) +
			sizeof(uint32_t) +
			strlen(group->name) + 1 +
			container_id.length() + 1;

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
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 3;

	auto* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + scapevt->nparams * sizeof(uint16_t);

	lens[0] = sizeof(uint32_t);
	lens[1] = strlen(group->name) + 1;
	lens[2] = container_id.length() + 1;

	memcpy(valptr, &group->gid, lens[0]);
	valptr += lens[0];
	memcpy(valptr, group->name, lens[1]);
	valptr += lens[1];
	memcpy(valptr, container_id.c_str(), lens[2]);

	evt->init();
	return true;
}

void sinsp_usergroup_manager::notify_user_changed(const scap_userinfo *user, const string &container_id, bool added)
{
	if (!m_inspector->m_inited || !m_import_users)
	{
		return;
	}

	auto *evt = new sinsp_evt();

	if (added)
	{
		user_to_sinsp_event(user, evt, container_id, PPME_USER_ADDED_E);
	}
	else
	{
		user_to_sinsp_event(user, evt, container_id, PPME_USER_DELETED_E);
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_user_changed (%d): USER event, queuing to inspector",
			user->uid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}

void sinsp_usergroup_manager::notify_group_changed(const scap_groupinfo *group, const string &container_id, bool added)
{
	if (!m_inspector->m_inited || !m_import_users)
	{
		return;
	}

	auto *evt = new sinsp_evt();
	if (added)
	{
		group_to_sinsp_event(group, evt, container_id, PPME_GROUP_ADDED_E);
	}
	else
	{
		group_to_sinsp_event(group, evt, container_id, PPME_GROUP_DELETED_E);
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"notify_group_changed (%d): GROUP event, queuing to inspector",
			group->gid);

	std::shared_ptr<sinsp_evt> cevt(evt);

#ifndef _WIN32
	m_inspector->m_pending_state_evts.push(cevt);
#endif
}
