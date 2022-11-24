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
#include "../common/strlcpy.h"
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
struct passwd *sinsp_usergroup_manager::__getpwuid(uint32_t uid)
{
	if(m_host_root.empty())
	{
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		return getpwuid(uid);
	}

	// If we have a host root and we can use fgetpwent,
	// we take the entry directly from file
#ifdef HAVE_FGET__ENT
	static std::string filename(m_host_root + "/etc/passwd");

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
struct group *sinsp_usergroup_manager::__getgrgid(uint32_t gid)
{
	if(m_host_root.empty())
	{
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		return getgrgid(gid);
	}

	// If we have a host root and we can use fgetgrent,
	// we take the entry directly from file
#ifdef HAVE_FGET__ENT
	static std::string filename(m_host_root + "/etc/group");

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
#if defined(HAVE_PWD_H) || defined(HAVE_GRP_H)
	, m_host_root(m_inspector->get_host_root())
	, m_ns_helper(new libsinsp::procfs_utils::ns_helper(m_host_root))
#endif
{
}
// clang-format on

void sinsp_usergroup_manager::subscribe_container_mgr()
{
	if (m_import_users)
	{
		// Emplace container manager listener to delete container users upon container deletion
		m_inspector->m_container_manager.subscribe_on_remove_container([&](const sinsp_container_info &cinfo) -> void {
			delete_container_users_groups(cinfo);
		});

		m_inspector->m_container_manager.subscribe_on_new_container([&](const sinsp_container_info&cinfo, sinsp_threadinfo *tinfo) -> void {
		        load_from_container(cinfo.m_id, cinfo.m_overlayfs_root);
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

scap_userinfo *sinsp_usergroup_manager::add_user(const string &container_id, uint32_t uid, uint32_t gid, const char *name, const char *home, const char *shell, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding user: container: %s, name: %s",
			container_id.c_str(), name);

	if (!m_import_users)
	{
		return nullptr;
	}

	scap_userinfo *usr = get_user(container_id, uid);
	if (!usr)
	{
		bool inserted{false};
		if (name)
		{
			usr = userinfo_map_insert(
				m_userlist[container_id],
				uid,
				gid,
				name,
				home,
				shell);
			inserted = true;
		}
		else if (container_id.empty())
		{
#ifdef HAVE_PWD_H
			// On Host, try to load info from db
			auto* p = __getpwuid(uid);
			if (p)
			{
				usr = userinfo_map_insert(
					m_userlist[container_id],
					p->pw_uid,
					p->pw_gid,
					p->pw_name,
					p->pw_dir,
					p->pw_shell);
				inserted = true;
			}
#endif
		}

		if (notify && inserted)
		{
			notify_user_changed(usr, container_id);
		}
	}
	else if (name != NULL)
	{
		// Update user if it was already there
		strlcpy(usr->name, name, MAX_CREDENTIALS_STR_LEN);
		strlcpy(usr->homedir, home, SCAP_MAX_PATH_SIZE);
		strlcpy(usr->shell, shell, SCAP_MAX_PATH_SIZE);
	}
	return usr;
}

scap_userinfo *sinsp_usergroup_manager::add_container_user(const std::string &container_id, int64_t pid, uint32_t uid, bool notify)
{
	ASSERT(!container_id.empty());
	ASSERT(uid != 0);

	auto userlist_it = m_userlist.find(container_id);
	if(userlist_it != m_userlist.end())
	{
		// userlist for this container exists
		auto it = userlist_it->second.find(uid);
		// not an expected condition to miss, but handle it anyway
		return (it == userlist_it->second.end())
			       ? nullptr
			       : &it->second;
	}

	scap_userinfo *retval{nullptr};

#if defined HAVE_PWD_H && defined HAVE_FGET__ENT

	if(false == m_ns_helper->in_own_ns_mnt(pid))
	{
		return nullptr;
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

scap_groupinfo *sinsp_usergroup_manager::add_group(const string &container_id, uint32_t gid, const char *name, bool notify)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"adding group: container: %s, name: %s",
			container_id.c_str(), name);
	if (!m_import_users)
	{
		return nullptr;
	}

	scap_groupinfo *gr = get_group(container_id, gid);
	if (!gr)
	{
		bool inserted{false};
		if (name)
		{
			gr = groupinfo_map_insert(m_grouplist[container_id], gid, name);
			inserted = true;
		}
		else if (container_id.empty())
		{
#ifdef HAVE_GRP_H
			// On Host, try to load info from db
			auto* g = __getgrgid(gid);
			if (g)
			{
				gr = groupinfo_map_insert(m_grouplist[container_id], g->gr_gid, g->gr_name);
				inserted = true;
			}
#endif
		}

		if (notify && inserted)
		{
			notify_group_changed(gr, container_id, true);
		}
	}
	else if (name != NULL)
	{
		// Update group if it was already there
		strlcpy(gr->name, name, MAX_CREDENTIALS_STR_LEN);

	}
	return gr;
}

scap_groupinfo *sinsp_usergroup_manager::add_container_group(const std::string &container_id, int64_t pid, uint32_t gid, bool notify)
{
	ASSERT(!container_id.empty());
	ASSERT(gid != 0);

	auto grouplist_it = m_grouplist.find(container_id);
	if(grouplist_it != m_grouplist.end())
	{
		// grouplist for this container exists
		auto it = grouplist_it->second.find(gid);
		// not an expected condition to miss, but handle it anyway
		return (it == grouplist_it->second.end())
			       ? nullptr
			       : &it->second;
	}

	scap_groupinfo *retval{nullptr};

#if defined HAVE_GRP_H && defined HAVE_FGET__ENT

	if(false == m_ns_helper->in_own_ns_mnt(pid))
	{
		return nullptr;
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
	if(uid == 0xffffffff)
	{
		return nullptr;
	}

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
	if(gid == 0xffffffff)
	{
		return nullptr;
	}

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

void sinsp_usergroup_manager::load_from_container(const std::string &container_id, const std::string &overlayfs_root)
{
	if (!m_import_users)
	{
		return;
	}

	if (overlayfs_root.empty())
	{
		// Avoid loading from host
		return;
	}

	if(m_userlist.find(container_id) != m_userlist.end())
	{
		// userlist for this container already exists
		return;
	}

#if defined HAVE_PWD_H && defined HAVE_FGET__ENT
	auto passwd_in_container = overlayfs_root + "/etc/passwd";
	auto pwd_file = fopen(passwd_in_container.c_str(), "r");
	if(pwd_file)
	{
		while(auto p = fgetpwent(pwd_file))
		{
			add_user(container_id, p->pw_uid, p->pw_gid, p->pw_name, p->pw_dir, p->pw_shell, true);
		}
		fclose(pwd_file);
	}
#endif

#if defined HAVE_GRP_H && defined HAVE_FGET__ENT
	auto group_in_container = overlayfs_root + "/etc/group";
	auto grp_file = fopen(group_in_container.c_str(), "r");
	if(grp_file)
	{
		while(auto g = fgetgrent(grp_file))
		{
			add_group(container_id, g->gr_gid, g->gr_name, true);
		}
		fclose(grp_file);
	}
#endif
}
