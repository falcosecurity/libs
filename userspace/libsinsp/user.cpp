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

#include <libsinsp/user.h>
#include <libsinsp/procfs_utils.h>
#include <libsinsp/utils.h>
#include <libsinsp/logger.h>
#include <libsinsp/sinsp.h>
#include <libscap/strl.h>
#include <sys/types.h>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

namespace {

// Splits `line` into up to `max` colon-separated fields, storing each into
// `out` (which must have room for at least `max` entries). Returns the number
// of fields found; the final field captures the remainder of the line,
// including any further colons.
//
// We parse /etc/passwd and /etc/group ourselves instead of relying on
// fgetpwent_r()/fgetgrent_r(): those require the *entire* line to fit in a
// fixed-size buffer and return ERANGE otherwise. A group with a large member
// list can exceed any such buffer, and the previous "continue on error" loops
// then spun forever, re-reading the same oversized line without ever advancing
// or reaching EOF. We only need the leading fixed fields (name, uid/gid), so
// reading whole lines with std::getline and parsing the prefix sidesteps the
// overflow entirely.
size_t split_fields(std::string_view line, std::string_view *out, size_t max) {
	size_t n = 0;
	size_t start = 0;
	while(n < max) {
		size_t pos = line.find(':', start);
		if(pos == std::string_view::npos) {
			out[n++] = line.substr(start);
			break;
		}
		out[n++] = line.substr(start, pos - start);
		start = pos + 1;
	}
	return n;
}

// Parses `s` as a base-10 uint32_t, requiring the *entire* field to be a valid
// number. Returns false (without touching `out`) on empty input, non-numeric
// characters, trailing garbage, or overflow. This matters because getpwent/
// getgrent-style files are untrusted: a malformed id field must be rejected,
// not silently coerced to 0 (which would alias to root's uid/gid).
bool parse_uint32(std::string_view s, uint32_t &out) {
	const char *begin = s.data();
	const char *end = s.data() + s.size();
	auto res = std::from_chars(begin, end, out);
	return res.ec == std::errc{} && res.ptr == end;
}

}  // namespace

#ifdef HAVE_PWD_H
static struct passwd *__getpwuid(uint32_t uid,
                                 const std::string &host_root,
                                 struct passwd *pwd,
                                 char *buf,
                                 size_t buflen) {
	if(uid == (uint32_t)-1) {
		return nullptr;
	}
	if(host_root.empty()) {
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		struct passwd *result = nullptr;
		if(getpwuid_r(uid, pwd, buf, buflen, &result) == 0) {
			return result;
		}
		return nullptr;
	}

	// With a host root set, read /etc/passwd directly. We parse each line
	// ourselves (rather than fgetpwent_r) so an over-long line cannot overflow
	// the fixed-size buffer; see split_fields().
	std::ifstream f(host_root + "/etc/passwd");
	std::string line;
	while(std::getline(f, line)) {
		// name:passwd:uid:gid:gecos:home:shell
		std::string_view fields[7];
		if(split_fields(line, fields, 7) < 7) {
			continue;  // skip malformed lines
		}
		uint32_t entry_uid;
		uint32_t entry_gid;
		if(!parse_uint32(fields[2], entry_uid) || !parse_uint32(fields[3], entry_gid)) {
			continue;  // skip lines with a non-numeric uid/gid
		}
		if(uid != entry_uid) {
			continue;
		}
		// `line` does not outlive this call, so copy the fields we keep into
		// the caller-owned buffer and point the result at them.
		char *w = buf;
		char *bufend = buf + buflen;
		auto stash = [&](std::string_view s) -> char * {
			if(w + s.size() + 1 > bufend) {
				return nullptr;
			}
			char *dst = w;
			memcpy(w, s.data(), s.size());
			w += s.size();
			*w++ = '\0';
			return dst;
		};
		char *name = stash(fields[0]);
		char *home = stash(fields[5]);
		char *shell = stash(fields[6]);
		if(!name || !home || !shell) {
			continue;  // does not fit (not expected for these fields)
		}
		pwd->pw_name = name;
		pwd->pw_uid = entry_uid;
		pwd->pw_gid = entry_gid;
		pwd->pw_dir = home;
		pwd->pw_shell = shell;
		return pwd;
	}
	return nullptr;
}
#endif

#ifdef HAVE_GRP_H
static struct group *__getgrgid(uint32_t gid,
                                const std::string &host_root,
                                struct group *grp,
                                char *buf,
                                size_t buflen) {
	if(gid == (uint32_t)-1) {
		return nullptr;
	}
	if(host_root.empty()) {
		// When we don't have any host root set,
		// leverage NSS (see man nsswitch.conf)
		struct group *result = nullptr;
		if(getgrgid_r(gid, grp, buf, buflen, &result) == 0) {
			return result;
		}
		return nullptr;
	}

	// With a host root set, read /etc/group directly. We parse each line
	// ourselves (rather than fgetgrent_r) so a large member list cannot
	// overflow the fixed-size buffer; see split_fields().
	std::ifstream f(host_root + "/etc/group");
	std::string line;
	while(std::getline(f, line)) {
		// name:passwd:gid:members
		std::string_view fields[3];
		if(split_fields(line, fields, 3) < 3) {
			continue;  // skip malformed lines
		}
		uint32_t entry_gid;
		if(!parse_uint32(fields[2], entry_gid)) {
			continue;  // skip lines with a non-numeric gid
		}
		if(gid != entry_gid) {
			continue;
		}
		// `line` does not outlive this call, so copy the name we keep into the
		// caller-owned buffer and point the result at it.
		std::string_view name = fields[0];
		if(name.size() + 1 > buflen) {
			return nullptr;
		}
		memcpy(buf, name.data(), name.size());
		buf[name.size()] = '\0';
		grp->gr_name = buf;
		grp->gr_gid = gid;
		grp->gr_mem = nullptr;
		return grp;
	}
	return nullptr;
}
#endif

using namespace std;

static inline std::string_view sv_or_empty(const char *s) {
	return s ? std::string_view(s) : std::string_view{};
}

// clang-format off
sinsp_usergroup_manager::sinsp_usergroup_manager(sinsp* inspector, const timestamper& timestamper)
	: m_import_users(true)
	, m_inspector(inspector)
	, m_timestamper {timestamper}
	, m_host_root(m_inspector->get_host_root())
#if defined(__linux__) && (defined(HAVE_PWD_H) || defined(HAVE_GRP_H))
	, m_ns_helper(std::make_unique<libsinsp::procfs_utils::ns_helper>(m_host_root))
#else
	, m_ns_helper(nullptr)
#endif
{
	strlcpy(m_fallback_user.name, "<NA>", sizeof(m_fallback_user.name));
	strlcpy(m_fallback_user.homedir, "<NA>", sizeof(m_fallback_user.homedir));
	strlcpy(m_fallback_user.shell, "<NA>", sizeof(m_fallback_user.shell));
	strlcpy(m_fallback_grp.name, "<NA>", sizeof(m_fallback_grp.name));
}
// clang-format on

void sinsp_usergroup_manager::dump_users_groups(sinsp_dumper &dumper) {
	for(const auto &it : m_userlist) {
		std::string container_id = it.first;
		const auto &usrlist = m_userlist[container_id];
		for(const auto &user : usrlist) {
			sinsp_evt evt;
			if(user_to_sinsp_event(&user.second, &evt, container_id, PPME_USER_ADDED_E)) {
				evt.get_scap_evt()->ts = m_timestamper.get_new_ts();
				dumper.dump(&evt);
			}
		}
	}

	for(const auto &it : m_grouplist) {
		std::string container_id = it.first;
		const auto &grplist = m_grouplist[container_id];
		for(const auto &group : grplist) {
			sinsp_evt evt;
			if(group_to_sinsp_event(&group.second, &evt, container_id, PPME_GROUP_ADDED_E)) {
				evt.get_scap_evt()->ts = m_timestamper.get_new_ts();
				dumper.dump(&evt);
			}
		}
	}
}

void sinsp_usergroup_manager::delete_container(const std::string &container_id) {
	if(auto usrlist = get_userlist(container_id)) {
		for(auto &u : *usrlist) {
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_user_changed(&u.second, container_id, false);
		}
	}

	if(auto grplist = get_grouplist(container_id)) {
		for(auto &g : *grplist) {
			// We do not have a thread id here, as a removed container
			// means that it has no tIDs anymore.
			notify_group_changed(&g.second, container_id, false);
		}
	}

	m_userlist.erase(container_id);
	m_grouplist.erase(container_id);
}

scap_userinfo *sinsp_usergroup_manager::userinfo_map_insert(userinfo_map &map,
                                                            uint32_t uid,
                                                            uint32_t gid,
                                                            std::string_view name,
                                                            std::string_view home,
                                                            std::string_view shell) {
	auto &usr = map[uid];
	usr.uid = uid;
	usr.gid = gid;
	// In case the node is configured to use NIS,
	// some struct passwd* fields may be set to NULL.
	strlcpy(usr.name,
	        (name.data() != nullptr) ? std::string(name).c_str() : "<NA>",
	        MAX_CREDENTIALS_STR_LEN);
	strlcpy(usr.homedir,
	        (home.data() != nullptr) ? std::string(home).c_str() : "<NA>",
	        SCAP_MAX_PATH_SIZE);
	strlcpy(usr.shell,
	        (shell.data() != nullptr) ? std::string(shell).c_str() : "<NA>",
	        SCAP_MAX_PATH_SIZE);

	return &usr;
}

scap_groupinfo *sinsp_usergroup_manager::groupinfo_map_insert(groupinfo_map &map,
                                                              uint32_t gid,
                                                              std::string_view name) {
	auto &grp = map[gid];
	grp.gid = gid;
	strlcpy(grp.name,
	        (name.data() != nullptr) ? std::string(name).c_str() : "<NA>",
	        MAX_CREDENTIALS_STR_LEN);

	return &grp;
}

scap_userinfo *sinsp_usergroup_manager::add_user(const std::string &container_id,
                                                 int64_t pid,
                                                 uint32_t uid,
                                                 uint32_t gid,
                                                 std::string_view name,
                                                 std::string_view home,
                                                 std::string_view shell,
                                                 bool notify) {
	// ignore NSS entries
	if(!name.empty() && (name[0] == '+' || name[0] == '-')) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "NSS user ignored: %.*s",
		                          static_cast<int>(name.length()),
		                          name.data());
		return nullptr;
	}

	if(!m_import_users) {
		m_fallback_user.uid = uid;
		m_fallback_user.gid = gid;
		return &m_fallback_user;
	}

	scap_userinfo *usr = get_user(container_id, uid);
	if(usr) {
		// Update user if it was already there
		if(name.data() != nullptr) {
			strlcpy(usr->name, std::string(name).c_str(), MAX_CREDENTIALS_STR_LEN);
			strlcpy(usr->homedir, std::string(home).c_str(), SCAP_MAX_PATH_SIZE);
			strlcpy(usr->shell, std::string(shell).c_str(), SCAP_MAX_PATH_SIZE);
		}
		return usr;
	}

	if(container_id.empty()) {
		return add_host_user(uid, gid, name, home, shell, notify);
	}
	return add_container_user(container_id, pid, uid, notify);
}

scap_groupinfo *sinsp_usergroup_manager::add_group(const std::string &container_id,
                                                   int64_t pid,
                                                   uint32_t gid,
                                                   bool notify) {
	if(gid == (uint32_t)-1) {
		return nullptr;
	}
	if(auto gr = get_group(container_id, gid); gr != nullptr) {
		return gr;
	}

	if(gid == 0) {
		return add_group(container_id, pid, gid, "root", notify);
	} else {
		return add_group(container_id, pid, gid, {}, notify);
	}
}

scap_userinfo *sinsp_usergroup_manager::add_host_user(uint32_t uid,
                                                      uint32_t gid,
                                                      std::string_view name,
                                                      std::string_view home,
                                                      std::string_view shell,
                                                      bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "adding host user: name: %.*s",
	                          static_cast<int>(name.length()),
	                          name.data());

	scap_userinfo *retval{nullptr};
	if(name.data() != nullptr) {
		retval = userinfo_map_insert(m_userlist[""], uid, gid, name, home, shell);
	} else {
#ifdef HAVE_PWD_H
		// On Host, try to load info from db
		struct passwd pwd_entry;
		char pwd_buf[4096];
		auto *p = __getpwuid(uid, m_host_root, &pwd_entry, pwd_buf, sizeof(pwd_buf));
		if(p) {
			retval = userinfo_map_insert(m_userlist[""],
			                             p->pw_uid,
			                             p->pw_gid,
			                             sv_or_empty(p->pw_name),
			                             sv_or_empty(p->pw_dir),
			                             sv_or_empty(p->pw_shell));
		}
#endif
	}

	if(notify && retval) {
		notify_user_changed(retval, "");
	}
	return retval;
}

scap_userinfo *sinsp_usergroup_manager::add_container_user(const std::string &container_id,
                                                           int64_t pid,
                                                           uint32_t uid,
                                                           bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "adding container [%s] user %d",
	                          container_id.c_str(),
	                          uid);

	scap_userinfo *retval{nullptr};

#if defined(__linux__) && defined HAVE_PWD_H
	if(!m_ns_helper->in_own_ns_mnt(pid)) {
		return retval;
	}

	std::string path = m_ns_helper->get_pid_root(pid) + "/etc/passwd";
	std::ifstream pwd_file(path);
	if(pwd_file) {
		auto &userlist = m_userlist[container_id];
		std::string line;
		while(std::getline(pwd_file, line)) {
			// name:passwd:uid:gid:gecos:home:shell
			std::string_view fields[7];
			if(split_fields(line, fields, 7) < 7) {
				continue;  // skip malformed lines
			}
			uint32_t u_uid;
			uint32_t u_gid;
			if(!parse_uint32(fields[2], u_uid) || !parse_uint32(fields[3], u_gid)) {
				continue;  // skip lines with a non-numeric uid/gid
			}
			// Here we cache all container users. Compare against whatever
			// was previously cached for this uid (if anything) *before*
			// the insert overwrites it in place, so we can tell a
			// genuinely new entry or a changed one (e.g. a rename) apart
			// from a no-op rescan of an already-known, unchanged entry.
			const auto existing_it = userlist.find(u_uid);
			const scap_userinfo *previous =
			        existing_it != userlist.end() ? &existing_it->second : nullptr;
			const bool changed = !previous || previous->gid != u_gid ||
			                     fields[0] != previous->name || fields[5] != previous->homedir ||
			                     fields[6] != previous->shell;

			auto *usr =
			        userinfo_map_insert(userlist, u_uid, u_gid, fields[0], fields[5], fields[6]);

			if(notify && changed) {
				notify_user_changed(usr, container_id);
			}

			if(uid == u_uid) {
				retval = usr;
			}
		}
	}
#endif

	return retval;
}

bool sinsp_usergroup_manager::rm_user(const string &container_id, uint32_t uid, bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "removing user: container: %s, uid: %d",
	                          container_id.c_str(),
	                          uid);
	bool res = false;
	scap_userinfo *usr = get_user(container_id, uid);
	if(usr) {
		if(notify) {
			notify_user_changed(usr, container_id, false);
		}
		m_userlist[container_id].erase(uid);
		res = true;
	}
	return res;
}

scap_groupinfo *sinsp_usergroup_manager::add_group(const string &container_id,
                                                   int64_t pid,
                                                   uint32_t gid,
                                                   std::string_view name,
                                                   bool notify) {
	// ignore NSS entries
	if(!name.empty() && (name[0] == '+' || name[0] == '-')) {
		libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
		                          "NSS group ignored: %.*s",
		                          static_cast<int>(name.length()),
		                          name.data());
		return nullptr;
	}

	if(!m_import_users) {
		m_fallback_grp.gid = gid;
		return &m_fallback_grp;
	}

	scap_groupinfo *gr = get_group(container_id, gid);
	if(gr) {
		// Update group if it was already there
		if(name.data() != nullptr) {
			strlcpy(gr->name, std::string(name).c_str(), MAX_CREDENTIALS_STR_LEN);
		}
		return gr;
	}

	if(container_id.empty()) {
		return add_host_group(gid, name, notify);
	}
	return add_container_group(container_id, pid, gid, notify);
}

scap_groupinfo *sinsp_usergroup_manager::add_host_group(uint32_t gid,
                                                        std::string_view name,
                                                        bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "adding host group: name: %.*s",
	                          static_cast<int>(name.length()),
	                          name.data());

	scap_groupinfo *gr = nullptr;
	if(name.data()) {
		gr = groupinfo_map_insert(m_grouplist[""], gid, name);
	} else {
#ifdef HAVE_GRP_H
		// On Host, try to load info from db
		struct group grp_entry;
		char grp_buf[4096];
		auto *g = __getgrgid(gid, m_host_root, &grp_entry, grp_buf, sizeof(grp_buf));
		if(g) {
			gr = groupinfo_map_insert(m_grouplist[""], g->gr_gid, sv_or_empty(g->gr_name));
		}
#endif
	}

	if(notify && gr) {
		notify_group_changed(gr, "", true);
	}
	return gr;
}

scap_groupinfo *sinsp_usergroup_manager::add_container_group(const std::string &container_id,
                                                             int64_t pid,
                                                             uint32_t gid,
                                                             bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "adding container [%s] group: %d",
	                          container_id.c_str(),
	                          gid);

	scap_groupinfo *retval{nullptr};

#if defined(__linux__) && defined HAVE_GRP_H
	if(!m_ns_helper->in_own_ns_mnt(pid)) {
		return retval;
	}

	std::string path = m_ns_helper->get_pid_root(pid) + "/etc/group";
	std::ifstream group_file(path);
	if(group_file) {
		auto &grouplist = m_grouplist[container_id];
		std::string line;
		while(std::getline(group_file, line)) {
			// name:passwd:gid:members
			std::string_view fields[3];
			if(split_fields(line, fields, 3) < 3) {
				continue;  // skip malformed lines
			}
			uint32_t g_gid;
			if(!parse_uint32(fields[2], g_gid)) {
				continue;  // skip lines with a non-numeric gid
			}
			// Here we cache all container groups. Compare against whatever
			// was previously cached for this gid (if anything) *before*
			// the insert overwrites it in place, so we can tell a
			// genuinely new entry or a changed one (e.g. a rename) apart
			// from a no-op rescan of an already-known, unchanged entry.
			const auto existing_it = grouplist.find(g_gid);
			const scap_groupinfo *previous =
			        existing_it != grouplist.end() ? &existing_it->second : nullptr;
			const bool changed = !previous || fields[0] != previous->name;

			auto *gr = groupinfo_map_insert(grouplist, g_gid, fields[0]);

			if(notify && changed) {
				notify_group_changed(gr, container_id, true);
			}

			if(gid == g_gid) {
				retval = gr;
			}
		}
	}
#endif

	return retval;
}

bool sinsp_usergroup_manager::rm_group(const string &container_id, uint32_t gid, bool notify) {
	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "removing group: container: %s, gid: %d",
	                          container_id.c_str(),
	                          gid);
	bool res = false;
	scap_groupinfo *gr = get_group(container_id, gid);
	if(gr) {
		if(notify) {
			notify_group_changed(gr, container_id, false);
		}
		m_grouplist[container_id].erase(gid);
		res = true;
	}
	return res;
}

const unordered_map<uint32_t, scap_userinfo> *sinsp_usergroup_manager::get_userlist(
        const string &container_id) {
	if(m_userlist.find(container_id) == m_userlist.end()) {
		return nullptr;
	}
	return &m_userlist[container_id];
}

scap_userinfo *sinsp_usergroup_manager::get_user(const string &container_id, uint32_t uid) {
	if(m_userlist.find(container_id) == m_userlist.end()) {
		return nullptr;
	}

	auto &userlist = m_userlist[container_id];
	auto it = userlist.find(uid);
	if(it == userlist.end()) {
		return nullptr;
	}
	return &it->second;
}

const unordered_map<uint32_t, scap_groupinfo> *sinsp_usergroup_manager::get_grouplist(
        const string &container_id) {
	if(m_grouplist.find(container_id) == m_grouplist.end()) {
		return nullptr;
	}
	return &m_grouplist[container_id];
}

scap_groupinfo *sinsp_usergroup_manager::get_group(const std::string &container_id, uint32_t gid) {
	if(m_grouplist.find(container_id) == m_grouplist.end()) {
		return nullptr;
	}

	auto &grplist = m_grouplist[container_id];
	auto it = grplist.find(gid);
	if(it == grplist.end()) {
		return nullptr;
	}
	return &it->second;
}

scap_userinfo *sinsp_usergroup_manager::add_user(const std::string &container_id,
                                                 int64_t pid,
                                                 uint32_t uid,
                                                 uint32_t gid,
                                                 bool notify) {
	if(uid == (uint32_t)-1) {
		return nullptr;
	}
	if(auto usr = get_user(container_id, uid); usr != nullptr) {
		return usr;
	}

	if(uid == 0) {
		return add_user(container_id, pid, uid, gid, "root", "/root", {}, notify);
	} else {
		return add_user(container_id, pid, uid, gid, {}, {}, {}, notify);
	}
}

bool sinsp_usergroup_manager::user_to_sinsp_event(const scap_userinfo *user,
                                                  sinsp_evt *evt,
                                                  const string &container_id,
                                                  uint16_t ev_type) {
	// 6 lens, uid, gid, name, home, shell, container_id
	size_t totlen = sizeof(scap_evt) + 6 * sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t) +
	                strlen(user->name) + 1 + strlen(user->homedir) + 1 + strlen(user->shell) + 1 +
	                container_id.length() + 1;

	ASSERT(evt->get_scap_evt_storage() == nullptr);
	evt->set_scap_evt_storage(new char[totlen]);
	evt->set_scap_evt((scap_evt *)evt->get_scap_evt_storage());

	evt->set_cpuid(0);
	evt->set_num(0);
	evt->set_inspector(m_inspector);

	scap_evt *scapevt = evt->get_scap_evt();

	scapevt->ts = (uint64_t)-1;
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 6;

	auto *lens = (uint16_t *)((char *)scapevt + sizeof(ppm_evt_hdr));
	char *valptr = (char *)lens + scapevt->nparams * sizeof(uint16_t);

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

bool sinsp_usergroup_manager::group_to_sinsp_event(const scap_groupinfo *group,
                                                   sinsp_evt *evt,
                                                   const string &container_id,
                                                   uint16_t ev_type) {
	// gid, name, container_id
	size_t totlen = sizeof(scap_evt) + 3 * sizeof(uint16_t) + sizeof(uint32_t) +
	                strlen(group->name) + 1 + container_id.length() + 1;

	ASSERT(evt->get_scap_evt_storage() == nullptr);
	evt->set_scap_evt_storage(new char[totlen]);
	evt->set_scap_evt((scap_evt *)evt->get_scap_evt_storage());

	evt->set_cpuid(0);
	evt->set_num(0);
	evt->set_inspector(m_inspector);

	scap_evt *scapevt = evt->get_scap_evt();

	scapevt->ts = (uint64_t)-1;
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = ev_type;
	scapevt->nparams = 3;

	auto *lens = (uint16_t *)((char *)scapevt + sizeof(ppm_evt_hdr));
	char *valptr = (char *)lens + scapevt->nparams * sizeof(uint16_t);

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

void sinsp_usergroup_manager::notify_user_changed(const scap_userinfo *user,
                                                  const string &container_id,
                                                  bool added) {
	if(!m_inspector->m_inited || !m_import_users) {
		return;
	}

	std::unique_ptr<sinsp_evt> evt(new sinsp_evt());

	if(added) {
		user_to_sinsp_event(user, evt.get(), container_id, PPME_USER_ADDED_E);
	} else {
		user_to_sinsp_event(user, evt.get(), container_id, PPME_USER_DELETED_E);
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "notify_user_changed (%d): USER event, queuing to inspector",
	                          user->uid);

	m_inspector->handle_async_event(std::move(evt));
}

void sinsp_usergroup_manager::notify_group_changed(const scap_groupinfo *group,
                                                   const string &container_id,
                                                   bool added) {
	if(!m_inspector->m_inited || !m_import_users) {
		return;
	}

	std::unique_ptr<sinsp_evt> evt(new sinsp_evt());
	if(added) {
		group_to_sinsp_event(group, evt.get(), container_id, PPME_GROUP_ADDED_E);
	} else {
		group_to_sinsp_event(group, evt.get(), container_id, PPME_GROUP_DELETED_E);
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
	                          "notify_group_changed (%d): GROUP event, queuing to inspector",
	                          group->gid);

	m_inspector->handle_async_event(std::move(evt));
}
