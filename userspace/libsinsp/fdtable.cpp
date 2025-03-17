// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#ifndef _WIN32
#include <algorithm>
#endif
#include <libsinsp/fdtable.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>

static const auto s_fdtable_static_fields = sinsp_fdinfo::get_static_fields();

sinsp_fdtable::sinsp_fdtable(const sinsp_mode& sinsp_mode,
                             const uint32_t max_table_size,
                             const sinsp_fdinfo_factory& fdinfo_factory,
                             const std::shared_ptr<const sinsp_plugin>& input_plugin,
                             const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
                             scap_platform* const* scap_platform):
        built_in_table{"file_descriptors", &s_fdtable_static_fields},
        m_sinsp_mode{sinsp_mode},
        m_max_table_size{max_table_size},
        m_fdinfo_factory{fdinfo_factory},
        m_input_plugin{input_plugin},
        m_sinsp_stats_v2{sinsp_stats_v2},
        m_scap_platform{scap_platform},
        m_tid{0} {
	reset_cache();
}

inline const std::shared_ptr<sinsp_fdinfo>& sinsp_fdtable::find_ref(int64_t fd) {
	//
	// Try looking up in our simple cache
	//
	if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd) {
		if(m_sinsp_stats_v2) {
			m_sinsp_stats_v2->m_n_cached_fd_lookups++;
		}
		return m_last_accessed_fdinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	auto fdit = m_table.find(fd);

	if(fdit == m_table.end()) {
		if(m_sinsp_stats_v2) {
			m_sinsp_stats_v2->m_n_failed_fd_lookups++;
		}
		return m_nullptr_ret;
	} else {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
		}

		m_last_accessed_fd = fd;
		m_last_accessed_fdinfo = fdit->second;
		lookup_device(*m_last_accessed_fdinfo);
		return m_last_accessed_fdinfo;
	}
}

inline const std::shared_ptr<sinsp_fdinfo>& sinsp_fdtable::add_ref(
        int64_t fd,
        std::shared_ptr<sinsp_fdinfo>&& fdinfo) {
	if(fdinfo->dynamic_fields() != dynamic_fields()) {
		throw sinsp_exception("adding entry with incompatible dynamic defs to fd table");
	}

	fdinfo->m_fd = fd;

	//
	// Look for the FD in the table
	//
	auto it = m_table.find(fd);

	// Three possible exits here:
	// 1. fd is not on the table
	//   a. the table size is under the limit so create a new entry
	//   b. table size is over the limit, discard the fd
	// 2. fd is already in the table, replace it
	if(it == m_table.end()) {
		if(m_table.size() < m_max_table_size) {
			//
			// No entry in the table, this is the normal case
			//
			m_last_accessed_fd = -1;
			if(m_sinsp_stats_v2 != nullptr) {
				m_sinsp_stats_v2->m_n_added_fds++;
			}

			return m_table.emplace(fd, std::move(fdinfo)).first->second;
		} else {
			return m_nullptr_ret;
		}
	} else {
		//
		// the fd is already in the table.
		//
		if(it->second->m_flags & sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS) {
			//
			// Sometimes an FD-creating syscall can be called on an FD that is being closed (i.e
			// the close enter has arrived but the close exit has not arrived yet).
			// If this is the case, mark the new entry so that the successive close exit won't
			// destroy it.
			//
			fdinfo->m_flags &= ~sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS;
			fdinfo->m_flags |= sinsp_fdinfo::FLAGS_CLOSE_CANCELED;

			m_table[CANCELED_FD_NUMBER] = it->second->clone();
		} else {
			//
			// This can happen if:
			//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened
			//  with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going
			// is a reasonable choice. We include an assertion to catch the situation.
			//
			// XXX Can't have this enabled until the FD_CLOEXEC flag is supported
			// ASSERT(false);
		}

		//
		// Replace the fd as a struct copy
		//
		m_last_accessed_fd = -1;
		it->second = std::move(fdinfo);
		return it->second;
	}
}

bool sinsp_fdtable::erase(int64_t fd) {
	auto fdit = m_table.find(fd);

	if(fd == m_last_accessed_fd) {
		m_last_accessed_fd = -1;
	}

	if(fdit == m_table.end()) {
		//
		// Looks like there's no fd to remove.
		// Either the fd creation event was dropped or (more likely) our logic doesn't support the
		// call that created this fd. The assertion will detect it, while in release mode we just
		// keep going.
		//
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_failed_fd_lookups++;
		}
		return false;
	} else {
		m_table.erase(fdit);
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
			m_sinsp_stats_v2->m_n_removed_fds++;
		}
		return true;
	}
}

void sinsp_fdtable::clear() {
	m_table.clear();
}

size_t sinsp_fdtable::size() const {
	return m_table.size();
}

void sinsp_fdtable::reset_cache() {
	m_last_accessed_fd = -1;
}

void sinsp_fdtable::lookup_device(sinsp_fdinfo& fdi) const {
#ifndef _WIN32
	if(m_sinsp_mode.is_offline() || (m_sinsp_mode.is_plugin() && !is_syscall_plugin_enabled())) {
		return;
	}

	if(m_tid != 0 && m_tid != static_cast<uint64_t>(-1) && fdi.is_file() && fdi.m_dev == 0 &&
	   fdi.m_mount_id != 0) {
		char procdir[SCAP_MAX_PATH_SIZE];
		snprintf(procdir, sizeof(procdir), "%s/proc/%ld/", scap_get_host_root(), m_tid);
		fdi.m_dev = scap_get_device_by_mount_id(get_scap_platform(), procdir, fdi.m_mount_id);
		fdi.m_mount_id = 0;  // don't try again
	}
#endif  // _WIN32
}

sinsp_fdinfo* sinsp_fdtable::find(const int64_t fd) {
	return find_ref(fd).get();
}

sinsp_fdinfo* sinsp_fdtable::add(const int64_t fd, std::shared_ptr<sinsp_fdinfo>&& fdinfo) {
	return add_ref(fd, std::move(fdinfo)).get();
}

std::unique_ptr<libsinsp::state::table_entry> sinsp_fdtable::new_entry() const {
	return m_fdinfo_factory.create();
};

std::shared_ptr<libsinsp::state::table_entry> sinsp_fdtable::get_entry(const int64_t& key) {
	return find_ref(key);
}
