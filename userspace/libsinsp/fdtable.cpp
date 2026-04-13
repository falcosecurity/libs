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
#include <cinttypes>

#include <libsinsp/fdtable.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>

static const auto s_fdtable_static_fields = sinsp_fdinfo::get_static_fields();

template<typename SyncPolicy>
sinsp_fdtable_impl<SyncPolicy>::sinsp_fdtable_impl(const std::shared_ptr<ctor_params>& params):
        extensible_table{"file_descriptors", &s_fdtable_static_fields},
        m_params{params},
#ifndef LIBSINSP_USE_FOLLY
        m_last_accessed_fd{-1},
#endif
        m_tid{0} {
}

template<typename SyncPolicy>
inline std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::find_ref(int64_t fd) {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		auto& c = tl_cache();
		if(c.table == this && c.fd == fd) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_cached_fd_lookups();
			}
			return c.fdinfo;
		}

		auto fdit = m_table.find(fd);
		if(fdit == m_table.end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}

		c.table = this;
		c.fd = fd;
		c.fdinfo = fdit->second;
		return c.fdinfo;
#endif
	} else {
		std::shared_lock lock(m_mutex);

		auto fdit = m_table.find(fd);
		if(fdit == m_table.end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}

		return fdit->second;
	}
}

template<typename SyncPolicy>
inline std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::add_ref(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo) {
	std::unique_lock lock(m_mutex);

	if(fdinfo->dynamic_fields() != dynamic_fields()) {
		throw sinsp_exception("adding entry with incompatible dynamic defs to fd table");
	}

	fdinfo->m_fd = fd;
	lookup_device(*fdinfo);

	const uint32_t max_size = m_params ? m_params->m_max_table_size : 0xFFFFFFFFU;

	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		if(m_table.size() >= max_size) {
			auto it = m_table.find(fd);
			if(it == m_table.end()) {
				return nullptr;
			}
		}

		invalidate_tl_cache();

		auto [it, inserted] = m_table.insert_or_assign(fd, std::move(fdinfo));
		if(inserted && m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_added_fds();
		}
		return it->second;
#endif
	} else {
		const auto it = m_table.find(fd);

		if(it == m_table.end()) {
			if(m_table.size() == max_size) {
				return nullptr;
			}

#ifndef LIBSINSP_USE_FOLLY
			m_last_accessed_fd = -1;
#endif
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_added_fds();
			}

			auto& ref = m_table.emplace(fd, std::move(fdinfo)).first->second;
			return ref;
		}

#ifndef LIBSINSP_USE_FOLLY
		m_last_accessed_fd = -1;
#endif
		it->second = std::move(fdinfo);
		return it->second;
	}
}

template<typename SyncPolicy>
bool sinsp_fdtable_impl<SyncPolicy>::erase(int64_t fd) {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();

		auto erased = m_table.erase(fd);
		if(erased == 0) {
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return false;
		}
		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			auto& c = m_params->m_sinsp_stats_v2->get_thread_counters();
			c.inc_n_noncached_fd_lookups();
			c.inc_n_removed_fds();
		}
		return true;
#endif
	} else {
		std::unique_lock lock(m_mutex);
#ifndef LIBSINSP_USE_FOLLY
		if(fd == m_last_accessed_fd) {
			m_last_accessed_fd = -1;
		}
#endif

		auto fdit = m_table.find(fd);

		if(fdit == m_table.end()) {
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return false;
		} else {
			m_table.erase(fdit);
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				auto& c = m_params->m_sinsp_stats_v2->get_thread_counters();
				c.inc_n_noncached_fd_lookups();
				c.inc_n_removed_fds();
			}
			return true;
		}
	}
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::clear() {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();
#endif
	} else {
		std::unique_lock lock(m_mutex);
#ifndef LIBSINSP_USE_FOLLY
		m_last_accessed_fd = -1;
#endif
	}
	m_table.clear();
}

template<typename SyncPolicy>
size_t sinsp_fdtable_impl<SyncPolicy>::size() const {
	std::shared_lock lock(m_mutex);
	return m_table.size();
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::reset_cache() {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();
#endif
	} else {
#ifndef LIBSINSP_USE_FOLLY
		m_last_accessed_fd = -1;
#endif
	}
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::lookup_device(fdinfo_t& fdi) const {
#ifndef _WIN32
	if(!m_params) {
		return;
	}
	if(m_params->m_sinsp_mode.is_offline() ||
	   (m_params->m_sinsp_mode.is_plugin() && !is_syscall_plugin_enabled())) {
		return;
	}

	if(m_tid != 0 && m_tid != static_cast<uint64_t>(-1) && fdi.is_file() && fdi.m_dev == 0 &&
	   fdi.m_mount_id != 0) {
		char procdir[SCAP_MAX_PATH_SIZE];
		snprintf(procdir, sizeof(procdir), "%s/proc/%" PRIu64 "/", scap_get_host_root(), m_tid);
		fdi.m_dev = scap_get_device_by_mount_id(m_params->m_scap_platform, procdir, fdi.m_mount_id);
		fdi.m_mount_id = 0;  // don't try again
	}
#endif  // _WIN32
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::find(const int64_t fd) {
	return find_ref(fd);
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::add(const int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo) {
	return add_ref(fd, std::move(fdinfo));
}

template<typename SyncPolicy>
std::unique_ptr<libsinsp::state::table_entry> sinsp_fdtable_impl<SyncPolicy>::new_entry() const {
	return m_params ? m_params->m_fdinfo_factory.create() : nullptr;
};

template<typename SyncPolicy>
std::shared_ptr<libsinsp::state::table_entry> sinsp_fdtable_impl<SyncPolicy>::get_entry(
        const int64_t& key) {
	return find_ref(key);
}

template class sinsp_fdtable_impl<sync_policy_default>;
