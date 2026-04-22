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

#pragma once

#include <type_traits>
#include <libsinsp/state/table.h>
#include <libsinsp/fdinfo.h>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_mode.h>

#ifdef LIBSINSP_USE_FOLLY
#include <folly/concurrency/ConcurrentHashMap.h>
#endif

// Forward declare sinsp_stats_v2 to avoid including metrics_collector.h here.
class sinsp_stats_v2;

struct sinsp_fdtable_ctor_params {
	// The following fields are externally provided and access to them is expected to be
	// read-only.
	const sinsp_mode& m_sinsp_mode;
	const uint32_t m_max_table_size;
	const sinsp_fdinfo_factory m_fdinfo_factory;
	const std::shared_ptr<const sinsp_plugin> m_input_plugin;

	// The following fields are externally provided and expected to be populated/updated by the
	// fdtable.
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;
};

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
template<typename SyncPolicy = sync_policy_default>
class sinsp_fdtable_impl : public libsinsp::state::extensible_table<int64_t> {
public:
	using traits = libsinsp::sync_policy_traits<SyncPolicy>;
	using fdinfo_t = sinsp_fdinfo_impl<SyncPolicy>;
	using ctor_params = sinsp_fdtable_ctor_params;
	typedef std::function<bool(int64_t, fdinfo_t&)> fdtable_visitor_t;
	typedef std::function<bool(int64_t, const fdinfo_t&)> fdtable_const_visitor_t;

	explicit sinsp_fdtable_impl(const std::shared_ptr<ctor_params>& params);

	std::shared_ptr<fdinfo_t> find(int64_t fd);

	std::shared_ptr<fdinfo_t> add(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo);

	inline bool const_loop(const fdtable_const_visitor_t callback) const {
		if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
			for(auto it = m_table.cbegin(); it != m_table.cend(); ++it) {
				std::shared_ptr<fdinfo_t> pin = it->second;
				if(!pin) {
					continue;
				}
				if(!callback(it->first, *pin)) {
					return false;
				}
			}
#endif
		} else {
			std::shared_lock lock(m_mutex);
			for(auto it = m_table.begin(); it != m_table.end(); ++it) {
				if(!callback(it->first, *it->second)) {
					return false;
				}
			}
		}
		return true;
	}

	inline bool loop(const fdtable_visitor_t callback) {
		if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
			for(auto it = m_table.begin(); it != m_table.end(); ++it) {
				std::shared_ptr<fdinfo_t> pin = it->second;
				if(!pin) {
					continue;
				}
				if(!callback(it->first, *pin)) {
					return false;
				}
			}
#endif
		} else {
			std::shared_lock lock(m_mutex);
			for(auto it = m_table.begin(); it != m_table.end(); ++it) {
				if(!callback(it->first, *it->second)) {
					return false;
				}
			}
		}
		return true;
	}

	// If the key is present, returns true, otherwise returns false.
	bool erase(int64_t fd);

	void clear();

	size_t size() const;

	void reset_cache();

	inline uint64_t get_tid() const { return m_tid; }

	inline void set_tid(uint64_t v) { m_tid = v; }

	// ---- libsinsp::state::table implementation ----

	size_t entries_count() const override { return size(); }

	void clear_entries() override { clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override;

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		return loop([&pred](int64_t i, fdinfo_t& e) { return pred(e); });
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const int64_t& key) override;

	std::shared_ptr<libsinsp::state::table_entry> add_entry(
	        const int64_t& key,
	        std::unique_ptr<libsinsp::state::table_entry> entry) override {
		if(!entry) {
			throw sinsp_exception("null entry added to fd table");
		}
		auto fdinfo = dynamic_cast<fdinfo_t*>(entry.get());
		if(!fdinfo) {
			throw sinsp_exception("unknown entry type added to fd table");
		}
		entry.release();

		return add_ref(key, std::unique_ptr<fdinfo_t>(fdinfo));
	}

	bool erase_entry(const int64_t& key) override { return erase(key); }

	// Lock order: when both fdtable (m_mutex) and fdinfo (sinsp_fdinfo::m_mutex) are needed,
	// always take fdtable first, then fdinfo. Violating this can cause lock-order inversion
	// and deadlock (see set_net_role_by_guessing in fdinfo.cpp).
	mutable typename traits::fdtable_outer_mutex m_mutex;

private:
	// Parameters provided at fdtable construction phase.
	// Notice: the struct instance is shared among all fdtable instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

#ifdef LIBSINSP_USE_FOLLY
	using folly_map_t = folly::ConcurrentHashMap<int64_t, std::shared_ptr<fdinfo_t>>;
#endif
	using std_map_t = std::unordered_map<int64_t, std::shared_ptr<fdinfo_t>>;

	using map_type = std::conditional_t<traits::k_use_folly_chm,
#ifdef LIBSINSP_USE_FOLLY
	                                    folly_map_t,
#else
	                                    std_map_t,
#endif
	                                    std_map_t>;

	map_type m_table;

#ifdef LIBSINSP_USE_FOLLY
	struct fd_cache_entry {
		const sinsp_fdtable_impl* table{nullptr};
		int64_t fd{-1};
		std::shared_ptr<fdinfo_t> fdinfo;
	};

	static fd_cache_entry& tl_cache() {
		static thread_local fd_cache_entry entry;
		return entry;
	}

	inline void invalidate_tl_cache() {
		auto& c = tl_cache();
		if(c.table == this) {
			c.fd = -1;
			c.fdinfo.reset();
		}
	}
#endif

#ifndef LIBSINSP_USE_FOLLY
	int64_t m_last_accessed_fd;
	std::shared_ptr<fdinfo_t> m_last_accessed_fdinfo;
#endif
	uint64_t m_tid;

	bool is_syscall_plugin_enabled() const {
		return m_params && m_params->m_sinsp_mode.is_plugin() && m_params->m_input_plugin &&
		       m_params->m_input_plugin->id() == 0;
	}

	inline void lookup_device(fdinfo_t& fdi) const;
	std::shared_ptr<fdinfo_t> find_ref(int64_t fd);
	std::shared_ptr<fdinfo_t> add_ref(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo);
};

using sinsp_fdtable = sinsp_fdtable_impl<>;
