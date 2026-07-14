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

#include <libsinsp/state/table.h>
#include <libsinsp/fdinfo.h>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_mode.h>

// Forward declare sinsp_stats_v2 to avoid including metrics_collector.h here.
struct sinsp_stats_v2;

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
class sinsp_fdtable : public libsinsp::state::extensible_table<int64_t> {
public:
	typedef std::function<bool(int64_t, sinsp_fdinfo&)> fdtable_visitor_t;

	typedef std::function<bool(int64_t, const sinsp_fdinfo&)> fdtable_const_visitor_t;

	/*!
	  \brief Container holding parameters to be provided to sinsp_fdtable constructor.
	  An instance of this struct is meant to be shared among all sinsp_fdtable instances.
	*/
	struct ctor_params {
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

	explicit sinsp_fdtable(const std::shared_ptr<ctor_params>& params);

	// Read-only lookup: the returned entry must not be modified, as it may be
	// shared with other fd tables.
	const sinsp_fdinfo* find(int64_t fd) const;

	// Lookup for modification: the single chokepoint through which every
	// mutable entry is handed out.
	sinsp_fdinfo* find_mut(int64_t fd);

	sinsp_fdinfo* add(int64_t fd, std::shared_ptr<sinsp_fdinfo>&& fdinfo);

	// Shares table contents with `other` (typically the parent process's
	// table at fork). Both tables then see the same entries; the first
	// content modification through either table detaches a private copy
	// (copy-on-write), leaving the other sharers untouched.
	void share_from(const sinsp_fdtable& other);

	// True if the contents are currently shared with at least one other fd
	// table.
	bool is_shared() const { return m_table.use_count() > 1; }

	// Identity of the current contents: tables sharing contents report the
	// same value, letting accountants count shared contents once.
	const void* contents_id() const { return m_table.get(); }

	inline bool const_loop(const fdtable_const_visitor_t callback) const {
		for(auto it = m_table->begin(); it != m_table->end(); ++it) {
			if(!callback(it->first, *it->second)) {
				return false;
			}
		}
		return true;
	}

	inline bool loop(const fdtable_visitor_t callback) {
		if(m_table->empty()) {
			// Nothing to visit; in particular, don't detach shared contents
			// (proc-scan fixups run on freshly created, still-empty tables).
			return true;
		}
		detach_if_shared();
		for(auto it = m_table->begin(); it != m_table->end(); ++it) {
			if(!callback(it->first, *it->second)) {
				return false;
			}
		}
		return true;
	}

	void retain(const fdtable_const_visitor_t& callback) {
		if(m_table->empty()) {
			return;
		}
		if(is_shared()) {
			// Build the private copy directly from the survivors instead of
			// detaching everything first: the fork→execve path retains only
			// the non-CLOEXEC subset of the entries.
			auto retained = std::make_shared<table_t>();
			for(const auto& [fd, info] : *m_table) {
				if(callback(fd, *info)) {
					retained->emplace(fd, info->clone());
				}
			}
			m_table = std::move(retained);
			reset_cache();
			return;
		}
		for(auto it = m_table->begin(); it != m_table->end();) {
			if(!callback(it->first, *it->second)) {
				// Invalidate the cache if we are removing the cached fd, otherwise a
				// later lookup would return a dangling reference to the removed entry
				// (the same hazard erase() guards against).
				if(it->first == m_last_accessed_fd) {
					reset_cache();
				}
				it = m_table->erase(it);
			} else {
				++it;
			}
		}
	}

	// If the key is present, returns true, otherwise returns false.
	bool erase(int64_t fd);

	void clear();

	size_t size() const;

	void reset_cache() const;

	inline uint64_t get_tid() const { return m_tid; }

	inline void set_tid(uint64_t v) { m_tid = v; }

	// ---- libsinsp::state::table implementation ----

	size_t entries_count() const override { return size(); }

	void clear_entries() override { clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override;

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		return loop([&pred](int64_t i, sinsp_fdinfo& e) { return pred(e); });
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const int64_t& key) override;

	std::shared_ptr<libsinsp::state::table_entry> add_entry(
	        const int64_t& key,
	        std::unique_ptr<libsinsp::state::table_entry> entry) override {
		if(!entry) {
			throw sinsp_exception("null entry added to fd table");
		}
		auto fdinfo = dynamic_cast<sinsp_fdinfo*>(entry.get());
		if(!fdinfo) {
			throw sinsp_exception("unknown entry type added to fd table");
		}
		entry.release();

		return add_ref(key, std::unique_ptr<sinsp_fdinfo>(fdinfo));
	}

	bool erase_entry(const int64_t& key) override { return erase(key); }

private:
	// Parameters provided at fdtable construction phase.
	// Notice: the struct instance is shared among all fdtable instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

	using table_t = std::unordered_map<int64_t, std::shared_ptr<sinsp_fdinfo>>;

	// The table contents. Held through a shared_ptr so that the fd tables of
	// related processes can share them; a shared map is never modified in
	// place (see detach_if_shared()).
	std::shared_ptr<table_t> m_table;

	//
	// Simple fd cache. This is per-owner memoization, not table content:
	// it stays mutable so that read-only lookups on a const table can
	// still maintain it.
	//
	mutable int64_t m_last_accessed_fd;
	mutable std::shared_ptr<sinsp_fdinfo> m_last_accessed_fdinfo;
	uint64_t m_tid;
	std::shared_ptr<sinsp_fdinfo> m_nullptr_ret;  // needed for returning a reference

	bool is_syscall_plugin_enabled() const {
		return m_params->m_sinsp_mode.is_plugin() && m_params->m_input_plugin->id() == 0;
	}

	// The shared immutable empty contents that every fd table starts out
	// referencing: threads that never own fds (all non-main threads) pay no
	// allocation. The first modification detaches a private map like any
	// other write to shared contents.
	static const std::shared_ptr<table_t>& empty_contents();

	// Gives this table private contents before an in-place modification.
	// Returns true if a detach actually took place (invalidating iterators
	// and entry pointers previously obtained from this table).
	bool detach_if_shared();

	inline void lookup_device(sinsp_fdinfo& fdi) const;
	const std::shared_ptr<sinsp_fdinfo>& find_ref(int64_t fd) const;
	const std::shared_ptr<sinsp_fdinfo>& add_ref(int64_t fd,
	                                             std::shared_ptr<sinsp_fdinfo>&& fdinfo);
};
