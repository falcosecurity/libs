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
class sinsp_fdtable : public libsinsp::state::built_in_table<int64_t> {
public:
	typedef std::function<bool(int64_t, sinsp_fdinfo&)> fdtable_visitor_t;

	typedef std::function<bool(int64_t, const sinsp_fdinfo&)> fdtable_const_visitor_t;

	sinsp_fdtable(const sinsp_mode& mode,
	              uint32_t max_table_size,
	              const sinsp_fdinfo_factory& fdinfo_factory,
	              const std::shared_ptr<const sinsp_plugin>& input_plugin,
	              const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
	              scap_platform* const& scap_platform);

	sinsp_fdinfo* find(int64_t fd);

	sinsp_fdinfo* add(int64_t fd, std::shared_ptr<sinsp_fdinfo>&& fdinfo);

	inline bool const_loop(const fdtable_const_visitor_t callback) const {
		for(auto it = m_table.begin(); it != m_table.end(); ++it) {
			if(!callback(it->first, *it->second)) {
				return false;
			}
		}
		return true;
	}

	inline bool loop(const fdtable_visitor_t callback) {
		for(auto it = m_table.begin(); it != m_table.end(); ++it) {
			if(!callback(it->first, *it->second)) {
				return false;
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
	std::unordered_map<int64_t, std::shared_ptr<sinsp_fdinfo>> m_table;

	// The following fields are externally provided and access to them is expected to be read-only.
	const sinsp_mode& m_sinsp_mode;
	const uint32_t m_max_table_size;
	const sinsp_fdinfo_factory m_fdinfo_factory;
	const std::shared_ptr<const sinsp_plugin>& m_input_plugin;

	// The following fields are externally provided and expected to be populated/updated by the
	// fdtable.
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;

	//
	// Simple fd cache
	//
	int64_t m_last_accessed_fd;
	std::shared_ptr<sinsp_fdinfo> m_last_accessed_fdinfo;
	uint64_t m_tid;
	std::shared_ptr<sinsp_fdinfo> m_nullptr_ret;  // needed for returning a reference

	bool is_syscall_plugin_enabled() const {
		return m_sinsp_mode.is_plugin() && m_input_plugin->id() == 0;
	}

	inline void lookup_device(sinsp_fdinfo& fdi) const;
	const std::shared_ptr<sinsp_fdinfo>& find_ref(int64_t fd);
	const std::shared_ptr<sinsp_fdinfo>& add_ref(int64_t fd,
	                                             std::shared_ptr<sinsp_fdinfo>&& fdinfo);
};
