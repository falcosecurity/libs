// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef LIBSINSP_USE_FOLLY
#include <folly/concurrency/ConcurrentHashMap.h>
#else
#include <shared_mutex>
#endif

typedef struct ppm_evt_hdr scap_evt;

namespace libsinsp {

class sinsp_suppress {
public:
	sinsp_suppress() = default;

	void suppress_comm(const std::string& comm);

	void suppress_tid(uint64_t tid);

	void clear_suppress_comm();

	void clear_suppress_tid();

	bool check_suppressed_comm(uint64_t tid, uint64_t parent_tid, const std::string& comm);

	int32_t process_event(scap_evt* e);

	bool is_suppressed_tid(uint64_t tid) const;

	uint64_t get_num_suppressed_events() const {
		return m_num_suppressed_events.load(std::memory_order_relaxed);
	}

	uint64_t get_num_suppressed_tids() const { return suppressed_tids_size(); }

	void initialize();

	void finalize();

protected:
	std::atomic<bool> m_active{false};
	std::atomic<uint64_t> m_num_suppressed_events{0};

#ifdef LIBSINSP_USE_FOLLY
	folly::ConcurrentHashMap<uint64_t, bool> m_suppressed_tids;
	mutable std::mutex m_comms_mutex;
#else
	mutable std::shared_mutex m_mutex;
	std::unordered_set<uint64_t> m_suppressed_tids;
#endif
	std::unordered_set<std::string> m_suppressed_comms;

	bool find_suppressed_tid(uint64_t tid) const;
	void insert_suppressed_tid(uint64_t tid);
	void erase_suppressed_tid(uint64_t tid);
	void clear_suppressed_tids();
	size_t suppressed_tids_size() const;

private:
	struct tid_tree_node {
		uint64_t m_tid;
		std::string m_comm;
		std::vector<uint64_t> m_children;
	};

	void handle_thread(uint64_t tid, uint64_t parent_tid, const std::string& comm);

	std::unique_ptr<std::map<uint64_t, tid_tree_node>> m_tids_tree;
};

}  // namespace libsinsp
