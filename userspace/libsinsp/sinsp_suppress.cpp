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

#include <cstring>

#include <libsinsp/sinsp_suppress.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/logger.h>
#include <driver/ppm_events_public.h>
#include <libscap/scap_const.h>
#include <libscap/scap_assert.h>

// ---------------------------------------------------------------------------
// Helpers that abstract ConcurrentHashMap vs std::unordered_set differences.
// With LIBSINSP_USE_FOLLY every operation on m_suppressed_tids is lock-free;
// without Folly the caller must hold m_mutex.
// ---------------------------------------------------------------------------

bool libsinsp::sinsp_suppress::find_suppressed_tid(uint64_t tid) const {
	if(tid == 0) {
		return false;
	}
#ifdef LIBSINSP_USE_FOLLY
	return m_suppressed_tids.find(tid) != m_suppressed_tids.cend();
#else
	return m_suppressed_tids.find(tid) != m_suppressed_tids.end();
#endif
}

void libsinsp::sinsp_suppress::insert_suppressed_tid(uint64_t tid) {
#ifdef LIBSINSP_USE_FOLLY
	m_suppressed_tids.insert_or_assign(tid, true);
#else
	m_suppressed_tids.insert(tid);
#endif
}

void libsinsp::sinsp_suppress::erase_suppressed_tid(uint64_t tid) {
	m_suppressed_tids.erase(tid);
}

void libsinsp::sinsp_suppress::clear_suppressed_tids() {
	m_suppressed_tids.clear();
}

size_t libsinsp::sinsp_suppress::suppressed_tids_size() const {
	return m_suppressed_tids.size();
}

// ---------------------------------------------------------------------------
// Configuration (cold path — called before event processing starts)
// ---------------------------------------------------------------------------

void libsinsp::sinsp_suppress::suppress_comm(const std::string &comm) {
#ifdef LIBSINSP_USE_FOLLY
	std::lock_guard lock(m_comms_mutex);
#else
	std::unique_lock lock(m_mutex);
#endif
	m_suppressed_comms.emplace(comm);
	m_active.store(true, std::memory_order_relaxed);
}

void libsinsp::sinsp_suppress::suppress_tid(uint64_t tid) {
#ifdef LIBSINSP_USE_FOLLY
	insert_suppressed_tid(tid);
#else
	std::unique_lock lock(m_mutex);
	m_suppressed_tids.emplace(tid);
#endif
	m_active.store(true, std::memory_order_relaxed);
}

void libsinsp::sinsp_suppress::clear_suppress_comm() {
#ifdef LIBSINSP_USE_FOLLY
	std::lock_guard lock(m_comms_mutex);
#else
	std::unique_lock lock(m_mutex);
#endif
	m_suppressed_comms.clear();
}

void libsinsp::sinsp_suppress::clear_suppress_tid() {
#ifdef LIBSINSP_USE_FOLLY
	clear_suppressed_tids();
#else
	std::unique_lock lock(m_mutex);
	m_suppressed_tids.clear();
#endif
}

// ---------------------------------------------------------------------------
// Proc scan (cold path — called during initialization, single-threaded)
// ---------------------------------------------------------------------------

void libsinsp::sinsp_suppress::initialize() {
#ifdef LIBSINSP_USE_FOLLY
	std::lock_guard lock(m_comms_mutex);
#else
	std::unique_lock lock(m_mutex);
#endif
	if(m_tids_tree == nullptr) {
		m_tids_tree = std::make_unique<std::map<uint64_t, tid_tree_node>>();
	} else {
		m_tids_tree->clear();
	}
}

void libsinsp::sinsp_suppress::handle_thread(uint64_t tid,
                                             uint64_t parent_tid,
                                             const std::string &comm) {
	if(tid == 0) {
		return;
	}

	if(m_tids_tree == nullptr) {
		return;
	}

	(*m_tids_tree)[tid].m_comm = comm;
	(*m_tids_tree)[tid].m_tid = tid;
	(*m_tids_tree)[parent_tid].m_children.push_back(tid);
}

void libsinsp::sinsp_suppress::finalize() {
#ifdef LIBSINSP_USE_FOLLY
	std::lock_guard lock(m_comms_mutex);
#else
	std::unique_lock lock(m_mutex);
#endif

	for(auto it = m_tids_tree->begin(); it != m_tids_tree->end(); it++) {
		auto &[_, node] = *it;

		if(find_suppressed_tid(node.m_tid)) {
			for(auto child_tid : node.m_children) {
				insert_suppressed_tid(child_tid);
			}
		}
	}
	m_tids_tree.reset(nullptr);
}

// ---------------------------------------------------------------------------
// check_suppressed_comm — called during proc scan AND on fork/exec events.
// Checks if the comm matches a suppressed comm and, if so, inserts the tid.
// ---------------------------------------------------------------------------

bool libsinsp::sinsp_suppress::check_suppressed_comm(uint64_t tid,
                                                     uint64_t parent_tid,
                                                     const std::string &comm) {
#ifdef LIBSINSP_USE_FOLLY
	std::lock_guard lock(m_comms_mutex);
#else
	std::unique_lock lock(m_mutex);
#endif
	handle_thread(tid, parent_tid, comm);

	if(m_suppressed_comms.find(comm) != m_suppressed_comms.end()) {
		insert_suppressed_tid(tid);
		m_num_suppressed_events.fetch_add(1, std::memory_order_relaxed);
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// is_suppressed_tid — public query (used by sinsp::check_suppressed)
// ---------------------------------------------------------------------------

bool libsinsp::sinsp_suppress::is_suppressed_tid(uint64_t tid) const {
#ifdef LIBSINSP_USE_FOLLY
	return find_suppressed_tid(tid);
#else
	std::shared_lock lock(m_mutex);
	return find_suppressed_tid(tid);
#endif
}

// ---------------------------------------------------------------------------
// process_event — HOT PATH, called on every event by every worker thread.
// With Folly: completely lock-free.
// Without Folly: falls back to shared_mutex (existing behavior + atomic fast-path).
// ---------------------------------------------------------------------------

int32_t libsinsp::sinsp_suppress::process_event(scap_evt *e) {
	if(!m_active.load(std::memory_order_relaxed)) {
		return SCAP_SUCCESS;
	}

	uint64_t tid;
	memcpy(&tid, &e->tid, sizeof(uint64_t));

	switch(e->type) {
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
	case PPME_SYSCALL_CLONE3_X: {
		uint32_t j;
		const char *comm = nullptr;
		char *ptid_ptr = nullptr;

		auto *lens = (uint16_t *)((char *)e + sizeof(ppm_evt_hdr));
		char *valptr = (char *)lens + e->nparams * sizeof(uint16_t);
		uint16_t scratch = 0;

		ASSERT(e->nparams >= 14);
		if(e->nparams < 14) {
			return SCAP_SUCCESS;
		}

		for(j = 0; j < 13; j++) {
			if(j == 5) {
				ptid_ptr = valptr;
			}

			memcpy(&scratch, &lens[j], sizeof(uint16_t));
			valptr += scratch;
		}

		ASSERT(ptid_ptr != nullptr);
		if(ptid_ptr == nullptr) {
			return SCAP_SUCCESS;
		}

		comm = valptr;

		uint64_t ptid;
		memcpy(&ptid, ptid_ptr, sizeof(uint64_t));

#ifdef LIBSINSP_USE_FOLLY
		if(find_suppressed_tid(ptid)) {
			insert_suppressed_tid(tid);
			m_num_suppressed_events.fetch_add(1, std::memory_order_relaxed);
			return SCAP_FILTERED_EVENT;
		}
#else
		{
			std::unique_lock lock(m_mutex);
			if(find_suppressed_tid(ptid)) {
				m_suppressed_tids.insert(tid);
				m_num_suppressed_events.fetch_add(1, std::memory_order_relaxed);
				return SCAP_FILTERED_EVENT;
			}
		}
#endif

		if(check_suppressed_comm(tid, ptid, comm)) {
			return SCAP_FILTERED_EVENT;
		}

		return SCAP_SUCCESS;
	}
	case PPME_PROCEXIT_1_E: {
#ifdef LIBSINSP_USE_FOLLY
		erase_suppressed_tid(tid);
#else
		std::unique_lock lock(m_mutex);
		if(auto it = m_suppressed_tids.find(tid); it != m_suppressed_tids.cend()) {
			m_suppressed_tids.erase(it);
		}
#endif
		return SCAP_SUCCESS;
	}

	default: {
#ifdef LIBSINSP_USE_FOLLY
		if(find_suppressed_tid(tid)) {
			m_num_suppressed_events.fetch_add(1, std::memory_order_relaxed);
			return SCAP_FILTERED_EVENT;
		}
		return SCAP_SUCCESS;
#else
		std::shared_lock lock(m_mutex);
		if(find_suppressed_tid(tid)) {
			m_num_suppressed_events.fetch_add(1, std::memory_order_relaxed);
			return SCAP_FILTERED_EVENT;
		}
		return SCAP_SUCCESS;
#endif
	}
	}
}
