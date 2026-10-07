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

#include <functional>
#include <memory>
#include <stdint.h>
#include <list>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/sinsp_public.h>

/* Forward declaration */
class sinsp_threadinfo;

/* Apart from the main thread all other threads when marked as dead should be removed
 * from the thread_table at the next event loop and so become expired. For this reason when we have
 * at least `n` dead threads we can try to clean up expired ones.
 */
#define DEFAULT_DEAD_THREADS_THRESHOLD 11

/* New struct that keep information regarding the thread group */
struct thread_group_info {
public:
	/* An entry of the thread list of the group. The thread table owns the threads, so borrow()
	 * returns a thread without taking a reference. The pointer is valid until the table erases
	 * the thread.
	 */
	class thread_ref {
	public:
		thread_ref(const std::shared_ptr<sinsp_threadinfo>& thread):
		        m_weak(thread),
		        m_raw(thread.get()) {}
		thread_ref(const std::weak_ptr<sinsp_threadinfo>& thread):
		        m_weak(thread),
		        m_raw(thread.lock().get()) {}

		inline bool expired() const { return m_weak.expired(); }
		inline std::shared_ptr<sinsp_threadinfo> lock() const { return m_weak.lock(); }
		inline sinsp_threadinfo* borrow() const { return m_weak.expired() ? nullptr : m_raw; }

	private:
		std::weak_ptr<sinsp_threadinfo> m_weak;
		sinsp_threadinfo* m_raw;
	};

	thread_group_info(int64_t group_pid,
	                  bool reaper,
	                  std::weak_ptr<sinsp_threadinfo> current_thread):
	        m_pid(group_pid),
	        m_reaper(reaper) {
		if(current_thread.expired()) {
			throw sinsp_exception("we cannot create a thread group info from an expired thread");
		}

		/* When we create the thread group info the count is 1, because we only have the creator
		 * thread */
		m_alive_count = 1;
		m_threads.push_front(current_thread);
	};

	inline void increment_thread_count() { m_alive_count++; }

	inline void decrement_thread_count() {
		m_alive_count--;

		/* Clean expired threads if necessary.
		 * Please note that this is an approximation, `m_threads.size() - m_alive_count` are not the
		 * real expired threads, they are just the ones marked as dead. For example the main thread
		 * of the group is marked as dead but it will be never expired until the thread group
		 * exists.
		 */
		if((m_threads.size() - m_alive_count) >= DEFAULT_DEAD_THREADS_THRESHOLD) {
			clean_expired_threads();
		}
	}

	inline uint64_t get_thread_count() const { return m_alive_count; }

	inline bool is_reaper() const { return m_reaper; }

	inline void set_reaper(bool reaper) { m_reaper = reaper; }

	inline int64_t get_tgroup_pid() const { return m_pid; }

	inline const std::list<thread_ref>& get_thread_list() const { return m_threads; }

	inline void add_thread_to_group(const std::shared_ptr<sinsp_threadinfo>& thread, bool main) {
		/* The main thread should always be the first element of the list, if present.
		 * In this way we can efficiently obtain the main thread.
		 */
		if(main) {
			m_threads.push_front(thread);
		} else {
			m_threads.push_back(thread);
		}
		/* we are adding a thread so we increment the count */
		increment_thread_count();
	}

	inline void clean_expired_threads() {
		auto thread = m_threads.begin();
		while(thread != m_threads.end()) {
			/* This child is expired */
			if(thread->expired()) {
				/* `erase` returns the pointer to the next child
				 * no need for manual increment.
				 */
				thread = m_threads.erase(thread);
				continue;
			}
			thread++;
		}
	}

	inline sinsp_threadinfo* get_first_thread() const { return m_threads.front().borrow(); }

	/* The parent process is the group of the thread that forked, and the tid of that thread.
	 * Only the child side of the link is stored. The parent keeps no list of children.
	 *
	 * The writer resolves the link when it writes it, and readers only follow it. A null link
	 * with a tid is a parent that we do not link to.
	 *
	 * Every link goes down in rank, so the links never form a cycle. The rank of a group is set
	 * before anything can link to the group, and it never changes. The rank is the rank of the
	 * parent plus one, 0 without a parent, and s_unknown_parent_rank when the parent is unknown.
	 * A link to a group of the same rank or higher is refused. Thus, the test of a link needs
	 * only the two groups.
	 */
	static constexpr uint64_t s_unknown_parent_rank = uint64_t{1} << 62;

	/* Link a group that nothing links to yet, and set its rank. If the rank of the parent is
	 * pending (also when the parent is this group), the link is refused. Then the function keeps
	 * the tid and returns false.
	 */
	inline bool link_new(std::shared_ptr<thread_group_info> parent, int64_t parent_tid) {
		if(parent != nullptr && parent->m_rank != s_pending_rank) {
			m_rank = parent->m_rank + 1;
			m_parent = std::move(parent);
			m_parent_tid = parent_tid;
			return true;
		}
		m_rank = parent_tid > 0 ? s_unknown_parent_rank : 0;
		m_parent = nullptr;
		m_parent_tid = parent_tid;
		return parent == nullptr;
	}

	/* Use this for a group that is published before it is linked, because the /proc scan creates
	 * its parent first. Nothing can link to the group until link_new() sets its rank.
	 */
	inline void set_rank_pending() { m_rank = s_pending_rank; }

	/* Link to `parent` unless that link goes up in rank. A refused link stores nothing. */
	inline bool relink(std::shared_ptr<thread_group_info> parent, int64_t parent_tid) {
		if(parent->m_rank >= m_rank) {
			return false;
		}
		m_parent = std::move(parent);
		m_parent_tid = parent_tid;
		return true;
	}

	/* Drop the link to the group of the parent, but keep the parent tid. */
	inline void unlink(int64_t parent_tid) {
		m_parent = nullptr;
		m_parent_tid = parent_tid;
	}

	inline uint64_t get_rank() const { return m_rank; }

	inline const std::shared_ptr<thread_group_info>& get_parent() const { return m_parent; }

	inline int64_t get_parent_tid() const { return m_parent_tid; }

	/* True if the chain of parent links ends (has no cycle). For asserts and tests only. */
	inline bool chain_ends() const {
		const thread_group_info* slow = this;
		const thread_group_info* fast = this;
		while(fast != nullptr && fast->m_parent != nullptr) {
			slow = slow->m_parent.get();
			fast = fast->m_parent->m_parent.get();
			if(slow == fast) {
				return false;
			}
		}
		return true;
	}

	/* A dead group is a tombstone (a group that stays after its process is gone). It leaves the
	 * group table with its last thread, and it lives while a child links to it. If the reaper is
	 * known, it replaces the parent link. If not, readers search above the tombstone.
	 */
	inline void set_dead(bool in_pid_namespace) {
		m_dead = true;
		m_in_pid_namespace = in_pid_namespace;
		m_threads.clear();
	}

	/* For a dead group: link to its reaper, unless that link goes up in rank. */
	inline bool link_reaper(std::shared_ptr<thread_group_info> reaper, int64_t reaper_tid) {
		if(reaper->m_rank >= m_rank) {
			return false;
		}
		m_parent = std::move(reaper);
		m_parent_tid = reaper_tid;
		m_reaper_known = true;
		return true;
	}

	inline bool is_dead() const { return m_dead; }

	/* For a dead group: true if the parent link names its reaper. */
	inline bool is_reaper_known() const { return m_reaper_known; }

	/* For a dead group: true if its last thread was in a child pid namespace. */
	inline bool is_in_pid_namespace() const { return m_in_pid_namespace; }

	/* Link straight to `parent`, where the dead parent `seen` leads. The tombstones in between
	 * are freed when nothing links to them. If the link is no longer `seen`, nothing is stored,
	 * so a relink in between wins.
	 */
	inline void skip_dead_parent(const thread_group_info* seen,
	                             std::shared_ptr<thread_group_info> parent,
	                             int64_t parent_tid) {
		ASSERT(parent->m_rank < m_rank);
		before_shortcut_store();
		if(m_parent.get() != seen) {
			return;
		}
		m_parent = std::move(parent);
		m_parent_tid = parent_tid;
	}

#ifdef _DEBUG
	/* Tests only: called between the walk and the store of a shortcut. */
	static inline std::function<void()> s_before_shortcut_store;
#endif

private:
	int64_t m_pid; /* unsigned if we want to use `-1` as an invalid value */
	uint64_t m_alive_count;
	std::list<thread_ref> m_threads;
	std::shared_ptr<thread_group_info> m_parent;
	int64_t m_parent_tid = 0;
	uint64_t m_rank = s_unknown_parent_rank;
	bool m_reaper;
	bool m_dead = false;
	bool m_reaper_known = false;
	bool m_in_pid_namespace = false;

	inline void before_shortcut_store() const {
#ifdef _DEBUG
		if(s_before_shortcut_store) {
			s_before_shortcut_store();
		}
#endif
	}

	static constexpr uint64_t s_pending_rank = UINT64_MAX;
};
