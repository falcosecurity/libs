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

#include <memory>
#include <stdint.h>
#include <list>
#include <libsinsp/sinsp_exception.h>

/* Forward declaration */
class sinsp_threadinfo;

/* Apart from the main thread all other threads when marked as dead should be removed
 * from the thread_table at the next event loop and so become expired. For this reason when we have
 * at least `n` dead threads we can try to clean up expired ones.
 */
#define DEFAULT_DEAD_THREADS_THRESHOLD 11

/* New struct that keep information regarding the thread group */
struct thread_group_info
{
public:
	thread_group_info(int64_t group_pid, bool reaper, std::weak_ptr<sinsp_threadinfo> current_thread):
		m_pid(group_pid), m_reaper(reaper)
	{
		if(current_thread.expired())
		{
			throw sinsp_exception("we cannot create a thread group info from an expired thread");
		}

		/* When we create the thread group info the count is 1, because we only have the creator thread */
		m_alive_count = 1;
		m_threads.push_front(current_thread);
	};

	inline void increment_thread_count() { m_alive_count++; }

	inline void decrement_thread_count()
	{
		m_alive_count--;

		/* Clean expired threads if necessary.
		 * Please note that this is an approximation, `m_threads.size() - m_alive_count` are not the
		 * real expired threads, they are just the ones marked as dead. For example the main thread
		 * of the group is marked as dead but it will be never expired until the thread group exists.
		 */
		if((m_threads.size() - m_alive_count) >= DEFAULT_DEAD_THREADS_THRESHOLD)
		{
			clean_expired_threads();
		}
	}

	inline uint64_t get_thread_count() const { return m_alive_count; }

	inline bool is_reaper() const { return m_reaper; }

	inline void set_reaper(bool reaper) { m_reaper = reaper; }

	inline int64_t get_tgroup_pid() const { return m_pid; }

	inline const std::list<std::weak_ptr<sinsp_threadinfo>>& get_thread_list() const { return m_threads; }

	inline void add_thread_to_group(const std::shared_ptr<sinsp_threadinfo>& thread, bool main)
	{
		/* The main thread should always be the first element of the list, if present.
		 * In this way we can efficiently obtain the main thread.
		 */
		if(main)
		{
			m_threads.push_front(thread);
		}
		else
		{
			m_threads.push_back(thread);
		}
		/* we are adding a thread so we increment the count */
		increment_thread_count();
	}

	inline void clean_expired_threads()
	{
		auto thread = m_threads.begin();
		while(thread != m_threads.end())
		{
			/* This child is expired */
			if(thread->expired())
			{
				/* `erase` returns the pointer to the next child
				 * no need for manual increment.
				 */
				thread = m_threads.erase(thread);
				continue;
			}
			thread++;
		}
	}

	inline sinsp_threadinfo* get_first_thread() const { return m_threads.front().lock().get(); }

private:
	int64_t m_pid; /* unsigned if we want to use `-1` as an invalid value */
	uint64_t m_alive_count;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_threads;
	bool m_reaper;
};
