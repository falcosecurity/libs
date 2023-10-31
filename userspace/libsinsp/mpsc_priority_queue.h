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

#include <mutex>
#include <atomic>
#include <queue>
#include <memory>
#include <type_traits>

/**
 * @brief Concurrent priority queue optimized for multiple producer/single consumer
 * (mpsc) use cases. This queue allows checking the top element against
 * a provided predicate before popping. It is optimized for checking for
 * emptyness before popping.
 */
template<typename Elm, typename Cmp, typename Mtx = std::mutex>
class mpsc_priority_queue
{
	// limit the implementation of Elm to std::shared_ptr | std::unique_ptr
	static_assert(
		std::is_same<Elm, std::shared_ptr<typename Elm::element_type>>::value ||
		std::is_same<Elm, std::unique_ptr<typename Elm::element_type>>::value,
        "mpsc_priority_queue requires std::shared_ptr or std::unique_ptr elements");

public:
	explicit mpsc_priority_queue(size_t capacity = 0) : m_capacity(capacity){}

	/**
	 * @brief Returns true if the queue contains no elements.
	 */
	inline bool empty() const { return m_queue_top == nullptr; }

	/**
	 * @brief Push an element into queue, and returns false in case the
	 * maximum queue capacity is met.
	 */
	inline bool push(Elm e)
	{
		std::scoped_lock<Mtx> lk(m_mtx);
		if (m_capacity == 0 || m_queue.size() < m_capacity)
		{
			m_queue.push(queue_elm{std::move(e)});
			m_queue_top = m_queue.top().elm.get();
			return true;
		}
		return false;
	}

	/**
	 * @brief Pops the highest priority element from the queue. Returns false
	 * in case of empty queue.
	 */
	inline bool pop(OUT Elm& res)
	{
		// first we try lock-free m_queue_top and if it passes the check, then
		// we lock the queue and pop its top
		elm_ptr top = m_queue_top.load();
		if (top == nullptr)
		{
			return false;
		}

		std::scoped_lock<Mtx> lk(m_mtx);
		res = std::move(m_queue.top().elm);
		m_queue.pop();
		m_queue_top = m_queue.empty() ? nullptr : m_queue.top().elm.get();
		return true;
	}

	/**
	 * @brief This is analoguous to pop() but evaluates the element against
	 * a predicate before returning it. If the predicate returns false, the
	 * element is not popped from the queue and this method returns false.
	 */
	template <typename Callable>
	inline bool pop_if(const Callable& cl, OUT Elm& res)
	{
		elm_ptr top = m_queue_top.load();
		if (top == nullptr || !cl(top))
		{
			return false;
		}

		// at this point, we have a guarantee
		// that queue.top() has priority not less than the local top,
		// and we can pop the queue top safely
		std::scoped_lock<Mtx> lk(m_mtx);
		res = std::move(m_queue.top().elm);
		m_queue.pop();
		m_queue_top = m_queue.empty() ? nullptr : m_queue.top().elm.get();
		return true;
	}

private:
	using elm_ptr = typename Elm::element_type*;

	// workaround to make unique_ptr usable when copying the queue top
	// which is const unique<ptr>& and denies moving
	struct queue_elm
	{
		inline bool operator < (const queue_elm& r) const {return Cmp{}(elm, r.elm);}
		mutable Elm elm;
	};

	const size_t m_capacity;
	std::priority_queue<queue_elm> m_queue{};
	std::atomic<elm_ptr> m_queue_top{nullptr};
	Mtx m_mtx;
};
