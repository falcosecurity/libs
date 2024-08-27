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
 * emptyness before popping. The queue accepts only elements of pointer-type
 * in the form of std::shared_ptr<T> or std::unique_ptr<T>. The priority queue
 * bases its element ordering constraints on Cmp. Elements with equal priority
 * follow the temporal order with which they have been pushed.
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
	inline bool push(Elm&& e)
	{
		std::scoped_lock<Mtx> lk(m_mtx);
		if (m_capacity == 0 || m_queue.size() < m_capacity)
		{
			m_queue.push(queue_elm{std::move(e), m_elem_counter++});
			m_queue_top = m_queue.top().elm.get();
			return true;
		}
		return false;
	}

	/**
	 * @brief Pops the highest priority element from the queue. Returns false
	 * in case of empty queue.
	 */
	inline bool try_pop(Elm& res)
	{
		// we check that the queue is not empty before acquiring the lock
		if (m_queue_top == nullptr)
		{
			return false;
		}

		// at this point, we're sure that the queue is not empty and that
		// we're the only one attempting pop-ing (single consumer guarantee).
		{
			std::scoped_lock<Mtx> lk(m_mtx);
			res = std::move(m_queue.top().elm);
			m_queue.pop();
			m_queue_top = m_queue.empty() ? nullptr : m_queue.top().elm.get();
			return true;
		}
	}

	/**
	 * @brief This is analoguous to pop() but evaluates the element against
	 * a predicate before returning it. If the predicate returns false, the
	 * element is not popped from the queue and this method returns false.
	 */
	template <typename Callable>
	inline bool try_pop_if(Elm& res, const Callable& pred)
	{
		// we check that the queue is not empty before acquiring the lock
		if (m_queue_top == nullptr)
		{
			return false;
		}

		while (true)
		{
			// we need to evaluate the top element against the predicate, but
			// we must be careful in case other producers push a new element in
			// the queue, which can potentially have more priority than the one
			// we just checked.
			elm_ptr top = m_queue_top.load();
			auto should_pop = pred(*top);

			// we must not pop the element
			if (!should_pop)
			{
				// check that the top-priority element ha not changed since
				// we evaluated it, otherwise keep looping
				if (top == m_queue_top.load())
				{
					return false;
				}
				continue;
			}

			// check that the top-priority elem has changed since evaluating it,
			// otherwise keep looping. We check this before acquiring the lock
			// as an extra concurrency optimization.
			if (top != m_queue_top.load())
			{
				continue;
			}

			// let's acquire the lock so that producers are blocked from
			// pushing new elements, potentially with higher priority
			{
				std::scoped_lock<Mtx> lk(m_mtx);

				// while the lock is held no element can be pushed between
				// our checks, so we verify one last time that the actual
				// top element is the one we wish to pop, otherwise release
				// the lock and keep looping
				if (m_queue.top().elm.get() != top)
				{
					continue;
				}

				// the top-priority element is the one we want to pop
				res = std::move(m_queue.top().elm);
				m_queue.pop();
				m_queue_top = m_queue.empty() ? nullptr : m_queue.top().elm.get();
				return true;
			}
		}
	}

	/**
	 * @brief Sets the maximum capacity of the queue. Returns false
	 * if the the specified capacity cannot be set (when the current queue's
	 * size is bigger than the specified capacity).
	 * This setter doesn't actually set the capacity of 'm_queue',
	 * it sets 'm_capacity' which is the valued to used to bound the queue's
	 * size when pushing.
	 */
	inline bool set_capacity(size_t capacity)
	{
		std::scoped_lock<Mtx> lk(m_mtx);
		if(m_queue.size() <= capacity)
		{
			m_capacity = capacity;
			return true;
		}

		return false;
	}

private:
	using elm_ptr = typename Elm::element_type*;

	struct queue_elm
	{
		inline bool operator < (const queue_elm& r) const
		{
			// we check if this elem is less than the other. If the comparison
			// gives the same result when inverting the operands, then we can
			// assume them being equal.
			Cmp c{};
			auto res = c(*elm, *r.elm);
			if (res == c(*r.elm, *elm))
			{
				// if elements have the same priority, order them by
				// temporal order of arrival in the queue by using an atomic
				// logical clock (counter).
				// note(jasondellaluce): this approach is vulnerable to integer overflow
				// that would cause the second-level ordering guarantee to be broken,
				// but given that we use a uint64_t counter we find this unlikely
				return std::greater_equal<uint64_t>{}(num, r.num);
			}
			return res;
		}
		// using mutable is a workaround to make unique_ptr usable when copying
		// the queue top(), which is returned a const unique<ptr>& and denies moving
		mutable Elm elm;
		uint64_t num;
	};

	size_t m_capacity;
	std::priority_queue<queue_elm> m_queue{};
	std::atomic<elm_ptr> m_queue_top{nullptr};
	std::atomic<uint64_t> m_elem_counter{0};
	Mtx m_mtx;
};
