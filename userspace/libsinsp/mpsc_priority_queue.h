
#pragma once

#include <mutex>
#include <atomic>
#include <queue>

/*
 * concurrent priority queue optimized for multiple producer/single consumer (mpsc) apps
 * this queue checks the top against provided predicate before popping
 * provides fast empty() method
 * optional capacity limit could be provided
 *
 */
template<typename Elm, typename Cmp, typename Mtx = std::mutex, typename Enb = void> class mpsc_priority_queue;

template<typename Elm, typename Cmp, typename Mtx>
class mpsc_priority_queue<
	Elm, Cmp, Mtx,
	// limit the implementation of Elm to std::shared_ptr | std::unique_ptr
	typename std::enable_if<std::is_same_v<Elm, std::shared_ptr<typename Elm::element_type>> ||
				std::is_same_v<Elm, std::unique_ptr<typename Elm::element_type>> >::type >
{
	// workaround to make unique_ptr usable when copying the queue top
	// which is const unique<ptr>& and denies moving
	struct queue_elm
	{
		inline bool operator < (const queue_elm& r) const {return Cmp{}(elm, r.elm);}
		mutable Elm elm;
	};
public:
	using elm_ptr = typename Elm::element_type*;

	explicit mpsc_priority_queue(size_t capacity = 0) : m_capacity(capacity){}

	inline bool empty() const { return m_queue_top == nullptr; }

	/*
	 * push an element into queue if capacity allows
	 */
	inline bool push(Elm e)
	{
		std::scoped_lock<Mtx> lk(m_mtx);
		if (m_capacity == 0 ||  m_queue.size() < m_capacity)
		{
			m_queue.push(queue_elm{std::move(e)});
			m_queue_top = m_queue.top().elm.get();
			return true;
		}
		return false;
	}

	/*
	 * check predicate before popping
	 * first we try lock-free m_queue_top
	 * if it passes the check, then we lock the queue and pop its top
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
	const size_t m_capacity;
	std::priority_queue<queue_elm> m_queue{};
	std::atomic<elm_ptr> m_queue_top{nullptr};
	Mtx m_mtx;
};
