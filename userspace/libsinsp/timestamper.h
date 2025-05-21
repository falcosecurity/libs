#pragma once
#include <stdint.h>
#include <atomic>
#include <libsinsp/utils.h>

/*!
 * \brief Wrapper allowing to handle timestamp generation and caching.
 * When a new timestamp is generated, the `set_cached_ts()` API can be called to cache the timestamp
 * value. A new timestamp can be obtained by calling `get_new_ts()`: the implementation requires a
 * new timestamp to the OS only if the current cached timestamp value is in an invalid state, and
 * returns the cached one otherwise. The cached timestamp is invalid if its value is equal to the
 * invalid timestamp value provided at construction time.
 */
class timestamper {
	uint64_t m_invalid_ts;
	std::atomic<uint64_t> m_cached_ts;

public:
	explicit timestamper(const uint64_t invalid_ts):
	        m_invalid_ts{invalid_ts},
	        m_cached_ts{invalid_ts} {}

	/*!
	  \brief Return the cached timestamp value.
	  \return The cached timestamp value.
	  \note Differently from `get_new_ts()`, this returns the current cached timestamp value,
	    without generating any new timestamp if this one happens to be equal to the configured
	    invalid one.
	 */
	uint64_t get_cached_ts() const { return m_cached_ts.load(); }

	/*!
	  \brief Set the cached timestamp to the configured invalid timestamp value.
	 */
	void reset() { m_cached_ts = m_invalid_ts; }

	/*!
	  \brief Set the cached timestamp.
	  \param cached_ts The new cached timestamp value.
	  \note If the provided timestamp is equal to the configured invalid timestamp value, this is
	    equivalent to calling `reset()`.
	 */
	void set_cached_ts(const uint64_t cached_ts) {
		auto prev_cached_ts = m_cached_ts.load();
		while(prev_cached_ts < cached_ts &&
		      !m_cached_ts.compare_exchange_weak(prev_cached_ts, cached_ts)) {
		}
	}

	/*!
	  \brief Get a new timestamp.

	  \return The current time in nanoseconds if the cached timestamp is set to the configured
	    invalid value, the cached timestamp otherwise.
	  \note This doesn't cache the returned timestamp. In order to set the cached timestamp,
	    `set_cached_ts()` must be explicitly called.
	 */
	uint64_t get_new_ts() const {
		// m_cached_ts is m_invalid_ts at startup when containers are being created as a part of the
		// initial process scan.
		const auto cached_ts = m_cached_ts.load();
		return cached_ts == m_invalid_ts ? sinsp_utils::get_current_time_ns() : cached_ts;
	}
};
