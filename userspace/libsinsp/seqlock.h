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

#include <atomic>
#include <utility>

//
// Sequence lock: optimized for read-heavy workloads.
//
// Writers acquire exclusive access via CAS spin (incrementing an odd counter)
// and release by incrementing back to even. Readers speculatively copy data
// then validate the counter has not changed.
//
// Readers are wait-free in the uncontended case (two atomic counter loads +
// an acquire fence). Writers pay ~20-40ns for CAS + fetch_add, cheaper than
// std::shared_mutex (~50-100ns).
//
// TSAN note: TSAN cannot model speculative read-retry semantics, so it will
// report false-positive data races between seqlock readers and writers. These
// are suppressed via "race:sinsp_seqlock::read" in the TSAN suppressions file.
// The seqlock's correctness relies on the retry loop: if a writer was active
// during the read, the counter check in read_retry() detects it and the reader
// re-executes fn().
//
// Copyable: copy/move constructors produce a fresh seqlock (seq=0), matching
// sinsp_copyable_mutex semantics.
//
class sinsp_seqlock {
	alignas(64) std::atomic<uint32_t> m_seq{0};

public:
	sinsp_seqlock() = default;
	sinsp_seqlock(const sinsp_seqlock&) noexcept: m_seq(0) {}
	sinsp_seqlock& operator=(const sinsp_seqlock&) noexcept { return *this; }
	sinsp_seqlock(sinsp_seqlock&&) noexcept: m_seq(0) {}
	sinsp_seqlock& operator=(sinsp_seqlock&&) noexcept { return *this; }

	uint32_t read_begin() const {
		uint32_t s;
		do {
			s = m_seq.load(std::memory_order_acquire);
		} while(s & 1);
		return s;
	}

	bool read_retry(uint32_t start) const {
		std::atomic_thread_fence(std::memory_order_acquire);
		return m_seq.load(std::memory_order_relaxed) != start;
	}

	template<typename F>
	void read(F&& fn) const {
		uint32_t seq;
		do {
			seq = read_begin();
			fn();
		} while(read_retry(seq));
	}

	void write_lock() {
		uint32_t expected;
		do {
			expected = m_seq.load(std::memory_order_relaxed) & ~1u;
		} while(!m_seq.compare_exchange_weak(expected,
		                                     expected + 1,
		                                     std::memory_order_acquire,
		                                     std::memory_order_relaxed));
	}

	void write_unlock() { m_seq.fetch_add(1, std::memory_order_release); }
};

// RAII write guard -- movable, not copyable.
class sinsp_seqlock_write_guard {
	sinsp_seqlock* m_lock;

public:
	explicit sinsp_seqlock_write_guard(sinsp_seqlock& sl): m_lock(&sl) { m_lock->write_lock(); }
	~sinsp_seqlock_write_guard() {
		if(m_lock) {
			m_lock->write_unlock();
		}
	}
	sinsp_seqlock_write_guard(sinsp_seqlock_write_guard&& o) noexcept:
	        m_lock(std::exchange(o.m_lock, nullptr)) {}
	sinsp_seqlock_write_guard& operator=(sinsp_seqlock_write_guard&&) = delete;
	sinsp_seqlock_write_guard(const sinsp_seqlock_write_guard&) = delete;
	sinsp_seqlock_write_guard& operator=(const sinsp_seqlock_write_guard&) = delete;
};

// No-op variants for single-threaded policy.
struct sinsp_null_seqlock {
	uint32_t read_begin() const { return 0; }
	bool read_retry(uint32_t) const { return false; }
	template<typename F>
	void read(F&& fn) const {
		fn();
	}
	void write_lock() {}
	void write_unlock() {}

	sinsp_null_seqlock() = default;
	sinsp_null_seqlock(const sinsp_null_seqlock&) noexcept = default;
	sinsp_null_seqlock& operator=(const sinsp_null_seqlock&) noexcept = default;
	sinsp_null_seqlock(sinsp_null_seqlock&&) noexcept = default;
	sinsp_null_seqlock& operator=(sinsp_null_seqlock&&) noexcept = default;
};

struct sinsp_null_seqlock_write_guard {
	explicit sinsp_null_seqlock_write_guard(sinsp_null_seqlock&) {}
};
