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

#include <mutex>
#include <shared_mutex>

/*!
 * \brief Tag: single-threaded access to libsinsp state for this inspector (no inter-thread
 * sharing).
 */
struct sync_policy_single {};

/*!
 * \brief Tag: concurrent access (multiple threads on the same sinsp instance).
 */
struct sync_policy_concurrent {};

/// Default policy for sinsp and related templates.
/// Set at build time: single-threaded (no mutexes) unless ENABLE_MULTI_THREAD is defined.
#ifdef ENABLE_MULTI_THREAD
using sync_policy_default = sync_policy_concurrent;
#else
using sync_policy_default = sync_policy_single;
#endif

namespace libsinsp {

/// No-op mutex for BasicLockable (e.g. m_children_mutex in single-threaded policy).
struct sinsp_null_mutex {
	void lock() {}
	void unlock() {}
	bool try_lock() { return true; }
};

/// No-op shared mutex for std::shared_lock / std::unique_lock exclusive.
struct sinsp_null_shared_mutex {
	void lock() {}
	void unlock() {}
	bool try_lock() { return true; }
	void lock_shared() {}
	void unlock_shared() {}
	bool try_lock_shared() { return true; }
};

template<typename SyncPolicy>
struct sync_policy_traits;

template<>
struct sync_policy_traits<sync_policy_single> {
	static constexpr bool k_use_folly_chm = false;
	static constexpr bool k_needs_fdtable_shared_mutex = false;
	using mutex = sinsp_null_mutex;
	using shared_mutex = sinsp_null_shared_mutex;
	using thread_state_mutex = sinsp_null_shared_mutex;
	using thread_children_mutex = sinsp_null_mutex;
	using fdinfo_inner_mutex = sinsp_null_shared_mutex;
	using thread_group_mutex = sinsp_null_shared_mutex;
	/// Always held around fdtable map ops; no-op type for single-threaded policy.
	using fdtable_outer_mutex = sinsp_null_shared_mutex;
};

template<>
struct sync_policy_traits<sync_policy_concurrent> {
#ifdef LIBSINSP_USE_FOLLY
	static constexpr bool k_use_folly_chm = true;
	static constexpr bool k_needs_fdtable_shared_mutex = false;
#else
	static constexpr bool k_use_folly_chm = false;
	static constexpr bool k_needs_fdtable_shared_mutex = true;
#endif
	using mutex = std::mutex;
	using shared_mutex = std::shared_mutex;
	using thread_state_mutex = std::shared_mutex;
	using thread_children_mutex = std::mutex;
	using fdinfo_inner_mutex = std::shared_mutex;
	using thread_group_mutex = std::shared_mutex;
#ifdef LIBSINSP_USE_FOLLY
	using fdtable_outer_mutex = sinsp_null_shared_mutex;
#else
	using fdtable_outer_mutex = std::shared_mutex;
#endif
};

/*!
 * Copyable wrapper so sinsp_fdinfo remains copyable; inner mutex type comes from sync policy.
 */
template<typename InnerMutex>
struct sinsp_copyable_mutex {
	mutable InnerMutex m;
	sinsp_copyable_mutex() = default;
	sinsp_copyable_mutex(const sinsp_copyable_mutex&) noexcept {}
	sinsp_copyable_mutex& operator=(const sinsp_copyable_mutex&) noexcept { return *this; }
	sinsp_copyable_mutex(sinsp_copyable_mutex&&) noexcept {}
	sinsp_copyable_mutex& operator=(sinsp_copyable_mutex&&) noexcept { return *this; }
};

template<typename SyncPolicy>
using sinsp_fd_mutex_wrapper =
        sinsp_copyable_mutex<typename sync_policy_traits<SyncPolicy>::fdinfo_inner_mutex>;

}  // namespace libsinsp
