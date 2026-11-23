// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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
#include <shared_mutex>

/*!
 * \brief Tag: single-threaded access (no inter-thread sharing). All the synchronization primitives
 * selected by this policy are no-ops, so a class parameterized on it pays nothing for them.
 */
struct sync_policy_single {};

/*!
 * \brief Tag: concurrent access from several threads. The synchronization primitives selected by
 * this policy are the standard library ones.
 */
struct sync_policy_concurrent {};

/// Default policy of the classes that are parameterized on a sync policy. It is
/// `sync_policy_single`, unless the library is built with `LIBSINSP_SYNC_POLICY_CONCURRENT` (or
/// `ENABLE_MULTI_THREAD`) defined. A class can always be instantiated with an explicit policy
/// regardless of this default.
#if defined(LIBSINSP_SYNC_POLICY_CONCURRENT) || defined(ENABLE_MULTI_THREAD)
using sync_policy_default = sync_policy_concurrent;
#else
using sync_policy_default = sync_policy_single;
#endif

namespace libsinsp {

/// No-op shared mutex. Satisfies SharedMutex, so it can be used with `std::shared_lock` and
/// `std::unique_lock`; every operation compiles to nothing.
struct sinsp_null_shared_mutex {
	void lock() {}
	void unlock() {}
	bool try_lock() { return true; }
	void lock_shared() {}
	void unlock_shared() {}
	bool try_lock_shared() { return true; }
};

/// Maps a sync policy to the primitives that classes parameterized on it use.
template<typename SyncPolicy>
struct sync_policy_traits;

template<>
struct sync_policy_traits<sync_policy_single> {
	static constexpr bool is_concurrent = false;
	/// Reader/writer lock protecting a data structure.
	using shared_mutex = sinsp_null_shared_mutex;
	/// Flag written and read without any other protection. Plain `bool`: same layout and code as
	/// before the policy existed.
	using atomic_flag = bool;
};

template<>
struct sync_policy_traits<sync_policy_concurrent> {
	static constexpr bool is_concurrent = true;
	using shared_mutex = std::shared_mutex;
	using atomic_flag = std::atomic<bool>;
};

}  // namespace libsinsp
