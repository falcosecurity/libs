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

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <type_traits>

#include <libsinsp/sync_policy.h>

using namespace libsinsp;

// The single policy must not cost anything: its lock is an empty type, and its flag a plain bool.
static_assert(std::is_empty_v<sync_policy_traits<sync_policy_single>::shared_mutex>);
static_assert(std::is_same_v<sync_policy_traits<sync_policy_single>::shared_mutex,
                             sinsp_null_shared_mutex>);
static_assert(std::is_same_v<sync_policy_traits<sync_policy_single>::atomic_flag, bool>);
static_assert(!sync_policy_traits<sync_policy_single>::is_concurrent);

// The concurrent policy uses the standard library primitives.
static_assert(std::is_same_v<sync_policy_traits<sync_policy_concurrent>::shared_mutex,
                             std::shared_mutex>);
static_assert(
        std::is_same_v<sync_policy_traits<sync_policy_concurrent>::atomic_flag, std::atomic<bool>>);
static_assert(sync_policy_traits<sync_policy_concurrent>::is_concurrent);

// Without the build flags, the library default is the single policy.
#if !defined(LIBSINSP_SYNC_POLICY_CONCURRENT) && !defined(ENABLE_MULTI_THREAD)
static_assert(std::is_same_v<sync_policy_default, sync_policy_single>);
#endif

TEST(sync_policy, null_shared_mutex_never_blocks) {
	sinsp_null_shared_mutex m;
	// Locking in any order and any number of times must be fine, also from the same thread: a
	// real mutex would deadlock or throw.
	std::unique_lock<sinsp_null_shared_mutex> writer(m);
	std::shared_lock<sinsp_null_shared_mutex> reader1(m);
	std::shared_lock<sinsp_null_shared_mutex> reader2(m);
	ASSERT_TRUE(writer.owns_lock());
	ASSERT_TRUE(reader1.owns_lock());
	ASSERT_TRUE(reader2.owns_lock());
	ASSERT_TRUE(m.try_lock());
	ASSERT_TRUE(m.try_lock_shared());
}

TEST(sync_policy, traits_select_a_working_lock) {
	// Both selected types are usable through the same lock guards.
	sync_policy_traits<sync_policy_single>::shared_mutex single;
	sync_policy_traits<sync_policy_concurrent>::shared_mutex concurrent;
	{
		std::shared_lock<decltype(single)> a(single);
		std::shared_lock<decltype(concurrent)> b(concurrent);
		std::shared_lock<decltype(concurrent)> c(concurrent);  // readers share
		ASSERT_TRUE(a.owns_lock());
		ASSERT_TRUE(b.owns_lock());
		ASSERT_TRUE(c.owns_lock());
		// a writer cannot get in while readers hold the real lock
		ASSERT_FALSE(concurrent.try_lock());
	}
	ASSERT_TRUE(concurrent.try_lock());
	concurrent.unlock();
}
