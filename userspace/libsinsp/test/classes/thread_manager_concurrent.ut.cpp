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

#include <helpers/threads_helpers.h>
#include <atomic>
#include <thread>

#if defined(__SANITIZE_THREAD__)
#define LIBSINSP_SKIP_CONCURRENT_TESTS_UNDER_TSAN 1
#else
#define LIBSINSP_SKIP_CONCURRENT_TESTS_UNDER_TSAN 0
#endif

// Concurrent add, lookup, and iteration. Validates thread-safe table operations.
// Skipped under ThreadSanitizer: Folly's hazptr TLS can trigger TSAN reports;
// run without USE_TSAN to exercise these tests.
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_add_lookup_iterate) {
#if LIBSINSP_SKIP_CONCURRENT_TESTS_UNDER_TSAN
	GTEST_SKIP() << "concurrent thread manager tests skipped under TSAN (Folly hazptr TLS)";
#endif
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	auto& factory = m_inspector.get_threadinfo_factory();

	constexpr int64_t tid_start = 10000;
	constexpr int num_adds = 200;
	constexpr int num_lookup_iters = 500;
	constexpr int num_loop_iters = 100;

	std::atomic<bool> stop{false};
	std::thread adder([&]() {
		for(int i = 0; i < num_adds; ++i) {
			auto tinfo = factory.create();
			const int64_t tid = tid_start + i;
			tinfo->m_tid = tid;
			tinfo->m_pid = tid;
			tinfo->m_ptid = 0;
			manager->add_thread(std::move(tinfo), false);
		}
	});

	std::thread lookup([&]() {
		for(int k = 0; k < num_lookup_iters; ++k) {
			for(int i = 0; i < num_adds; ++i) {
				(void)manager->find_thread(tid_start + i, true);
			}
			(void)manager->get_thread_count();
		}
	});

	std::thread iter([&]() {
		for(int k = 0; k < num_loop_iters; ++k) {
			manager->loop_threads([&](const std::shared_ptr<sinsp_threadinfo>&) { return true; });
		}
	});

	adder.join();
	lookup.join();
	iter.join();

	// All added threads should be findable
	for(int i = 0; i < num_adds; ++i) {
		auto p = manager->find_thread(tid_start + i, true);
		ASSERT_TRUE(p) << "tid " << (tid_start + i);
	}
}

// Concurrent add, lookup, iteration, and remove. Skipped under TSAN (see above).
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_add_lookup_iterate_remove) {
#if LIBSINSP_SKIP_CONCURRENT_TESTS_UNDER_TSAN
	GTEST_SKIP() << "concurrent thread manager tests skipped under TSAN (Folly hazptr TLS)";
#endif
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	auto& factory = m_inspector.get_threadinfo_factory();

	constexpr int64_t tid_start = 20000;
	constexpr int num_adds = 300;
	constexpr int num_rounds = 3;

	for(int round = 0; round < num_rounds; ++round) {
		// Phase 1: add threads
		for(int i = 0; i < num_adds; ++i) {
			auto tinfo = factory.create();
			const int64_t tid = tid_start + round * 1000 + i;
			tinfo->m_tid = tid;
			tinfo->m_pid = tid;
			tinfo->m_ptid = 0;
			manager->add_thread(std::move(tinfo), false);
		}

		// Phase 2: concurrent lookup + iteration while remover runs
		std::atomic<bool> phase2_done{false};
		std::thread lookup([&]() {
			while(!phase2_done.load()) {
				for(int i = 0; i < num_adds; ++i) {
					(void)manager->find_thread(tid_start + round * 1000 + i, true);
				}
				(void)manager->get_thread_count();
			}
		});
		std::thread iter([&]() {
			while(!phase2_done.load()) {
				manager->loop_threads(
				        [&](const std::shared_ptr<sinsp_threadinfo>&) { return true; });
			}
		});
		std::thread remover([&]() {
			for(int i = 0; i < num_adds; ++i) {
				manager->remove_thread(tid_start + round * 1000 + i);
			}
			phase2_done.store(true);
		});

		remover.join();
		phase2_done.store(true);
		lookup.join();
		iter.join();
	}
}
