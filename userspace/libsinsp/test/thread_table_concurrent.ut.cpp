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

#include <gtest/gtest.h>
#include <sinsp_with_test_input.h>

#include <atomic>
#include <thread>
#include <vector>

// Suppress deprecation warning for get_threads() -- used intentionally for direct map access
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Helper: create a threadinfo via the inspector's factory and set its tid.
static threadinfo_map_t::ptr_t make_test_entry(sinsp& inspector, int64_t tid) {
	auto ti = inspector.m_thread_manager->new_entry();
	auto* tinfo = dynamic_cast<sinsp_threadinfo*>(ti.get());
	tinfo->m_tid = tid;
	tinfo->m_pid = tid;
	tinfo->m_ptid = 0;
	tinfo->m_comm = "test";
	ti.release();
	return std::shared_ptr<sinsp_threadinfo>(tinfo);
}

// Test 1: Concurrent add + lookup
// Multiple writer threads insert entries while reader threads look up random TIDs.
TEST_F(sinsp_with_test_input, concurrent_add_and_lookup) {
	add_default_init_thread();
	open_inspector();

	auto* map = m_inspector.m_thread_manager->get_threads();

	constexpr int num_writers = 4;
	constexpr int entries_per_writer = 1000;
	constexpr int num_readers = 4;
	// Use TID range starting well above INIT_TID to avoid conflicts
	constexpr int64_t tid_base = 100000;

	std::atomic<bool> start{false};
	std::atomic<bool> writers_done{false};

	std::vector<std::thread> threads;

	// Writer threads: each inserts a disjoint range of TIDs
	for(int w = 0; w < num_writers; w++) {
		threads.emplace_back([this, map, &start, w]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int64_t base = tid_base + w * entries_per_writer;
			for(int i = 0; i < entries_per_writer; i++) {
				int64_t tid = base + i;
				auto entry = make_test_entry(m_inspector, tid);
				map->put(entry);
			}
		});
	}

	// Reader threads: continuously look up random TIDs
	for(int r = 0; r < num_readers; r++) {
		threads.emplace_back([map, &start, &writers_done, r]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int64_t max_tid = tid_base + num_writers * entries_per_writer;
			int lookups = 0;
			while(!writers_done.load(std::memory_order_acquire) || lookups < 1000) {
				int64_t tid =
				        tid_base + ((r * 7 + lookups * 13) % (num_writers * entries_per_writer));
				auto result = map->get_ref(tid);
				// Result may or may not be found depending on timing
				if(result) {
					EXPECT_EQ(result->m_tid, tid);
				}
				lookups++;
				if(lookups > 100000) {
					break;  // safety limit
				}
			}
		});
	}

	// Start all threads simultaneously
	start.store(true, std::memory_order_release);

	// Wait for writers to complete
	for(int w = 0; w < num_writers; w++) {
		threads[w].join();
	}
	writers_done.store(true, std::memory_order_release);

	// Wait for readers to complete
	for(int r = 0; r < num_readers; r++) {
		threads[num_writers + r].join();
	}

	// Verify all entries are present
	for(int64_t i = 0; i < num_writers * entries_per_writer; i++) {
		int64_t tid = tid_base + i;
		auto entry = map->get_ref(tid);
		ASSERT_NE(entry, nullptr) << "Missing entry for tid " << tid;
		EXPECT_EQ(entry->m_tid, tid);
	}
}

// Test 2: Concurrent remove + iteration
// Some threads remove entries while others iterate the full table.
TEST_F(sinsp_with_test_input, concurrent_remove_and_iteration) {
	add_default_init_thread();
	open_inspector();

	auto* map = m_inspector.m_thread_manager->get_threads();

	constexpr int total_entries = 2000;
	constexpr int num_removers = 4;
	constexpr int entries_per_remover = 250;
	constexpr int num_iterators = 4;
	constexpr int64_t tid_base = 100000;

	// Pre-populate
	for(int64_t i = 0; i < total_entries; i++) {
		map->put(make_test_entry(m_inspector, tid_base + i));
	}

	std::atomic<bool> start{false};
	std::atomic<bool> removers_done{false};

	std::vector<std::thread> threads;

	// Remover threads: each removes a disjoint subset
	for(int r = 0; r < num_removers; r++) {
		threads.emplace_back([map, &start, r]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int64_t base = tid_base + r * entries_per_remover;
			for(int i = 0; i < entries_per_remover; i++) {
				map->erase(base + i);
			}
		});
	}

	// Iterator threads: continuously iterate the table
	for(int it = 0; it < num_iterators; it++) {
		threads.emplace_back([map, &start, &removers_done]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int iterations = 0;
			while(!removers_done.load(std::memory_order_acquire) || iterations < 5) {
				map->loop([](sinsp_threadinfo& tinfo) {
					// Verify each entry is valid (not corrupted)
					EXPECT_GE(tinfo.m_tid, 0);
					return true;
				});
				iterations++;
			}
		});
	}

	start.store(true, std::memory_order_release);

	// Wait for removers
	for(int r = 0; r < num_removers; r++) {
		threads[r].join();
	}
	removers_done.store(true, std::memory_order_release);

	// Wait for iterators
	for(int it = 0; it < num_iterators; it++) {
		threads[num_removers + it].join();
	}

	// Verify correct entries remain
	for(int64_t i = 0; i < total_entries; i++) {
		int64_t tid = tid_base + i;
		auto entry = map->get_ref(tid);
		if(i < num_removers * entries_per_remover) {
			EXPECT_EQ(entry, nullptr) << "Entry " << tid << " should have been removed";
		} else {
			ASSERT_NE(entry, nullptr) << "Entry " << tid << " should still exist";
			EXPECT_EQ(entry->m_tid, tid);
		}
	}
}

// Test 3: Mixed workload
// Simultaneous add, remove, lookup, and iteration from different threads.
TEST_F(sinsp_with_test_input, mixed_workload) {
	add_default_init_thread();
	open_inspector();

	auto* map = m_inspector.m_thread_manager->get_threads();

	constexpr int ops_per_thread = 5000;
	constexpr int64_t tid_range = 2000;
	constexpr int64_t tid_base = 100000;

	// Pre-populate with some entries
	for(int64_t i = 0; i < tid_range / 2; i++) {
		map->put(make_test_entry(m_inspector, tid_base + i));
	}

	std::atomic<bool> start{false};
	std::atomic<bool> done{false};

	std::vector<std::thread> threads;

	// 2 adder threads
	for(int a = 0; a < 2; a++) {
		threads.emplace_back([this, map, &start, a]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			for(int i = 0; i < ops_per_thread; i++) {
				int64_t tid = tid_base + ((a * 997 + i * 31) % tid_range);
				map->put(make_test_entry(m_inspector, tid));
			}
		});
	}

	// 2 remover threads
	for(int r = 0; r < 2; r++) {
		threads.emplace_back([map, &start, r]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			for(int i = 0; i < ops_per_thread; i++) {
				int64_t tid = tid_base + ((r * 991 + i * 37) % tid_range);
				map->erase(tid);
			}
		});
	}

	// 2 lookup threads
	for(int l = 0; l < 2; l++) {
		threads.emplace_back([map, &start, &done, l]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int lookups = 0;
			while(!done.load(std::memory_order_acquire) || lookups < ops_per_thread) {
				int64_t tid = tid_base + ((l * 983 + lookups * 41) % tid_range);
				auto result = map->get_ref(tid);
				if(result) {
					EXPECT_EQ(result->m_tid, tid);
				}
				lookups++;
				if(lookups > 200000) {
					break;  // safety limit
				}
			}
		});
	}

	// 2 iterator threads
	for(int it = 0; it < 2; it++) {
		threads.emplace_back([map, &start, &done]() {
			while(!start.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}

			int iterations = 0;
			while(!done.load(std::memory_order_acquire) || iterations < 3) {
				size_t count = 0;
				map->loop([&count](sinsp_threadinfo& tinfo) {
					EXPECT_GE(tinfo.m_tid, 0);
					count++;
					return true;
				});
				iterations++;
			}
		});
	}

	start.store(true, std::memory_order_release);

	// Wait for adders and removers (first 4 threads)
	for(int i = 0; i < 4; i++) {
		threads[i].join();
	}
	done.store(true, std::memory_order_release);

	// Wait for lookups and iterators (last 4 threads)
	for(int i = 4; i < 8; i++) {
		threads[i].join();
	}

	// Final consistency check: every entry in the map should be valid
	map->loop([](sinsp_threadinfo& tinfo) {
		EXPECT_GE(tinfo.m_tid, 0);
		return true;
	});
}
