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

/*
 * These tests run under TSAN. Folly hazptr TLS false positives are suppressed via
 * tsan_suppressions.txt. sinsp_threadinfo in-place updates are out of scope (see suppressions).
 *
 * Coverage of thread-safe structures:
 * - Thread table (Folly CHM): add, lookup, loop_threads, remove.
 * - m_thread_groups + thread_group_info: get_thread_group_info, create_thread_dependencies,
 *   remove_thread (erase group, update tginfo).
 * - m_last_flush_time_ns + proc counters (atomics): get/set_last_flush_time_ns,
 *   reset_thread_counters, get_m_n_proc_lookups(_duration_ns).
 * Not covered: m_server_ports (would require fd table thread-safety); m_foreign_* (init-only);
 * proc counter increments (get_thread with /proc lookup not triggered in tests).
 */

#include <helpers/threads_helpers.h>
#include <atomic>
#include <thread>

// Concurrent add, lookup, and iteration. Validates thread-safe table operations.
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_add_lookup_iterate) {
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	auto& factory = m_inspector.get_threadinfo_factory();

	constexpr int64_t tid_start = 10000;
	constexpr int num_adds = 200;
	constexpr int num_lookup_iters = 500;
	constexpr int num_loop_iters = 100;

	std::thread adder([&]() {
		for(int i = 0; i < num_adds; ++i) {
			auto tinfo = factory.create();
			const int64_t tid = tid_start + i;
			tinfo->m_tid = tid;
			tinfo->set_pid(tid);
			tinfo->set_ptid(0);
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
			manager->loop_threads([&](const sinsp_threadinfo&) { return true; });
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

// Concurrent add, lookup, iteration, and remove.
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_add_lookup_iterate_remove) {
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
			tinfo->set_pid(tid);
			tinfo->set_ptid(0);
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
				manager->loop_threads([&](const sinsp_threadinfo&) { return true; });
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

// Concurrent thread group access: add_thread + create_thread_dependencies (creates/updates
// m_thread_groups and thread_group_info), get_thread_group_info, remove_thread (erases from
// m_thread_groups). Runs under TSAN.
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_thread_groups) {
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	auto& factory = m_inspector.get_threadinfo_factory();

	constexpr int64_t pid_base = 40000;
	constexpr int num_procs = 20;        // 20 process groups
	constexpr int threads_per_proc = 5;  // 5 threads per process
	constexpr int num_rounds = 2;

	for(int round = 0; round < num_rounds; ++round) {
		const int64_t round_off = round * 1000;
		// Add threads so that each process (pid) has several threads; create_thread_dependencies
		// will create/update thread_group_info for each pid.
		for(int p = 0; p < num_procs; ++p) {
			const int64_t pid = pid_base + p + round_off;
			for(int t = 0; t < threads_per_proc; ++t) {
				auto tinfo = factory.create();
				const int64_t tid = pid * 10 + t;
				tinfo->m_tid = tid;
				tinfo->set_pid(pid);
				tinfo->set_ptid((t == 0) ? 0 : (pid * 10));
				manager->add_thread(std::move(tinfo), false);
			}
		}
		for(int p = 0; p < num_procs; ++p) {
			const int64_t pid = pid_base + p + round_off;
			for(int t = 0; t < threads_per_proc; ++t) {
				auto tinfo = manager->find_thread(pid * 10 + t, true);
				if(tinfo) {
					manager->create_thread_dependencies(tinfo);
				}
			}
		}

		std::atomic<bool> stop{false};
		std::thread reader([&]() {
			while(!stop.load()) {
				for(int p = 0; p < num_procs; ++p) {
					(void)manager->get_thread_group_info(pid_base + p + round_off);
				}
			}
		});
		std::thread remover([&]() {
			for(int p = 0; p < num_procs; ++p) {
				const int64_t pid = pid_base + p + round_off;
				for(int t = 0; t < threads_per_proc; ++t) {
					manager->remove_thread(pid * 10 + t);
				}
			}
			stop.store(true);
		});

		remover.join();
		reader.join();
	}
}

// Concurrent flush time and proc lookup counters (atomics): get/set_last_flush_time_ns,
// reset_thread_counters, get_m_n_proc_lookups. Runs under TSAN.
TEST_F(sinsp_with_test_input, THRD_MANAGER_concurrent_flush_and_counters) {
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	auto& factory = m_inspector.get_threadinfo_factory();

	constexpr int64_t tid_start = 50000;
	constexpr int num_threads = 100;
	for(int i = 0; i < num_threads; ++i) {
		auto tinfo = factory.create();
		tinfo->m_tid = tid_start + i;
		tinfo->set_pid(tid_start + i);
		tinfo->set_ptid(0);
		manager->add_thread(std::move(tinfo), false);
	}

	constexpr int num_iters = 500;
	std::thread flush_thread([&]() {
		for(int k = 0; k < num_iters; ++k) {
			manager->set_last_flush_time_ns(static_cast<uint64_t>(k));
			(void)manager->get_last_flush_time_ns();
			if(k % 10 == 0) {
				manager->reset_thread_counters();
			}
		}
	});
	std::thread lookup_thread([&]() {
		for(int k = 0; k < num_iters; ++k) {
			for(int i = 0; i < num_threads; ++i) {
				(void)manager->find_thread(tid_start + i, true);
			}
			(void)manager->get_m_n_proc_lookups();
			(void)manager->get_m_n_proc_lookups_duration_ns();
		}
	});

	flush_thread.join();
	lookup_thread.join();
}

// Note: Concurrent m_server_ports (add_thread_fd_from_scap vs fix_sockets_coming_from_proc)
// would require the per-thread fd table to be thread-safe, which is out of scope for this
// proposal. m_server_ports itself is protected by m_server_ports_mutex in thread_manager.
