// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

class thread_state_test : public ::testing::Test {
protected:
	virtual void SetUp() {
		const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();
		const auto& thread_manager = m_inspector.m_thread_manager;
		// Each entry in the vector has a parent of the previous
		// entry. The first entry has a parent of 1.
		for(int64_t pid = 100, i = 0; i < m_max; pid++, i++) {
			int64_t ppid = (i == 0 ? 1 : m_threads[i - 1]->m_tid);
			std::unique_ptr<sinsp_threadinfo> thr = threadinfo_factory.create();
			thr->init();
			thr->m_tid = pid;
			thr->m_ptid = ppid;

			thread_manager->add_thread(std::move(thr), true);
			sinsp_threadinfo* tinfo = thread_manager->find_thread(pid, true).get();

			m_threads.push_back(tinfo);
		}
	}

	virtual void TearDown() {}

	void reset() {
		// Reset the state
		for(uint32_t i = 0; i < m_max; i++) {
			int64_t ppid = (i == 0 ? 1 : m_threads[i - 1]->m_tid);
			sinsp_threadinfo* tinfo = m_threads[i];
			tinfo->m_lastevent_fd = 0;
			tinfo->set_parent_loop_detected(false);
			tinfo->m_ptid = ppid;
		}
	}

	void traverse_with_timeout(sinsp_threadinfo* tinfo) {
		promise<bool> finished;
		auto result = finished.get_future();

		sinsp_thread_manager::visitor_func_t visitor = [](sinsp_threadinfo* tinfo) {
			tinfo->m_lastevent_fd = 1;
			return true;
		};

		thread runner = thread(
		        [](promise<bool> finished,
		           const std::shared_ptr<sinsp_thread_manager>& thread_manager,
		           sinsp_threadinfo* tinfo,
		           sinsp_thread_manager::visitor_func_t visitor) {
			        thread_manager->traverse_parent_state(*tinfo, visitor);
			        finished.set_value(true);
		        },
		        std::move(finished),
		        m_inspector.m_thread_manager,
		        tinfo,
		        visitor);

		runner.detach();

		// If this fails, the thread will probably remain running.
		EXPECT_TRUE(result.wait_for(chrono::milliseconds(1000)) != future_status::timeout);
	}

	// This just verifies that the mechanism of wait_for with a
	// timeout actually works in the face of a thread that never
	// stops
	void loop_almost_forever() {
		promise<bool> finished;
		auto result = finished.get_future();

		// This runs for 3 seconds which is greater than the 1
		// second timeout below
		thread runner = thread([&finished]() {
			sleep(3);
			finished.set_value(true);
		});

		runner.detach();

		EXPECT_TRUE(result.wait_for(chrono::milliseconds(1000)) == future_status::timeout);
		sleep(5);

		EXPECT_TRUE(result.wait_for(chrono::milliseconds(1000)) != future_status::timeout);
	}

	void verify(uint32_t test_idx, bool loop_detected, vector<uint32_t>& visited) {
		SCOPED_TRACE("test_idx=" + to_string(test_idx));
		EXPECT_EQ(m_threads[test_idx]->parent_loop_detected(), loop_detected);
		for(uint32_t i = 0; i < m_max; i++) {
			SCOPED_TRACE("i=" + to_string(i));
			EXPECT_EQ(m_threads[i]->m_lastevent_fd, visited[i]);
		}
	}

	sinsp m_inspector;
	vector<sinsp_threadinfo*> m_threads;
	uint32_t m_max = 5;
};

TEST_F(thread_state_test, parent_state_single) {
	reset();
	traverse_with_timeout(m_threads[0]);

	// Nothing is visited as we are starting with the top thread's
	// parent.
	vector<uint32_t> expected = {0, 0, 0, 0, 0};
	verify(0, false, expected);
}

TEST_F(thread_state_test, parent_state_parent) {
	reset();
	traverse_with_timeout(m_threads[1]);

	vector<uint32_t> expected = {1, 0, 0, 0, 0};
	verify(1, false, expected);
}

TEST_F(thread_state_test, parent_state_parent_ancestors) {
	reset();
	traverse_with_timeout(m_threads[4]);

	vector<uint32_t> expected = {1, 1, 1, 1, 0};
	verify(4, false, expected);
}

TEST_F(thread_state_test, parent_state_single_loop) {
	reset();
	m_threads[0]->m_ptid = m_threads[0]->m_tid;
	traverse_with_timeout(m_threads[0]);

	// We end up visiting the top thread as we do so before
	// detecting the loop.
	vector<uint32_t> expected = {1, 0, 0, 0, 0};
	verify(0, true, expected);
}

TEST_F(thread_state_test, parent_state_short_loop) {
	reset();
	m_threads[0]->m_ptid = m_threads[1]->m_tid;
	traverse_with_timeout(m_threads[1]);

	// In this case we reach the end of the parent state before
	// detecting a loop.
	vector<uint32_t> expected = {1, 0, 0, 0, 0};
	verify(0, false, expected);
}

TEST_F(thread_state_test, parent_state_loop) {
	reset();
	m_threads[0]->m_ptid = m_threads[4]->m_tid;
	traverse_with_timeout(m_threads[4]);

	vector<uint32_t> expected = {1, 1, 1, 1, 0};
	verify(4, true, expected);
}

TEST_F(thread_state_test, parent_state_lollipop) {
	reset();
	m_threads[0]->m_ptid = m_threads[2]->m_tid;
	traverse_with_timeout(m_threads[4]);

	// In this case, we detect the loop before visiting all the
	// parents that comprise the loop.
	vector<uint32_t> expected = {0, 0, 1, 1, 0};
	verify(4, true, expected);
}

TEST_F(thread_state_test, parent_state_verify_timeout) {
	loop_almost_forever();
}
