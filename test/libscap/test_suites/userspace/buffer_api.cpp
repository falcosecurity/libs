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

#include <libscap/scap.h>
#include <libscap/engine/noop/noop.h>
#include <libscap/scap_engines.h>
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

namespace {

// Events are packed, so evt->tid may be misaligned: read it by value, never bind a reference to it
// (gtest's ASSERT_EQ takes references, which UBSan reports).
uint64_t tid_of(const scap_evt* evt) {
	uint64_t tid;
	memcpy(&tid, &evt->tid, sizeof(tid));
	return tid;
}

// Builds a bare event header: libscap does not parse the events of the test_input engine, so the
// thread id is enough to tell which event is which.
ppm_evt_hdr make_evt(uint64_t tid) {
	ppm_evt_hdr evt{};
	evt.ts = tid;
	evt.tid = tid;
	evt.len = sizeof(ppm_evt_hdr);
	evt.type = PPME_SYSCALL_CLOSE_E;
	return evt;
}

class buffer_api : public ::testing::Test {
protected:
	void TearDown() override {
		if(m_handle != nullptr) {
			scap_close(m_handle);
		}
	}

	// Adds a buffer holding events with the given tids, in order.
	void add_buffer(const std::vector<uint64_t>& tids, bool eof_when_empty = false) {
		m_events.emplace_back();
		for(const auto tid : tids) {
			m_events.back().push_back(make_evt(tid));
		}
		m_queues.emplace_back();
		m_eof.push_back(eof_when_empty);
	}

	void open_test_input(bool with_buffers = true) {
		// Pointers are taken only now, when the vectors can no longer be reallocated.
		for(size_t i = 0; i < m_events.size(); i++) {
			for(auto& evt : m_events[i]) {
				m_queues[i].push_back(&evt);
			}
			m_bufs.push_back({m_queues[i].data(), m_queues[i].size(), m_eof[i]});
		}
		m_input_buffers.buffers = m_bufs.data();
		m_input_buffers.n_buffers = static_cast<uint16_t>(m_bufs.size());

		m_data = {};
		scap_test_input_engine_params params{};
		params.test_input_data = &m_data;
		params.test_input_buffers = with_buffers ? &m_input_buffers : nullptr;
		scap_open_args oargs{};
		oargs.engine_params = &params;

		char error[SCAP_LASTERR_SIZE] = {};
		int32_t rc = SCAP_FAILURE;
		m_handle = scap_open(&oargs, &scap_test_input_engine, error, &rc);
		ASSERT_NE(m_handle, nullptr) << error;
	}

	scap_t* m_handle = nullptr;
	scap_test_input_data m_data{};
	scap_test_input_buffers m_input_buffers{};
	std::vector<std::vector<ppm_evt_hdr>> m_events;
	std::vector<std::vector<ppm_evt_hdr*>> m_queues;
	std::vector<scap_test_input_buffer> m_bufs;
	std::vector<int> m_eof;
};

}  // namespace

TEST_F(buffer_api, handle_count_matches_the_configured_buffers) {
	add_buffer({1});
	add_buffer({2});
	add_buffer({3});
	open_test_input();
	ASSERT_EQ(scap_buffer_get_n_allocated_handles(m_handle), 3);
}

TEST_F(buffer_api, reserved_handles_are_distinct_and_limited_to_the_count) {
	add_buffer({1});
	add_buffer({2});
	open_test_input();

	const scap_buffer_t h0 = scap_buffer_reserve_handle(m_handle);
	const scap_buffer_t h1 = scap_buffer_reserve_handle(m_handle);
	ASSERT_NE(h0, SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_NE(h1, SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_NE(h0, h1);

	// No handle left.
	ASSERT_EQ(scap_buffer_reserve_handle(m_handle), SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_STRNE(scap_getlasterr(m_handle), "");
	// Reserving does not change the number of allocated handles.
	ASSERT_EQ(scap_buffer_get_n_allocated_handles(m_handle), 2);
}

TEST_F(buffer_api, events_are_delivered_to_the_right_buffer_in_order) {
	add_buffer({10, 11});
	add_buffer({20});
	open_test_input();
	const scap_buffer_t h0 = scap_buffer_reserve_handle(m_handle);
	const scap_buffer_t h1 = scap_buffer_reserve_handle(m_handle);

	scap_evt* evt = nullptr;
	uint32_t flags = 0xff;

	// Read the buffers in an interleaved order: each one keeps its own sequence.
	ASSERT_EQ(scap_buffer_next(m_handle, h1, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(tid_of(evt), 20u);
	ASSERT_EQ(flags, 0u);
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(tid_of(evt), 10u);
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(tid_of(evt), 11u);
}

TEST_F(buffer_api, an_empty_buffer_times_out_without_affecting_the_others) {
	add_buffer({});
	add_buffer({7});
	open_test_input();
	const scap_buffer_t h0 = scap_buffer_reserve_handle(m_handle);
	const scap_buffer_t h1 = scap_buffer_reserve_handle(m_handle);

	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_TIMEOUT);
	ASSERT_EQ(scap_buffer_next(m_handle, h1, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(tid_of(evt), 7u);
	// h1 is now drained too, h0 is still just empty.
	ASSERT_EQ(scap_buffer_next(m_handle, h1, &evt, &flags), SCAP_TIMEOUT);
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_TIMEOUT);
}

TEST_F(buffer_api, eof_is_reported_per_buffer) {
	add_buffer({1}, /*eof_when_empty=*/true);
	add_buffer({2}, /*eof_when_empty=*/false);
	open_test_input();
	const scap_buffer_t h0 = scap_buffer_reserve_handle(m_handle);
	const scap_buffer_t h1 = scap_buffer_reserve_handle(m_handle);

	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_EOF);
	ASSERT_EQ(scap_buffer_next(m_handle, h1, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(scap_buffer_next(m_handle, h1, &evt, &flags), SCAP_TIMEOUT);
}

TEST_F(buffer_api, invalid_and_unreserved_handles_fail) {
	add_buffer({1});
	add_buffer({2});
	open_test_input();
	const scap_buffer_t h0 = scap_buffer_reserve_handle(m_handle);
	ASSERT_NE(h0, SCAP_INVALID_BUFFER_HANDLE);

	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_next(m_handle, SCAP_INVALID_BUFFER_HANDLE, &evt, &flags), SCAP_FAILURE);
	ASSERT_STRNE(scap_getlasterr(m_handle), "");
	// The second buffer exists but was not reserved yet.
	ASSERT_EQ(scap_buffer_next(m_handle, h0 + 1, &evt, &flags), SCAP_FAILURE);
	// A handle past the last buffer is just as invalid.
	ASSERT_EQ(scap_buffer_next(m_handle, 100, &evt, &flags), SCAP_FAILURE);
	// The failures did not consume anything.
	ASSERT_EQ(scap_buffer_next(m_handle, h0, &evt, &flags), SCAP_SUCCESS);
	ASSERT_EQ(tid_of(evt), 1u);
}

TEST_F(buffer_api, null_handle_is_rejected) {
	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_get_n_allocated_handles(nullptr), 0);
	ASSERT_EQ(scap_buffer_reserve_handle(nullptr), SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_EQ(scap_buffer_next(nullptr, 0, &evt, &flags), SCAP_FAILURE);
}

TEST_F(buffer_api, single_stream_mode_does_not_support_buffers) {
	open_test_input(/*with_buffers=*/false);

	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_get_n_allocated_handles(m_handle), 0);
	ASSERT_EQ(scap_buffer_reserve_handle(m_handle), SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_EQ(scap_buffer_next(m_handle, 0, &evt, &flags), SCAP_NOT_SUPPORTED);
}

TEST_F(buffer_api, engines_without_buffers_report_not_supported) {
	scap_open_args oargs{};
	char error[SCAP_LASTERR_SIZE] = {};
	int32_t rc = SCAP_FAILURE;
	m_handle = scap_open(&oargs, &scap_noop_engine, error, &rc);
	ASSERT_NE(m_handle, nullptr) << error;

	scap_evt* evt = nullptr;
	uint32_t flags = 0;
	ASSERT_EQ(scap_buffer_get_n_allocated_handles(m_handle), 0);
	ASSERT_EQ(scap_buffer_reserve_handle(m_handle), SCAP_INVALID_BUFFER_HANDLE);
	ASSERT_EQ(scap_buffer_next(m_handle, 0, &evt, &flags), SCAP_NOT_SUPPORTED);
	ASSERT_STRNE(scap_getlasterr(m_handle), "");
}

TEST_F(buffer_api, the_single_stream_is_not_affected_by_the_buffers) {
	add_buffer({1});
	open_test_input();
	scap_evt* evt = nullptr;
	uint16_t devid = 0;
	uint32_t flags = 0;
	// m_data has no events: the stream times out, the buffers are untouched.
	ASSERT_EQ(scap_next(m_handle, &evt, &devid, &flags), SCAP_TIMEOUT);
	const scap_buffer_t h = scap_buffer_reserve_handle(m_handle);
	ASSERT_EQ(scap_buffer_next(m_handle, h, &evt, &flags), SCAP_SUCCESS);
}
