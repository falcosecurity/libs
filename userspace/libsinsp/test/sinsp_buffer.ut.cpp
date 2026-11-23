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

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include <libsinsp/parsers.h>

#include "sinsp_with_test_input.h"

namespace {

constexpr int64_t tid_a = 100;
constexpr int64_t tid_b = 200;

class sinsp_buffer_test : public sinsp_with_test_input {
protected:
	~sinsp_buffer_test() {
		for(auto* evt : m_owned) {
			free(evt);
		}
	}

	// Creates an event that is owned by the fixture and is not part of the single event stream.
	scap_evt* make_event(int64_t tid, ppm_event_code type, uint32_t n, ...) {
		va_list args;
		va_start(args, n);
		scap_evt* evt = create_event_v(increasing_ts(), tid, type, nullptr, n, args);
		va_end(args);
		m_owned.push_back(evt);
		return evt;
	}

	scap_evt* make_open(int64_t tid, int64_t fd, const char* path) {
		return make_event(tid,
		                  PPME_SYSCALL_OPEN_X,
		                  6,
		                  fd,
		                  path,
		                  (uint32_t)0,
		                  (uint32_t)0,
		                  (uint32_t)0,
		                  (uint64_t)0);
	}

	scap_evt* make_close(int64_t tid, int64_t fd) {
		return make_event(tid, PPME_SYSCALL_CLOSE_X, 2, (int64_t)0, fd);
	}

	scap_evt* make_proc_exit(int64_t tid) {
		return make_event(tid,
		                  PPME_PROCEXIT_1_E,
		                  5,
		                  (int64_t)0,
		                  (int64_t)0,
		                  (uint8_t)0,
		                  (uint8_t)0,
		                  (int64_t)1);
	}

	scap_evt* copy_event(const scap_evt* evt) {
		auto* copy = static_cast<scap_evt*>(malloc(evt->len));
		memcpy(copy, evt, evt->len);
		m_owned.push_back(copy);
		return copy;
	}

	void add_threads() {
		add_default_init_thread();
		add_simple_thread(tid_a, tid_a, 1, "proc_a");
		add_simple_thread(tid_b, tid_b, 1, "proc_b");
	}

	// Opens m_inspector with the single stream in m_test_data plus the given per-buffer queues.
	void open_with_buffers(const std::vector<std::vector<scap_evt*>>& queues,
	                       bool eof_when_empty = false) {
		m_queues = queues;
		m_buffer_events.clear();
		m_buffer_descs.clear();
		for(auto& queue : m_queues) {
			m_buffer_events.emplace_back();
			for(auto* evt : queue) {
				m_buffer_events.back().push_back(reinterpret_cast<ppm_evt_hdr*>(evt));
			}
		}
		for(auto& events : m_buffer_events) {
			m_buffer_descs.push_back({events.data(), events.size(), eof_when_empty ? 1 : 0});
		}
		m_input_buffers.buffers = m_buffer_descs.data();
		m_input_buffers.n_buffers = static_cast<uint16_t>(m_buffer_descs.size());
		m_inspector.open_test_input(&m_test_data, &m_input_buffers, SINSP_MODE_TEST);
	}

	// Everything that the parsing of an event is expected to make visible, in one string.
	static std::string snapshot(sinsp_evt* evt) {
		std::ostringstream out;
		out << evt->get_num() << "|" << evt->get_ts() << "|" << evt->get_tid() << "|"
		    << evt->get_type() << "|" << evt->get_name() << "|";
		if(auto* tinfo = evt->get_thread_info(); tinfo != nullptr) {
			out << tinfo->m_comm << "|" << tinfo->m_pid << "|" << tinfo->is_dead() << "|";
		}
		if(auto* fdinfo = evt->get_fd_info(); fdinfo != nullptr) {
			out << fdinfo->m_name << "|" << evt->get_fd_num();
		}
		return out.str();
	}

	// Reads everything the given reader offers, up to the first non-event result.
	template<typename NextFn>
	static std::vector<std::string> read_all(NextFn next) {
		std::vector<std::string> out;
		for(int i = 0; i < 1000; i++) {
			sinsp_evt* evt = nullptr;
			const int32_t rc = next(&evt);
			if(rc == SCAP_FILTERED_EVENT) {
				continue;
			}
			if(rc != SCAP_SUCCESS) {
				break;
			}
			out.push_back(snapshot(evt));
		}
		return out;
	}

	std::vector<scap_evt*> m_owned;
	std::vector<std::vector<scap_evt*>> m_queues;
	std::vector<std::vector<ppm_evt_hdr*>> m_buffer_events;
	std::vector<scap_test_input_buffer> m_buffer_descs;
	scap_test_input_buffers m_input_buffers{};
};

}  // namespace

// The default buffer is what `next(evt)` has always been: reading with the explicit default handle
// gives the same events with the same parsing results.
TEST_F(sinsp_buffer_test, default_buffer_matches_next) {
	add_threads();
	std::vector<scap_evt*> events = {make_open(tid_a, 5, "/tmp/a"),
	                                 make_open(tid_a, 6, "/tmp/b"),
	                                 make_close(tid_a, 5),
	                                 make_proc_exit(tid_a),
	                                 make_open(tid_b, 7, "/tmp/c")};

	// Reader 1: the fixture inspector, `next(evt)`. Reader 2: another inspector with a copy of the
	// same input, explicit default handle.
	std::vector<ppm_evt_hdr*> hdrs1, hdrs2;
	for(auto* evt : events) {
		hdrs1.push_back(reinterpret_cast<ppm_evt_hdr*>(copy_event(evt)));
		hdrs2.push_back(reinterpret_cast<ppm_evt_hdr*>(copy_event(evt)));
	}
	scap_test_input_data data2 = m_test_data;
	m_test_data.events = hdrs1.data();
	m_test_data.event_count = hdrs1.size();
	data2.events = hdrs2.data();
	data2.event_count = hdrs2.size();

	open_inspector();
	sinsp second(true);
	second.open_test_input(&data2, SINSP_MODE_TEST);

	const auto expected = read_all([&](sinsp_evt** evt) { return m_inspector.next(evt); });
	const auto actual = read_all(
	        [&](sinsp_evt** evt) { return second.next(evt, SINSP_INVALID_BUFFER_HANDLE); });

	ASSERT_EQ(expected.size(), events.size());
	ASSERT_EQ(actual, expected);
	ASSERT_EQ(second.get_tid_to_remove(), m_inspector.get_tid_to_remove());
}

// A reserved handle fed by a test_input queue yields the same events and the same parsing results
// as the single stream does.
TEST_F(sinsp_buffer_test, reserved_handle_matches_the_single_stream) {
	add_threads();
	std::vector<scap_evt*> events = {make_open(tid_a, 5, "/tmp/a"),
	                                 make_open(tid_a, 6, "/tmp/b"),
	                                 make_close(tid_a, 5),
	                                 make_proc_exit(tid_a),
	                                 make_open(tid_b, 7, "/tmp/c")};

	std::vector<ppm_evt_hdr*> hdrs;
	std::vector<scap_evt*> queue;
	for(auto* evt : events) {
		hdrs.push_back(reinterpret_cast<ppm_evt_hdr*>(copy_event(evt)));
		queue.push_back(copy_event(evt));
	}
	scap_test_input_data data2 = m_test_data;
	m_test_data.events = hdrs.data();
	m_test_data.event_count = hdrs.size();
	data2.events = nullptr;
	data2.event_count = 0;

	open_inspector();
	sinsp second(true);
	// Same as open_with_buffers, for another inspector.
	std::vector<ppm_evt_hdr*> queue_hdrs;
	for(auto* evt : queue) {
		queue_hdrs.push_back(reinterpret_cast<ppm_evt_hdr*>(evt));
	}
	scap_test_input_buffer desc{queue_hdrs.data(), queue_hdrs.size(), 1};
	scap_test_input_buffers buffers{&desc, 1};
	second.open_test_input(&data2, &buffers, SINSP_MODE_TEST);

	const auto h = second.reserve_buffer_handle();
	ASSERT_NE(h, SINSP_INVALID_BUFFER_HANDLE);

	const auto expected = read_all([&](sinsp_evt** evt) { return m_inspector.next(evt); });
	const auto actual = read_all([&](sinsp_evt** evt) { return second.next(evt, h); });

	ASSERT_EQ(expected.size(), events.size());
	ASSERT_EQ(actual, expected);
	ASSERT_EQ(second.get_tid_to_remove(h), m_inspector.get_tid_to_remove());
}

TEST_F(sinsp_buffer_test, handles_are_limited_to_the_configured_buffers) {
	add_threads();
	open_with_buffers({{make_open(tid_a, 5, "/tmp/a")}, {make_open(tid_b, 6, "/tmp/b")}});

	ASSERT_EQ(m_inspector.get_num_allocated_buffer_handles(), 2);
	const auto h1 = m_inspector.reserve_buffer_handle();
	const auto h2 = m_inspector.reserve_buffer_handle();
	ASSERT_NE(h1, SINSP_INVALID_BUFFER_HANDLE);
	ASSERT_NE(h2, SINSP_INVALID_BUFFER_HANDLE);
	ASSERT_NE(h1, h2);
	ASSERT_THROW(m_inspector.reserve_buffer_handle(), sinsp_exception);

	sinsp_evt* evt = nullptr;
	ASSERT_THROW(m_inspector.next(&evt, static_cast<sinsp_buffer_t>(h2 + 1)), sinsp_exception);
	ASSERT_THROW(m_inspector.get_parser(static_cast<sinsp_buffer_t>(h2 + 1)), sinsp_exception);
}

TEST_F(sinsp_buffer_test, no_handles_without_buffers) {
	add_threads();
	open_inspector();

	ASSERT_EQ(m_inspector.get_num_allocated_buffer_handles(), 0);
	ASSERT_THROW(m_inspector.reserve_buffer_handle(), sinsp_exception);
}

TEST_F(sinsp_buffer_test, handles_need_an_open_capture) {
	ASSERT_EQ(m_inspector.get_num_allocated_buffer_handles(), 0);
	ASSERT_THROW(m_inspector.reserve_buffer_handle(), sinsp_exception);
}

// Each reserved handle reads its own queue, in order, whatever the order of the calls is. The
// single stream is not consumed by the reads of the buffers.
TEST_F(sinsp_buffer_test, buffers_read_their_own_events) {
	add_threads();
	add_event(increasing_ts(),
	          tid_a,
	          PPME_SYSCALL_OPEN_X,
	          6,
	          (int64_t)9,
	          "/tmp/stream",
	          (uint32_t)0,
	          (uint32_t)0,
	          (uint32_t)0,
	          (uint64_t)0);
	open_with_buffers({{make_open(tid_a, 5, "/tmp/a1"), make_open(tid_a, 6, "/tmp/a2")},
	                   {make_open(tid_b, 7, "/tmp/b1")}},
	                  true);

	const auto h1 = m_inspector.reserve_buffer_handle();
	const auto h2 = m_inspector.reserve_buffer_handle();

	sinsp_evt* evt = nullptr;
	ASSERT_EQ(m_inspector.next(&evt, h2), SCAP_SUCCESS);
	ASSERT_EQ(evt->get_tid(), tid_b);
	ASSERT_EQ(m_inspector.next(&evt, h1), SCAP_SUCCESS);
	ASSERT_EQ(evt->get_tid(), tid_a);
	ASSERT_EQ(evt->get_fd_info()->m_name, "/tmp/a1");
	ASSERT_EQ(m_inspector.next(&evt, h1), SCAP_SUCCESS);
	ASSERT_EQ(evt->get_fd_info()->m_name, "/tmp/a2");
	ASSERT_EQ(m_inspector.next(&evt, h1), SCAP_EOF);
	ASSERT_EQ(m_inspector.next(&evt, h2), SCAP_EOF);

	// The default buffer still has its own event.
	ASSERT_EQ(m_inspector.next(&evt), SCAP_SUCCESS);
	ASSERT_EQ(evt->get_fd_info()->m_name, "/tmp/stream");
}

TEST_F(sinsp_buffer_test, an_empty_buffer_times_out_without_affecting_the_others) {
	add_threads();
	open_with_buffers({{}, {make_open(tid_b, 7, "/tmp/b1")}});

	const auto h1 = m_inspector.reserve_buffer_handle();
	const auto h2 = m_inspector.reserve_buffer_handle();

	sinsp_evt* evt = nullptr;
	ASSERT_EQ(m_inspector.next(&evt, h1), SCAP_TIMEOUT);
	ASSERT_EQ(m_inspector.next(&evt, h2), SCAP_SUCCESS);
	ASSERT_EQ(evt->get_tid(), tid_b);
}

// Two buffers do not share the state that parsing an event writes: the parser (and its scratch
// event), the event returned to the caller and the verdict of the last event.
TEST_F(sinsp_buffer_test, parser_state_is_per_buffer) {
	add_threads();
	open_with_buffers({{make_open(tid_a, 5, "/tmp/a"), make_proc_exit(tid_a)},
	                   {make_open(tid_b, 6, "/tmp/b"), make_open(tid_b, 7, "/tmp/b2")}});

	const auto h1 = m_inspector.reserve_buffer_handle();
	const auto h2 = m_inspector.reserve_buffer_handle();

	ASSERT_NE(m_inspector.get_parser(h1), nullptr);
	ASSERT_NE(m_inspector.get_parser(h2), nullptr);
	ASSERT_NE(m_inspector.get_parser(h1), m_inspector.get_parser(h2));
	ASSERT_NE(m_inspector.get_parser(h1), m_inspector.get_parser());
	ASSERT_NE(m_inspector.get_parser(h2), m_inspector.get_parser());

	// The events returned for two buffers are distinct objects and stay valid together.
	sinsp_evt* evt1 = nullptr;
	sinsp_evt* evt2 = nullptr;
	ASSERT_EQ(m_inspector.next(&evt1, h1), SCAP_SUCCESS);
	ASSERT_EQ(m_inspector.next(&evt2, h2), SCAP_SUCCESS);
	ASSERT_NE(evt1, evt2);
	ASSERT_NE(evt1->get_scap_evt(), evt2->get_scap_evt());
	ASSERT_EQ(evt1->get_tid(), tid_a);
	ASSERT_EQ(evt1->get_fd_info()->m_name, "/tmp/a");
	ASSERT_EQ(evt2->get_tid(), tid_b);
	ASSERT_EQ(evt2->get_fd_info()->m_name, "/tmp/b");

	// A verdict set while parsing on a buffer stays on that buffer. The thread removal it asks for
	// is carried out by the next call on the same buffer, not by a call on another one.
	ASSERT_EQ(m_inspector.get_tid_to_remove(h1), -1);
	ASSERT_EQ(m_inspector.next(&evt1, h1), SCAP_SUCCESS);
	ASSERT_EQ(evt1->get_type(), PPME_PROCEXIT_1_E);
	ASSERT_EQ(m_inspector.get_tid_to_remove(h1), tid_a);
	ASSERT_EQ(m_inspector.get_tid_to_remove(h2), -1);
	ASSERT_EQ(m_inspector.get_tid_to_remove(), -1);

	ASSERT_EQ(m_inspector.next(&evt2, h2), SCAP_SUCCESS);
	ASSERT_EQ(evt2->get_fd_info()->m_name, "/tmp/b2");
	ASSERT_EQ(m_inspector.get_tid_to_remove(h1), tid_a);
	ASSERT_EQ(m_inspector.get_tid_to_remove(h2), -1);
}

TEST_F(sinsp_buffer_test, connection_status_tracking_applies_to_every_buffer) {
	add_threads();
	open_with_buffers({{make_open(tid_a, 5, "/tmp/a")}, {make_open(tid_b, 6, "/tmp/b")}});

	const auto h1 = m_inspector.reserve_buffer_handle();
	ASSERT_FALSE(m_inspector.get_parser(h1)->get_track_connection_status());

	m_inspector.set_track_connection_status(true);
	const auto h2 = m_inspector.reserve_buffer_handle();
	ASSERT_TRUE(m_inspector.get_track_connection_status());
	ASSERT_TRUE(m_inspector.get_parser()->get_track_connection_status());
	ASSERT_TRUE(m_inspector.get_parser(h1)->get_track_connection_status());
	ASSERT_TRUE(m_inspector.get_parser(h2)->get_track_connection_status());

	m_inspector.set_track_connection_status(false);
	ASSERT_FALSE(m_inspector.get_parser(h1)->get_track_connection_status());
	ASSERT_FALSE(m_inspector.get_parser(h2)->get_track_connection_status());
}
