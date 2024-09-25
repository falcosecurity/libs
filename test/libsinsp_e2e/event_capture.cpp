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

#include "event_capture.h"

#include <gtest/gtest.h>

#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include <libsinsp/sinsp_cycledumper.h>
#include <unistd.h>
#include <sys/eventfd.h>

std::string event_capture::s_engine_string = KMOD_ENGINE;
std::string event_capture::s_engine_path;
unsigned long event_capture::s_buffer_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
int event_capture::s_eventfd = -1;

event_capture::event_capture(sinsp_mode_t mode,
                             captured_event_callback_t captured_event_callback,
                             before_open_t before_open,
                             before_close_t before_close,
                             event_filter_t filter,
                             uint32_t max_thread_table_size,
                             uint64_t thread_timeout_ns,
                             uint64_t inactive_thread_scan_time_ns,
                             uint64_t max_timeouts) {
	m_mode = mode;

	m_captured_event_callback = std::move(captured_event_callback);
	m_before_open = std::move(before_open);
	m_before_close = std::move(before_close);
	m_filter = std::move(filter);
	m_max_timeouts = max_timeouts;

	s_eventfd = eventfd(0, EFD_NONBLOCK);
	m_inspector = std::make_unique<sinsp>();
	m_inspector->m_thread_manager->set_max_thread_table_size(max_thread_table_size);
	m_inspector->m_thread_timeout_ns = thread_timeout_ns;
	m_inspector->set_auto_threads_purging_interval_s(inactive_thread_scan_time_ns);
	m_inspector->set_auto_threads_purging(false);
	m_inspector->set_get_procs_cpu_from_driver(true);
	m_inspector->set_debug_mode(true);
	m_inspector->set_hostname_and_port_resolution_mode(false);

	m_param.m_inspector = m_inspector.get();
}

event_capture::~event_capture() {
	close(s_eventfd);
	s_eventfd = -1;
}

void event_capture::start(bool dump) {
	open_engine(event_capture::get_engine(), {});

	const ::testing::TestInfo* const test_info =
	        ::testing::UnitTest::GetInstance()->current_test_info();
	if(dump) {
		auto dump_filename = std::string(LIBSINSP_TEST_CAPTURES_PATH) +
		                     test_info->test_case_name() + "_" + test_info->name() + ".scap";
		m_dumper = std::make_unique<sinsp_cycledumper>(m_inspector.get(),
		                                               dump_filename.c_str(),
		                                               0,
		                                               0,
		                                               0,
		                                               0,
		                                               true);
	}

	m_before_open(m_inspector.get());
	m_inspector->start_capture();
}

void event_capture::stop() {
	// Begin teardown synchronized section
	m_before_close(m_inspector.get());

	m_inspector->stop_capture();
	if(m_dumper != nullptr) {
		m_dumper->close();
	}
}

void event_capture::capture() {
	sinsp_evt* event;
	bool result = true;
	int32_t next_result = SCAP_SUCCESS;

	uint32_t n_timeouts = 0;
	while(result && !::testing::Test::HasFatalFailure()) {
		if(handle_request()) {
			continue;
		}

		next_result = m_inspector->next(&event);
		if(next_result == SCAP_TIMEOUT) {
			n_timeouts++;

			if(n_timeouts < m_max_timeouts) {
				continue;
			} else {
				break;
			}
		}

		if(next_result == SCAP_FILTERED_EVENT) {
			continue;
		}
		if(next_result != SCAP_SUCCESS) {
			break;
		}
		if(m_dumper != nullptr) {
			m_dumper->dump(event);
		}
		result = handle_event(event);
	}
}

// Returns true if the current iteration can be skipped
bool event_capture::handle_request() {
	eventfd_t req;
	int ret = eventfd_read(s_eventfd, &req);
	if(ret == 0) {
		// manage request
		switch(req) {
		case E2E_REQ_STOP_CAPTURE: {
			m_inspector->stop_capture();
			int oldfl;
			oldfl = fcntl(s_eventfd, F_GETFL);
			// Drop the nonblock mode on the FD to avoid busy loop;
			// instead, main loop will block until start_capture is requested
			fcntl(s_eventfd, F_SETFL, oldfl & ~O_NONBLOCK);
			return true;
		}
		case E2E_REQ_START_CAPTURE: {
			m_inspector->start_capture();
			int oldfl;
			oldfl = fcntl(s_eventfd, F_GETFL);
			// Reset the O_NONBLOCK flag to avoid the blocking read from the eventfd.
			fcntl(s_eventfd, F_SETFL, oldfl | O_NONBLOCK);
			break;
		}
		case E2E_REQ_SUPPRESS_SH:
			m_inspector->suppress_events_comm("test_helper.sh");
			break;
		case E2E_REQ_SUPPRESS:
			m_inspector->suppress_events_comm("test_helper");
			break;
		default:
			break;
		}
	}
	return false;
}

bool event_capture::handle_event(sinsp_evt* event) {
	bool res = true;

	// Signal to exit!
	if(event->get_type() == PPME_SYSCALL_CLOSE_E &&
	   event->get_param(0)->as<int64_t>() == FD_SIGNAL_STOP) {
		return false;
	}

	if(::testing::Test::HasNonfatalFailure()) {
		return true;
	}

	if(m_filter(event)) {
		try {
			m_param.m_evt = event;
			m_captured_event_callback(m_param);
		} catch(...) {
			res = false;
		}
	}
	if(!res || ::testing::Test::HasNonfatalFailure()) {
		std::cerr << "failed on event " << event->get_num() << '\n';
	}
	return res;
}

void event_capture::open_engine(const std::string& engine_string,
                                libsinsp::events::set<ppm_sc_code> events_sc_codes) {
	if(false) {
	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE)) {
		m_inspector->open_kmod(s_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE)) {
		if(event_capture::get_engine().empty()) {
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine"
			          << std::endl;
			exit(EXIT_FAILURE);
		}
		m_inspector->open_bpf(event_capture::get_engine_path(), s_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE)) {
		m_inspector->open_modern_bpf(s_buffer_dim);
	}
#endif
	else {
		std::cerr << "Unknown engine" << '\n';
		exit(EXIT_FAILURE);
	}
}

void event_capture::set_engine(const std::string& engine_string, const std::string& engine_path) {
	s_engine_string = engine_string;
	s_engine_path = engine_path;
}

void event_capture::set_buffer_dim(const unsigned long& dim) {
	s_buffer_dim = dim;
}

const std::string& event_capture::get_engine() {
	return s_engine_string;
}

const std::string& event_capture::get_engine_path() {
	return s_engine_path;
}

void event_capture::do_request(e2e_req_t req) {
	eventfd_write(s_eventfd, req);
	// Wait for the request to be caught by the main thread
	usleep(50);
}
