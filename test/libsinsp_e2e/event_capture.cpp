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
unsigned long event_capture::s_buffer_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM * 4;

event_capture::event_capture(captured_event_callback_t captured_event_callback,
                             before_open_t before_open,
                             before_capture_t before_capture,
                             after_capture_t before_close,
                             event_filter_t filter,
                             uint32_t max_thread_table_size,
                             uint64_t thread_timeout_ns,
                             uint64_t inactive_thread_scan_time_ns) {
	m_captured_event_callback = std::move(captured_event_callback);
	m_before_open = std::move(before_open);
	m_before_capture = std::move(before_capture);
	m_after_capture = std::move(before_close);
	m_filter = std::move(filter);

	m_eventfd = -1;
	m_leaving = false;

	m_inspector = std::make_unique<sinsp>();
	m_inspector->m_thread_manager->set_max_thread_table_size(max_thread_table_size);
	m_inspector->m_thread_timeout_ns = thread_timeout_ns;
	m_inspector->set_auto_threads_purging_interval_s(inactive_thread_scan_time_ns);
	m_inspector->set_auto_threads_purging(false);
	m_inspector->set_debug_mode(true);
	m_inspector->set_hostname_and_port_resolution_mode(false);

	m_param.m_inspector = m_inspector.get();
}

void event_capture::start(bool dump, libsinsp::events::set<ppm_sc_code>& sc_set) {
	m_eventfd = eventfd(0, EFD_NONBLOCK);

	// To avoid back-pressure on the eventfd reads, do not attach them.
	if(sc_set.empty()) {
		for(int i = 0; i < PPM_SC_MAX; i++) {
			auto sc_code = (ppm_sc_code)i;
			if(sc_code != PPM_SC_READ && sc_code != PPM_SC_READV) {
				sc_set.insert(sc_code);
			}
		}
	}
	m_before_open(m_inspector.get());
	open_engine(event_capture::get_engine(), sc_set);

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

	m_before_capture(m_inspector.get());
	m_inspector->start_capture();
}

void event_capture::stop() {
	close(m_eventfd);
	m_inspector->stop_capture();
	m_after_capture(m_inspector.get());
	if(m_dumper != nullptr) {
		m_dumper->close();
	}
	m_inspector->close();
}

void event_capture::capture() {
	sinsp_evt* event;
	bool result = true;
	int32_t next_result = SCAP_SUCCESS;

	/*
	 * Loop until:
	 * * test has non fatal failures
	 * * handle_event returns true
	 * * we weren't asked to leave from eventfd and we received !SCAP_SUCCESS
	 */
	while(result && !::testing::Test::HasFatalFailure()) {
		handle_eventfd_request();
		next_result = m_inspector->next(&event);
		if(next_result == SCAP_FILTERED_EVENT) {
			continue;
		}
		if(next_result == SCAP_SUCCESS) {
			if(m_dumper != nullptr) {
				m_dumper->dump(event);
			}
			result = handle_event(event);
		} else if(m_leaving) {
			break;
		}
	}

	/*
	 * Second loop to empty the buffers from all the generated events:
	 * * loop until SCAP_TIMEOUT is received.
	 */
	result = true;
	while(result) {
		next_result = m_inspector->next(&event);
		if(next_result == SCAP_SUCCESS) {
			if(m_dumper != nullptr) {
				m_dumper->dump(event);
			}
			result = handle_event(event);
		} else if(next_result == SCAP_TIMEOUT) {
			break;
		}
	}

	auto capture_stats_str = capture_stats(m_inspector.get());
	std::cout << capture_stats_str << "\n";
}

bool event_capture::handle_event(sinsp_evt* event) {
	bool res = true;

	if(::testing::Test::HasNonfatalFailure()) {
		return res;
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

// Returns true if any request has been satisfied
bool event_capture::handle_eventfd_request() {
	eventfd_t req;
	int ret = eventfd_read(m_eventfd, &req);
	if(ret == 0) {
		// manage request
		switch(req) {
		case EVENTFD_SIGNAL_STOP:
			m_inspector->stop_capture();
			m_leaving = true;
			return true;
		default:
			break;
		}
	}
	return false;
}

std::string event_capture::capture_stats(sinsp* inspector) {
	scap_stats st;
	inspector->get_capture_stats(&st);

	std::stringstream ss;

	ss << "capture stats: dropped=" << st.n_drops << " buf=" << st.n_drops_buffer
	   << " pf=" << st.n_drops_pf << " bug=" << st.n_drops_bug;

	return ss.str();
}

void event_capture::open_engine(const std::string& engine_string,
                                libsinsp::events::set<ppm_sc_code> events_sc_codes) {
	if(false) {
	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE)) {
		m_inspector->open_kmod(s_buffer_dim, events_sc_codes);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE)) {
		if(event_capture::get_engine().empty()) {
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine"
			          << '\n';
			exit(EXIT_FAILURE);
		}
		m_inspector->open_bpf(event_capture::get_engine_path(), s_buffer_dim, events_sc_codes);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE)) {
		m_inspector->open_modern_bpf(s_buffer_dim,
		                             DEFAULT_CPU_FOR_EACH_BUFFER,
		                             true,
		                             events_sc_codes);
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
