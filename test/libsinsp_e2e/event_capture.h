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

#pragma once

#include "libsinsp_test_var.h"

#include <gtest/gtest.h>

#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <libsinsp/sinsp.h>

#include <functional>
#include <mutex>
#include <stdexcept>
#include <utility>

// Just a stupid fake FD value to signal to stop capturing events from driver and exit.
// Note: we don't use it through eventfd because we want to make sure
// that we received all events from the driver, until this very last close(FD_SIGNAL_STOP);
#define FD_SIGNAL_STOP 555

// eventfd inter-thread requests
typedef enum : std::uint8_t {
	E2E_REQ_STOP_CAPTURE = 1,
	E2E_REQ_START_CAPTURE = 2,
	E2E_REQ_SUPPRESS_SH = 3,
	E2E_REQ_SUPPRESS = 4,
} e2e_req_t;

class callback_param {
public:
	sinsp_evt* m_evt;
	sinsp* m_inspector;
};

typedef std::function<void(sinsp* inspector)> before_open_t;
typedef std::function<void(sinsp* inspector)> before_close_t;
typedef std::function<bool(sinsp_evt* evt)> event_filter_t;
typedef std::function<void(const callback_param& param)> captured_event_callback_t;

typedef std::function<void()> run_callback_t;

class event_capture {
public:
	event_capture(sinsp_mode_t mode,
	              captured_event_callback_t captured_event_callback,
	              before_open_t before_open,
	              before_close_t before_close,
	              event_filter_t filter,
	              uint32_t max_thread_table_size,
	              uint64_t thread_timeout_ns,
	              uint64_t inactive_thread_scan_time_ns,
	              uint64_t max_timeouts);
	~event_capture();

	void start(bool dump);
	void stop();
	void capture();

	static void do_nothing(sinsp* inspector) {}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_open_t before_open = event_capture::do_nothing,
	                before_close_t before_close = event_capture::do_nothing,
	                uint32_t max_thread_table_size = 131072,
	                uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                sinsp_mode_t mode = SINSP_MODE_LIVE,
	                uint64_t max_timeouts = 3,
	                bool dump = true) {
		event_capture capturing(mode,
		                        std::move(captured_event_callback),
		                        std::move(before_open),
		                        std::move(before_close),
		                        std::move(filter),
		                        max_thread_table_size,
		                        thread_timeout_ns,
		                        inactive_thread_scan_time_ns,
		                        max_timeouts);

		capturing.start(dump);

		std::thread thread([&run_function]() {
			usleep(50);
			run_function();
			// signal main thread to end the capture
			close(FD_SIGNAL_STOP);
		});

		capturing.capture();
		thread.join();

		capturing.stop();
	}

	static void do_request(e2e_req_t req);

	static void set_engine(const std::string& engine_string, const std::string& engine_path);
	static const std::string& get_engine();
	static void set_buffer_dim(const unsigned long& dim);
	static const std::string& get_engine_path();
	static std::string s_engine_string;
	static std::string s_engine_path;
	static unsigned long s_buffer_dim;

private:
	bool handle_request();
	bool handle_event(sinsp_evt* event);

	void open_engine(const std::string& engine_string,
	                 libsinsp::events::set<ppm_sc_code> events_sc_codes);

	std::unique_ptr<sinsp> m_inspector;
	std::unique_ptr<sinsp_cycledumper> m_dumper;
	event_filter_t m_filter;
	captured_event_callback_t m_captured_event_callback;
	before_open_t m_before_open;
	before_close_t m_before_close;
	callback_param m_param{};
	sinsp_mode_t m_mode;
	uint64_t m_max_timeouts{};

	static int s_eventfd;
};
