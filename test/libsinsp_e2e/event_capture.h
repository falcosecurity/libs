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

class callback_param
{
public:
	sinsp_evt* m_evt;
	sinsp* m_inspector;
};

typedef std::function<void(sinsp* inspector)> before_open_t;
typedef std::function<void(sinsp* inspector)> before_close_t;
typedef std::function<bool(sinsp_evt* evt)> event_filter_t;
typedef std::function<void(const callback_param& param)> captured_event_callback_t;

// Returns true/false to indicate whether the capture should continue
// or stop
typedef std::function<bool()> capture_continue_t;

typedef std::function<void(sinsp* inspector)> run_callback_t;

class event_capture
{
public:
	void capture();
	void stop_capture();
	void wait_for_capture_start();
	void wait_for_capture_stop();

	static void do_nothing(sinsp* inspector) {}

	static bool always_continue() { return true; }

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_open_t before_open)
	{
		run(run_function,
		    captured_event_callback,
		    filter,
		    131072,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    SINSP_MODE_LIVE,
		    before_open);
	}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_open_t before_open,
	                before_close_t before_close)
	{
		run(run_function,
		    captured_event_callback,
		    filter,
		    131072,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    SINSP_MODE_LIVE,
		    before_open,
		    before_close);
	}

	static void run(run_callback_t run_function, captured_event_callback_t captured_event_callback)
	{
		event_filter_t no_filter = [](sinsp_evt*) { return true; };
		run(run_function, captured_event_callback, no_filter);
	}

	static void run_nodriver(run_callback_t run_function,
	                         captured_event_callback_t captured_event_callback)
	{
		event_filter_t no_filter = [](sinsp_evt*) { return true; };

		run(run_function,
		    captured_event_callback,
		    no_filter,
		    131072,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    (uint64_t)60 * 1000 * 1000 * 1000,
		    SINSP_MODE_NODRIVER);
	}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                uint32_t max_thread_table_size = 131072,
	                uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                sinsp_mode_t mode = SINSP_MODE_LIVE,
	                before_open_t before_open = event_capture::do_nothing,
	                before_close_t before_close = event_capture::do_nothing,
	                capture_continue_t capture_continue = event_capture::always_continue,
	                uint64_t max_timeouts = 3)
	{
		event_capture capturing;
		capturing.m_mode = mode;
		capturing.m_captured_event_callback = captured_event_callback;
		capturing.m_before_open = before_open;
		capturing.m_before_close = before_close;
		capturing.m_capture_continue = capture_continue;
		capturing.m_filter = filter;
		capturing.m_max_thread_table_size = max_thread_table_size;
		capturing.m_thread_timeout_ns = thread_timeout_ns;
		capturing.m_inactive_thread_scan_time_ns = inactive_thread_scan_time_ns;
		capturing.m_max_timeouts = max_timeouts;


		std::thread thread([&capturing]() {
			capturing.capture();
		});

		capturing.wait_for_capture_start();

		if (!capturing.m_start_failed)
		{
			run_function(capturing.m_inspector);
			capturing.stop_capture();
			capturing.wait_for_capture_stop();
		}
		else
		{
			GTEST_MESSAGE_(capturing.m_start_failure_message.c_str(),
			               ::testing::TestPartResult::kFatalFailure);
		}

		thread.join();
	}

	static void set_engine(const std::string& engine_string, const std::string& engine_path);
	static const std::string& get_engine();
	static void set_buffer_dim(const unsigned long& dim);
	static const std::string& get_engine_path();
	static std::string m_engine_string;
	static std::string m_engine_path;
	static unsigned long m_buffer_dim;

private:
	event_capture()
	    : m_capture_started(false),
	      m_capture_stopped(false),
	      m_start_failed(false)
	{
	}

	void re_read_dump_file();

	bool handle_event(sinsp_evt* event);

	void open_engine(const std::string& engine_string, libsinsp::events::set<ppm_sc_code> events_sc_codes);

	std::mutex m_mutex;
    std::condition_variable m_condition_started;
    std::condition_variable m_condition_stopped;
    bool m_capture_started;
    bool m_capture_stopped;

	event_filter_t m_filter;
	captured_event_callback_t m_captured_event_callback;
	before_open_t m_before_open;
	before_close_t m_before_close;
	capture_continue_t m_capture_continue;
	uint32_t m_max_thread_table_size;
	uint64_t m_thread_timeout_ns;
	uint64_t m_inactive_thread_scan_time_ns;
	bool m_start_failed;
	std::string m_start_failure_message;
	std::string m_dump_filename;
	callback_param m_param;
	sinsp* m_inspector;
	sinsp_mode_t m_mode;
	uint64_t m_max_timeouts;
};
