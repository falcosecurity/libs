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

#include <cinttypes>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <libsinsp/sinsp.h>

#include <functional>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <sys/eventfd.h>
#include <thread>

// Just a stupid fake FD value to signal to stop capturing events from driver and exit.
// Note: we don't use it through eventfd because we want to make sure
// that we received all events from the driver, until this very last close(FD_SIGNAL_STOP);
#define EVENTFD_SIGNAL_STOP 1

class callback_param {
public:
	sinsp_evt* m_evt;
	sinsp* m_inspector;
};

// Right before inspector->start_capture() gets called.
// Engine is already opened (thus scap handle is already alive).
typedef std::function<void(sinsp* inspector)> before_capture_t;
// Right after inspector->stop_capture() gets called.
// Engine is still opened (thus scap handle is still alive).
typedef std::function<void(sinsp* inspector)> after_capture_t;
// Only events matching the filter function are passed to the captured_event_callback_t.
typedef std::function<bool(sinsp_evt* evt)> event_filter_t;
// On event callback
typedef std::function<void(const callback_param& param)> captured_event_callback_t;
typedef std::function<void(sinsp* inspector)> run_callback_t;
typedef std::function<void()> run_callback_async_t;

class event_capture {
public:
	event_capture(captured_event_callback_t captured_event_callback,
	              before_capture_t before_open,
	              after_capture_t before_close,
	              event_filter_t filter,
	              uint32_t max_thread_table_size,
	              uint64_t thread_timeout_ns,
	              uint64_t inactive_thread_scan_time_ns);

	void start(bool dump, libsinsp::events::set<ppm_sc_code>& sc_set);
	void stop();
	void capture();

	static void do_nothing(sinsp* inspector) {}

	/*!
	  \brief Run `run_function` synchronously, and
	  then loop on all events calling filter on them,
	  and, for any event that matches the filter,
	  calls captured_event_callback.
	  Before starting the capture, before_open is called.
	  After closing the capture, before_close is called.
	  The default ppm_sc_set is the whole set minus `read` and `readv`.
	*/
	static void run(const run_callback_t& run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_capture_t before_open = event_capture::do_nothing,
	                after_capture_t before_close = event_capture::do_nothing,
	                libsinsp::events::set<ppm_sc_code> sc_set = {},
	                uint32_t max_thread_table_size = 131072,
	                uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                bool dump = true) {
		event_capture capturing(std::move(captured_event_callback),
		                        std::move(before_open),
		                        std::move(before_close),
		                        std::move(filter),
		                        max_thread_table_size,
		                        thread_timeout_ns,
		                        inactive_thread_scan_time_ns);

		capturing.start(dump, sc_set);

		run_function(capturing.m_inspector.get());
		// signal main thread to end the capture
		eventfd_write(capturing.m_eventfd, EVENTFD_SIGNAL_STOP);

		capturing.capture();

		capturing.stop();
	}

	/*!
	  \brief Run `run_function` **asynchronously**, while
	  looping on all events calling filter on them,
	  and, for any event that matches the filter,
	  calls captured_event_callback.
	  Before starting the capture, before_open is called.
	  After closing the capture, before_close is called.
	  The default ppm_sc_set is the whole set minus `read` and `readv`.
	*/
	static void run(const run_callback_async_t& run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_capture_t before_open = event_capture::do_nothing,
	                after_capture_t before_close = event_capture::do_nothing,
	                libsinsp::events::set<ppm_sc_code> sc_set = {},
	                uint32_t max_thread_table_size = 131072,
	                uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                bool dump = true) {
		event_capture capturing(std::move(captured_event_callback),
		                        std::move(before_open),
		                        std::move(before_close),
		                        std::move(filter),
		                        max_thread_table_size,
		                        thread_timeout_ns,
		                        inactive_thread_scan_time_ns);

		capturing.start(dump, sc_set);

		std::thread thread([&run_function, &capturing]() {
			run_function();
			// signal main thread to end the capture
			eventfd_write(capturing.m_eventfd, EVENTFD_SIGNAL_STOP);
		});

		capturing.capture();
		thread.join();

		capturing.stop();
	}

	static void set_engine(const std::string& engine_string, const std::string& engine_path);
	static const std::string& get_engine();
	static void set_buffer_dim(const unsigned long& dim);
	static const std::string& get_engine_path();

	static std::string capture_stats(sinsp* inspector);

	static std::string s_engine_string;
	static std::string s_engine_path;
	static unsigned long s_buffer_dim;

private:
	bool handle_event(sinsp_evt* event);
	bool handle_eventfd_request();

	void open_engine(const std::string& engine_string,
	                 libsinsp::events::set<ppm_sc_code> events_sc_codes);

	std::unique_ptr<sinsp> m_inspector;
	std::unique_ptr<sinsp_cycledumper> m_dumper;
	event_filter_t m_filter;
	captured_event_callback_t m_captured_event_callback;
	before_capture_t m_before_capture;
	after_capture_t m_after_capture;
	callback_param m_param{};
	int m_eventfd;
	bool m_leaving;
};
