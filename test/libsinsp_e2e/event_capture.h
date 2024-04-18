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

class concurrent_object_handle_state_error : public std::logic_error
{
	using std::logic_error::logic_error;
};

class event_capture;

/**
 * The concurrent_object_handle class encapsulates the task of accessing
 * event_capture::m_inspector in a thread-safe way, especially in the
 * run_callback_t functions passed to event_capture::run().
 */
template<typename T>
class concurrent_object_handle
{
	public:
		friend event_capture;

		/**
		 * Creates a new, unlocked handle with other's wrapped pointer and underlying mutex.
		 * @param other
		 */
		concurrent_object_handle(const concurrent_object_handle& other) noexcept
			: m_object_ptr(other.m_object_ptr),
			  m_object_lock(*other.m_object_lock.mutex(), std::defer_lock)
		{
		}

		void lock() { m_object_lock.lock(); }

		T* operator->()
		{
			if (!m_object_lock.owns_lock())
			{
				throw concurrent_object_handle_state_error(
					"Attempt to access wrapped object without obtaining a lock.");
			}
			return m_object_ptr;
		}

		inline T* safe_ptr() { return operator->(); }

		T& operator*()
		{
			if (!m_object_lock.owns_lock())
			{
				throw concurrent_object_handle_state_error(
					"Attempt to access wrapped object without obtaining a lock.");
			}
			return *m_object_ptr;
		}

		T* unsafe_ptr() { return m_object_ptr; }

		void unlock() { m_object_lock.unlock(); }

	private:
		concurrent_object_handle(sinsp* object_ptr, std::mutex& object_mutex)
			: m_object_ptr(object_ptr),
			  m_object_lock(object_mutex, std::defer_lock)
		{
		}

		T* m_object_ptr;
		std::unique_lock<std::mutex> m_object_lock;
};

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

typedef std::function<void(concurrent_object_handle<sinsp> inspector)> run_callback_t;

class event_capture
{
public:
	void init_inspector();
	void capture();
	void stop_capture();
	void wait_for_capture_start();
	void wait_for_capture_stop();

	static void do_nothing(sinsp* inspector) {}

	static bool always_continue() { return true; }

	sinsp* get_inspector()
	{
			static sinsp inspector = sinsp();
			return &inspector;
	}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter,
	                before_open_t before_open = event_capture::do_nothing,
	                before_close_t before_close = event_capture::do_nothing,
	                capture_continue_t capture_continue = event_capture::always_continue,
	                uint32_t max_thread_table_size = 131072,
	                uint64_t thread_timeout_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                uint64_t inactive_thread_scan_time_ns = (uint64_t)60 * 1000 * 1000 * 1000,
	                sinsp_mode_t mode = SINSP_MODE_LIVE,
	                uint64_t max_timeouts = 3)
	{
		event_capture capturing;
		{  // Synchronized section
			std::unique_lock<std::mutex> object_state_lock(capturing.m_object_state_mutex);
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
		}


		std::thread thread([&capturing]() {
			capturing.capture();
		});

		capturing.wait_for_capture_start();

		if (!capturing.m_start_failed.load())
		{
			run_function(capturing.get_inspector_handle());
			capturing.stop_capture();
			capturing.wait_for_capture_stop();
		}
		else
		{
			std::unique_lock<std::mutex> error_lookup_lock(capturing.m_object_state_mutex);
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

	concurrent_object_handle<sinsp> get_inspector_handle();

	void re_read_dump_file();

	bool handle_event(sinsp_evt* event);

	void open_engine(const std::string& engine_string, libsinsp::events::set<ppm_sc_code> events_sc_codes);

	std::mutex m_inspector_mutex;     // Always lock first
	std::mutex m_object_state_mutex;  // Always lock second
	std::condition_variable m_condition_started;
	std::condition_variable m_condition_stopped;
	bool m_capture_started;
	bool m_capture_stopped;
	std::atomic<bool> m_start_failed;

	event_filter_t m_filter;
	captured_event_callback_t m_captured_event_callback;
	before_open_t m_before_open;
	before_close_t m_before_close;
	capture_continue_t m_capture_continue;
	uint32_t m_max_thread_table_size;
	uint64_t m_thread_timeout_ns;
	uint64_t m_inactive_thread_scan_time_ns;
	std::string m_start_failure_message;
	std::string m_dump_filename;
	callback_param m_param;
	static bool inspector_ok;
	sinsp_mode_t m_mode;
	uint64_t m_max_timeouts;
};
