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

std::string event_capture::m_engine_string = KMOD_ENGINE;
std::string event_capture::m_engine_path = "";
unsigned long event_capture::m_buffer_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
bool event_capture::inspector_ok = false;

concurrent_object_handle<sinsp> event_capture::get_inspector_handle()
{
	return {get_inspector(), m_inspector_mutex};
}

void event_capture::init_inspector()
{
		get_inspector()->m_thread_manager->set_max_thread_table_size(m_max_thread_table_size);
		get_inspector()->m_thread_timeout_ns = m_thread_timeout_ns;
		get_inspector()->set_auto_threads_purging_interval_s(m_inactive_thread_scan_time_ns);
		get_inspector()->set_auto_threads_purging(false);

		get_inspector()->set_get_procs_cpu_from_driver(true);

		ASSERT_FALSE(get_inspector()->is_capture());
		ASSERT_FALSE(get_inspector()->is_live());
		ASSERT_FALSE(get_inspector()->is_nodriver());

		try
		{
			if (m_mode == SINSP_MODE_NODRIVER)
			{
				get_inspector()->open_nodriver();
			}
			else
			{
				open_engine(event_capture::get_engine(), {});
			}
		}
		catch (sinsp_exception& e)
		{
			m_start_failed = true;
			m_start_failure_message =
				"couldn't open inspector (maybe driver hasn't been loaded yet?) err=" +
				get_inspector()->getlasterr() + " exception=" + e.what();
			{
				m_capture_started = true;
				m_condition_started.notify_one();
			}
			return;
		}

		get_inspector()->set_debug_mode(true);
		get_inspector()->set_hostname_and_port_resolution_mode(false);
}

void event_capture::capture()
{
	const ::testing::TestInfo* const test_info =
		::testing::UnitTest::GetInstance()->current_test_info();
	std::unique_ptr<sinsp_cycledumper> dumper;
	{
		std::scoped_lock init_lock(m_inspector_mutex, m_object_state_mutex);

		if(!inspector_ok)
		{
			init_inspector();
			if(!m_start_failed)
			{
				inspector_ok = true;
			}
			else
			{
				std::cerr << m_start_failure_message << std::endl;
				return;
			}
		}

		m_param.m_inspector = get_inspector();

		m_before_open(get_inspector());

		get_inspector()->start_capture();
		if (m_mode != SINSP_MODE_NODRIVER)
		{
			m_dump_filename = std::string(LIBSINSP_TEST_CAPTURES_PATH) + test_info->test_case_name() + "_" +
				test_info->name() + ".scap";
			dumper = std::make_unique<sinsp_cycledumper>(get_inspector(), m_dump_filename.c_str(),
														 0, 0, 0, 0, true);
		}
	}  // End init synchronized section

	bool signaled_start = false;
	sinsp_evt* event;
	bool result = true;
	int32_t next_result = SCAP_SUCCESS;
	while (!m_capture_stopped && result && !::testing::Test::HasFatalFailure())
	{
		{
			std::scoped_lock inspector_next_lock(m_inspector_mutex);
			next_result = get_inspector()->next(&event);
		}
		if (SCAP_SUCCESS == next_result)
		{
			result = handle_event(event);
			if (m_mode != SINSP_MODE_NODRIVER)
			{
				dumper->dump(event);
			}
		}
		if (!signaled_start)
		{
			signaled_start = true;
			m_capture_started = true;
			m_condition_started.notify_one();
		}
	}

	if (m_mode != SINSP_MODE_NODRIVER)
	{
		uint32_t n_timeouts = 0;
		while (result && !::testing::Test::HasFatalFailure())
		{
			{
				std::scoped_lock inspector_next_lock(m_inspector_mutex);
				next_result = get_inspector()->next(&event);
			}
			if (next_result == SCAP_TIMEOUT)
			{
				n_timeouts++;

				if (n_timeouts < m_max_timeouts)
				{
					continue;
				}
				else
				{
					break;
				}
			}

			if (next_result == SCAP_FILTERED_EVENT)
			{
				continue;
			}
			if (next_result != SCAP_SUCCESS)
			{
				break;
			}
			dumper->dump(event);
			result = handle_event(event);
		}
		{
			std::scoped_lock inspector_next_lock(m_inspector_mutex);
			while (SCAP_SUCCESS == get_inspector()->next(&event))
			{
				// just consume the remaining events
				dumper->dump(event);
			}
		}
	}

	{  // Begin teardown synchronized section
		std::scoped_lock teardown_lock(m_inspector_mutex, m_object_state_mutex);
		m_before_close(get_inspector());

		get_inspector()->stop_capture();
		if (m_mode != SINSP_MODE_NODRIVER)
		{
			dumper->close();
		}

		m_capture_stopped = true;
		m_condition_stopped.notify_one();
	}  // End teardown synchronized section

}

void event_capture::stop_capture()
{
	{
		std::scoped_lock init_lock(m_inspector_mutex, m_object_state_mutex);
		m_capture_stopped = true;
		m_condition_stopped.notify_one();
	}
}

void event_capture::wait_for_capture_start()
{
	std::unique_lock<std::mutex> lock(m_object_state_mutex);
	m_condition_started.wait(lock, [this]() {
		return m_capture_started;
	});
}

void event_capture::wait_for_capture_stop()
{
	std::unique_lock<std::mutex> lock(m_object_state_mutex);
	m_condition_stopped.wait(lock, [this]() {
		return m_capture_stopped;
	});
}

void event_capture::re_read_dump_file()
{
	try
	{
		sinsp inspector;
		sinsp_evt* event;

		inspector.open_savefile(m_dump_filename);
		uint32_t res;
		do
		{
			res = inspector.next(&event);
		} while (res == SCAP_SUCCESS);
		ASSERT_EQ((int)SCAP_EOF, (int)res);
	}
	catch (sinsp_exception& e)
	{
		FAIL() << "caught exception " << e.what();
	}
}

bool event_capture::
handle_event(sinsp_evt* event)
{
	std::unique_lock<std::mutex> object_state_lock(m_object_state_mutex);
	if (::testing::Test::HasNonfatalFailure())
	{
		return true;
	}
	bool res = true;
	if (m_filter(event))
	{
		try
		{
			m_param.m_evt = event;
			m_captured_event_callback(m_param);
		}
		catch(...)
		{
			res = false;
		}
	}
	if (!m_capture_continue())
	{
		return false;
	}
	if (!res || ::testing::Test::HasNonfatalFailure())
	{
		std::cerr << "failed on event " << event->get_num() << std::endl;
	}
	return res;
}

void event_capture::open_engine(const std::string& engine_string, libsinsp::events::set<ppm_sc_code> events_sc_codes)
{
	if(false)
	{
	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE))
	{
		get_inspector()->open_kmod(m_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE))
	{
		if(event_capture::get_engine().empty())
		{
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		get_inspector()->open_bpf(event_capture::get_engine_path().c_str(), m_buffer_dim);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE))
	{
		get_inspector()->open_modern_bpf(m_buffer_dim);
	}
#endif
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}
}

void event_capture::set_engine(const std::string& engine_string, const std::string& engine_path)
{
	m_engine_string = engine_string;
	m_engine_path = engine_path;
}

void event_capture::set_buffer_dim(const unsigned long& dim)
{
	m_buffer_dim = dim;
}

const std::string& event_capture::get_engine()
{
	return m_engine_string;
}

const std::string& event_capture::get_engine_path()
{
	return m_engine_path;
}
