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
#include "event_capture.h"
#include "ppm_events_public.h"
#include "subprocess.h"

#include <gtest/gtest.h>

#include <libsinsp/event.h>

#include <list>
#include <tuple>

uint32_t get_server_address();

class proc_started_filter
{
	public:
		bool operator()(sinsp_evt* evt)
		{
			if (!m_child_ready && evt->get_type() == PPME_SYSCALL_WRITE_X)
			{
				auto buffer = evt->get_param_value_str("data", false);
				if(buffer.find("SERVER UP") != std::string::npos ||
				   buffer.find("STARTED") != std::string::npos)
				{
					m_child_ready = true;
				}
			}
			return m_child_ready;
		}

	private:
		bool m_child_ready{false};
};

class sys_call_test : public testing::Test
{
public:
	static void SetUpTestCase() {}

	static void TearDownTestCase() {}

protected:
	void SetUp()
	{
		m_tid = getpid();
		m_tid_filter = [this](sinsp_evt* evt)
		{
			if (evt->get_param_value_str("fd").find(LIBSINSP_TEST_KERNEL_MODULE_NAME) != std::string::npos)
			{
				return false;
			}
			return evt->get_tid() == m_tid;
		};
	};

	__pid_t m_tid;
	event_filter_t m_tid_filter;
};

#ifdef __x86_64__

using sys_call_test32 = sys_call_test;

#endif
