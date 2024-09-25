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

#include "sys_call_test.h"

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <libsinsp/sinsp.h>

TEST_F(sys_call_test, can_consume_a_capture_file) {
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) {
		std::string evt_name(evt->get_name());
		return evt_name.find("stat") != std::string::npos && m_tid_filter(evt) &&
		       evt->get_direction() == SCAP_ED_OUT;
	};

	run_callback_t test = []() {
		struct stat sb;
		for(int i = 0; i < 100; i++) {
			stat("/tmp", &sb);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(100, callnum);

	sinsp inspector;
	sinsp_evt* event;

	const ::testing::TestInfo* const test_info =
	        ::testing::UnitTest::GetInstance()->current_test_info();
	auto filename = std::string(LIBSINSP_TEST_CAPTURES_PATH) + test_info->test_case_name() + "_" +
	                test_info->name() + ".scap";
	inspector.open_savefile(filename);
	callnum = 0;
	int32_t res;
	while((res = inspector.next(&event)) != SCAP_EOF) {
		ASSERT_EQ(SCAP_SUCCESS, res);
		std::string evt_name(event->get_name());
		if(evt_name.find("stat") != std::string::npos && m_tid_filter(event) &&
		   event->get_direction() == SCAP_ED_OUT) {
			callnum++;
		}
	}

	ASSERT_EQ(SCAP_EOF, res);
	ASSERT_EQ(100, callnum);
}
