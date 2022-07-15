/*
Copyright (C) 2021 The Falco Authors.

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

#include "sinsp.h"
#include "filterchecks.h"
#include <gtest/gtest.h>

using namespace libsinsp;

class sinsp_external_processor_dummy : public event_processor
{
	void on_capture_start() override {}
	void process_event(sinsp_evt* evt, event_return rc) override {}
	void add_chisel_metric(statsd_metric* metric) override {}
};

TEST(sinsp, external_event_processor_initialization)
{
	sinsp my_sinsp;
	EXPECT_EQ(my_sinsp.get_external_event_processor(), nullptr);
	sinsp_external_processor_dummy processor;
	my_sinsp.register_external_event_processor(processor);
	EXPECT_EQ(my_sinsp.get_external_event_processor(), &processor);
}

class sinsp_with_test_input : public ::testing::Test {
protected:
	void SetUp() override
	{
		m_test_data = std::unique_ptr<scap_test_input_data>(new scap_test_input_data);
		m_test_data->event_count = 0;
		m_test_data->events = nullptr;
	}

	void TearDown() override
	{
		for (size_t i = 0; i < m_events.size(); i++)
		{
			free(m_events[i]);
		}
	}

	sinsp inspector;

	void open_inspector()
	{
		inspector.open_test_input(m_test_data.get());
	}

	scap_evt* add_event(uint64_t ts, uint64_t tid, enum ppm_event_type event_type, uint32_t n, ...)
	{
		struct scap_sized_buffer event_buf = {NULL, 0};
		size_t event_size;
		char error[SCAP_LASTERR_SIZE];
		error[0] = '\0';

		va_list args;
		va_start(args, n);
		int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
		va_end(args);

		if(ret != SCAP_INPUT_TOO_SMALL) {
			return nullptr;
		}

		event_buf.buf = malloc(event_size);
		event_buf.size = event_size;

		if(event_buf.buf == NULL) {
			return nullptr;
		}

		va_start(args, n);
		ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
		va_end(args);

		if(ret != SCAP_SUCCESS) {
			free(event_buf.buf);
			event_buf.size = 0;
			return nullptr;
		}

		scap_evt *event = static_cast<scap_evt*>(event_buf.buf);
		m_events.push_back(event);
		m_test_data->events = m_events.data();
		m_test_data->event_count = m_events.size();

		return event;
	}

	std::string get_field_as_string(sinsp_evt *evt, std::string field_name)
	{
		sinsp_filter_check *chk = g_filterlist.new_filter_check_from_fldname(field_name, &inspector, false);
		chk->parse_field_name(field_name.c_str(), true, false);
		std::string result = chk->tostring(evt);
		return result;
	}

	unique_ptr<scap_test_input_data> m_test_data;
	std::vector<scap_evt*> m_events;
};

TEST_F(sinsp_with_test_input, test_event)
{
	add_event(1657881958, 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", 0, 0);

	open_inspector();

	sinsp_evt *evt;
	inspector.next(&evt);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN_E);
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.name"), "/tmp/the_file");
}
