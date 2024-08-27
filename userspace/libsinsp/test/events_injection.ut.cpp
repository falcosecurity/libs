#include <gtest/gtest.h>

#include "sinsp_with_test_input.h"
#include "test_utils.h"


TEST_F(sinsp_with_test_input, event_async_queue)
{
	open_inspector();
	m_inspector.set_lastevent_ts(123);

	sinsp_evt* evt{};
	const scap_evt *scap_evt;

	scap_evt = add_async_event(-1, -1, PPME_ASYNCEVENT_E, 3,
		100, "event_name", scap_const_sized_buffer{NULL, 0});

	// create test input event
	auto* scap_evt0 = add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file",
					     PPM_O_RDWR, 0, 5, (uint64_t)123);

	// should pop injected event
	auto res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->get_scap_evt(), scap_evt);
	ASSERT_EQ(evt->get_scap_evt()->ts, 123);
	ASSERT_TRUE(m_inspector.m_async_events_queue.empty());

	// multiple injected events
	m_inspector.set_lastevent_ts(scap_evt0->ts - 10);

	uint64_t injected_ts = scap_evt0->ts + 10;
	for (int i = 0; i < 10; ++i)
	{
		add_async_event(injected_ts + i, -1, PPME_ASYNCEVENT_E, 3,
			100, "event_name", scap_const_sized_buffer{NULL, 0});
	}

	// create input[1] ivent
	auto* scap_evt1 = add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file",
					     PPM_O_RDWR, 0, 5, (uint64_t)123);

	// pop scap 0 event
	res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_EQ(evt->get_scap_evt(), scap_evt0);
	auto last_ts = evt->get_scap_evt()->ts;
	
	// pop injected
	for (int i= 0; i < 10; ++i)
	{
		res = m_inspector.next(&evt);
		ASSERT_EQ(res, SCAP_SUCCESS);
		ASSERT_EQ(evt->get_scap_evt(), m_async_events[i+1]);
		ASSERT_TRUE(last_ts <= evt->get_scap_evt()->ts);
		last_ts = evt->get_scap_evt()->ts;
	}
	ASSERT_TRUE(m_inspector.m_async_events_queue.empty());

	// pop scap 1
	res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_EQ(evt->get_scap_evt(), scap_evt1);
}

