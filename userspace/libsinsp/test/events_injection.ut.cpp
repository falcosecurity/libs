#include <gtest/gtest.h>

#include "sinsp_with_test_input.h"
#include "test_utils.h"


static void encode_async_event(scap_evt* scapevt, uint64_t tid, const char* data)
{
	struct scap_plugin_params
	{};

	static uint32_t plug_id[2] = {sizeof (uint32_t), 0};

	size_t totlen = sizeof(scap_evt) + sizeof(plug_id)  + sizeof(uint32_t) + strlen(data) + 1;

	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = PPME_ASYNCEVENT_E;
	scapevt->nparams = 2;

	char* buff = (char *)scapevt + sizeof(struct ppm_evt_hdr);
	memcpy(buff, (char*)plug_id, sizeof(plug_id));
	buff += sizeof(plug_id);

	char* valptr = buff + sizeof(uint32_t);

	auto* data_len_ptr = (uint32_t*)buff;
	*data_len_ptr = (uint32_t)strlen(data) + 1;
	memcpy(valptr, data, *data_len_ptr);
}

class sinsp_evt_generator
{
private:
	struct scap_buff
	{
		uint8_t data[128];
	};

public:
	sinsp_evt_generator() = default;
	sinsp_evt_generator(sinsp_evt_generator&&) = default;
	~sinsp_evt_generator()
	{
		if (thr.joinable())
		{
			thr.join();
		}
	}

	scap_evt* get(size_t idx)
	{
		return scap_ptrs[idx];
	}

	scap_evt* back()
	{
		return scap_ptrs.back();
	}

	std::unique_ptr<sinsp_evt> next(uint64_t ts = (uint64_t) -1)
	{
		scaps.emplace_back(new scap_buff());
		scap_ptrs.emplace_back((scap_evt*)scaps.back()->data);

		encode_async_event(scap_ptrs.back(), 1, "dummy_data");

		auto event = std::make_unique<sinsp_evt>();
		event->m_pevt = scap_ptrs.back();
		event->m_cpuid = 0;
		event->m_pevt->ts = ts;
		return event;
	};

	void run_async(size_t n_events, sinsp& inspector)
	{
		auto runner = [this](size_t n_events, sinsp& inspector)
		{
			for(size_t i = 0; i < n_events; ++i)
			{
				inspector.handle_async_event(next(sinsp_utils::get_current_time_ns()));
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		};
		thr = std::thread(runner, n_events, std::ref(inspector));
	}

private:
	std::vector<std::shared_ptr<scap_buff> > scaps;
	std::vector<scap_evt*> scap_ptrs; // gdb watch helper
	std::thread thr;
};

TEST_F(sinsp_with_test_input, event_async_queue)
{
	open_inspector();
	m_inspector.m_lastevent_ts = 123;

	sinsp_evt_generator evt_gen;
	sinsp_evt* evt{};

	// inject event
	m_inspector.handle_async_event(evt_gen.next());
	//ASSERT_EQ(m_inspector.m_pending_state_evts.m_queue.size(), 1);

	// create test input event
	auto* scap_evt0 = add_event_with_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file",
					     PPM_O_RDWR, 0, 5, (uint64_t)123);

	// should pop injected event
	auto res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(evt->m_pevt, evt_gen.back());
	ASSERT_EQ(evt->m_pevt->ts, 123);
	ASSERT_TRUE(m_inspector.m_pending_state_evts.empty());

	// multiple injected events
	m_inspector.m_lastevent_ts = scap_evt0->ts - 10;

	uint64_t injected_ts = scap_evt0->ts + 10;
	for (int i = 0; i < 10; ++i)
	{
		m_inspector.handle_async_event(evt_gen.next(injected_ts + i));
	}

	// create input[1] ivent
	auto* scap_evt1 = add_event_with_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3, "/tmp/the_file",
					     PPM_O_RDWR, 0, 5, (uint64_t)123);

	// pop scap 0 event
	res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_EQ(evt->m_pevt, scap_evt0);
	auto last_ts = evt->m_pevt->ts;
	
	// pop injected
	for (int i= 0; i < 10; ++i)
	{
		res = m_inspector.next(&evt);
		ASSERT_EQ(res, SCAP_SUCCESS);
		ASSERT_EQ(evt->m_pevt, evt_gen.get(i+1));
		ASSERT_TRUE(last_ts <= evt->m_pevt->ts);
		last_ts = evt->m_pevt->ts;
	}
	ASSERT_TRUE(m_inspector.m_pending_state_evts.empty());

	// pop scap 1
	res = m_inspector.next(&evt);
	ASSERT_EQ(res, SCAP_SUCCESS);
	ASSERT_EQ(evt->m_pevt, scap_evt1);
}

#ifndef __EMSCRIPTEN__

// threads creation may get "resource unavailable" with __EMSCRIPTEN__

/*
 * async test with ten multithreaded producers
 */
TEST_F(sinsp_with_test_input, event_async_queue_mpsc)
{
	open_inspector();
	m_inspector.m_lastevent_ts = sinsp_utils::get_current_time_ns();
	const size_t n_producers = 3;
	const size_t n_events = 30;

	// start producers
	std::vector<sinsp_evt_generator> gens;
	gens.reserve(n_producers);
	for (size_t i = 0; i < n_producers; ++i)
	{
		gens.emplace_back();
		gens.back().run_async(n_events, m_inspector);
	}

	// receive all sinsp events
	auto start = sinsp_utils::get_current_time_ns();
	auto current = start;

	int res  = SCAP_SUCCESS;
	size_t n_expected = n_producers * n_events;
	while ((current - start) / ONE_SECOND_IN_NS < 10)
	{
		std::this_thread::sleep_for(std::chrono::microseconds (10));
		current = sinsp_utils::get_current_time_ns();

		// generate scap input
		add_event_with_ts(current, 1, PPME_SYSCALL_OPEN_X, 6, (uint64_t)3,
				  "/tmp/the_file", PPM_O_RDWR, 0, 5, (uint64_t)123);

		sinsp_evt* evt;
		res = m_inspector.next(&evt);
		ASSERT_EQ(res, SCAP_SUCCESS);

		if (evt && evt->m_pevt->type != PPME_SYSCALL_OPEN_X)
		{
			ASSERT_EQ(evt->m_pevt->type, PPME_ASYNCEVENT_E);
			if(--n_expected == 0)
			{
				break;
			}
		}
	}

	ASSERT_EQ(n_expected, 0);
}
#endif // __EMSCRIPTEN__
