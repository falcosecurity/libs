#include "event_capture.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include <memory>
#include <mutex>
#include <thread>

extern sinsp_evttables g_infotables;

struct test_helper_args
{
	bool start_before;
	bool suppress_before;
	bool spawn_with_bash;
};

static void test_helper_quotactl(test_helper_args& hargs)
{
	// We start the test_helper process before starting the
	// capture, so the initial proc scan will see the pid. Once
	// the capture has started we let the test_helper process
	// perform its work.
	pid_t pid = getpid();
	bool test_helper_done = false;
	std::string bin = LIBSINSP_TEST_PATH "/test_helper";

	if (hargs.spawn_with_bash)
	{
		bin = LIBSINSP_TEST_PATH "/test_helper.sh";
	}

	subprocess test_proc(bin, {"threaded", "quotactl_ko"}, false);

	//
	// Access/modify inspector before opening
	//

	before_open_t before_open = [&](sinsp* inspector)
	{
		inspector->clear_suppress_events_comm();
		inspector->clear_suppress_events_tid();

		if (hargs.suppress_before)
		{
			inspector->suppress_events_comm(
			    std::string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}

		if (hargs.start_before)
		{
			test_proc.start();
		}
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return (evt->get_type() == PPME_SYSCALL_QUOTACTL_X || evt->get_type() == PPME_PROCEXIT_1_E);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		if (!hargs.suppress_before)
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->suppress_events_comm(
			    std::string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}

		if (!hargs.start_before)
		{
			test_proc.start();
		}

		// Wait for it to finish
		test_proc.wait();

		// Do a quotactl--when the callback loop sees this,
		// it's an indication that all the relevant events
		// have been received.
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;

		// make sure we don't add suppresed threads during initial /proc scan
		if (param.m_inspector->check_suppressed(evt->get_tid()))
		{
			ASSERT_EQ(nullptr, param.m_inspector->get_thread_ref(evt->get_tid(), false, true));
		}

		switch (evt->get_type())
		{
		case PPME_SYSCALL_QUOTACTL_X:
			if (evt->get_tid() != pid)
			{
				FAIL() << "Should not have observed any quotactl event";
			}
			else
			{
				test_helper_done = true;
			}
			break;
		case PPME_PROCEXIT_1_E:
			ASSERT_FALSE(param.m_inspector->check_suppressed(evt->get_tid()));
			break;
		}
	};

	capture_continue_t should_continue = [&]() { return (!test_helper_done); };

	before_close_t before_close = [](sinsp* inspector)
	{
		scap_stats st;

		inspector->get_capture_stats(&st);

		ASSERT_GT(st.n_suppressed, 0u);
		ASSERT_EQ(0u, st.n_tids_suppressed);

		inspector->clear_suppress_events_comm();
		inspector->clear_suppress_events_tid();
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
				callback,
				filter,
				before_open,
				before_close,
				should_continue,
				131072,
				6000,
				6000,
				SINSP_MODE_LIVE,
				1000);
	});
}

TEST_F(sys_call_test, suppress_new_process)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_add_new_value_while_running)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = false;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_grandchildren)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = true;

	test_helper_quotactl(hargs);
}

class suppress_types : public sys_call_test
{
protected:
	static bool is_target_call(uint16_t type);
	void do_syscalls();
	bool is_suppressed_evttype(uint16_t evttype) const;
	void run_test(std::vector<std::string> supp_syscalls);

	std::vector<ppm_sc_code> m_suppressed_syscalls;
	std::vector<ppm_event_code> m_suppressed_evttypes;
	int m_expected_calls;
};

bool suppress_types::is_target_call(uint16_t type)
{
	switch (type)
	{
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X:
	case PPME_SYSCALL_GETRLIMIT_E:
	case PPME_SYSCALL_GETRLIMIT_X:
		return true;
		break;
	}
	return false;
}

void suppress_types::do_syscalls()
{
	struct rlimit limits;
	// getrlimit called directly because libc likes prlimit()
	syscall(SYS_getrlimit, RLIMIT_AS, &limits);
	fcntl(1, F_GETFD);

	// enter+exit for each syscall
	m_expected_calls = 4;
	for (const auto ii : m_suppressed_evttypes)
	{
		if (is_target_call(ii))
		{
			m_expected_calls--;
		}
	}
}

bool suppress_types::is_suppressed_evttype(uint16_t type) const
{
	for (const auto ii : m_suppressed_evttypes)
	{
		if (type == ii)
		{
			return true;
		}
	}

	return false;
}

void parse_syscall_names(const std::vector<std::string>& supp_strs,
                                      std::vector<ppm_sc_code>& supp_ids)
{
	supp_ids.clear();

	for (auto sc = 0; sc < PPM_SC_MAX; sc++)
	{
		const char* name = scap_get_ppm_sc_name(static_cast<ppm_sc_code>(sc));

		auto iter = std::find(supp_strs.begin(), supp_strs.end(), std::string(name));
		if (iter != supp_strs.end())
		{
			supp_ids.push_back(static_cast<ppm_sc_code>(sc));
		}
	}
}

const char* event_name_by_id(uint16_t id)
{
	if (id >= PPM_EVENT_MAX)
	{
		ASSERT(false);
		return "NA";
	}
	return g_infotables.m_event_info[id].name;
}

void parse_suppressed_types(const std::vector<std::string>& supp_strs,
                                         std::vector<ppm_event_code>* supp_ids)
{
	for (auto ii = 0; ii < PPM_EVENT_MAX; ii++)
	{
		auto iter = std::find(supp_strs.begin(), supp_strs.end(), event_name_by_id(ii));
		if (iter != supp_strs.end())
		{
			supp_ids->push_back(static_cast<ppm_event_code>(ii));
		}
	}
}

void suppress_types::run_test(std::vector<std::string> supp_syscalls)
{
	int callnum = 0;

	parse_syscall_names(supp_syscalls, m_suppressed_syscalls);
	parse_suppressed_types(supp_syscalls, &m_suppressed_evttypes);

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		for (auto sc : m_suppressed_syscalls)
		{
			bool expect_exception = (sc >= PPM_SC_MAX);
			bool caught_exception = false;

			try
			{
				std::scoped_lock inspector_handle_lock(inspector_handle);
				inspector_handle->mark_ppm_sc_of_interest(sc, false);
			}
			catch (sinsp_exception& e)
			{
				caught_exception = true;
			}

			ASSERT_EQ(expect_exception, caught_exception);
		}

		do_syscalls();

		for (auto sc : m_suppressed_syscalls)
		{
			bool expect_exception = (sc >= PPM_SC_MAX);
			bool caught_exception = false;

			try
			{
				std::scoped_lock inspector_handle_lock(inspector_handle);
				inspector_handle->mark_ppm_sc_of_interest(sc, true);
			}
			catch (sinsp_exception& e)
			{
				caught_exception = true;
			}

			ASSERT_EQ(expect_exception, caught_exception);
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		auto type = param.m_evt->get_type();
		EXPECT_FALSE(is_suppressed_evttype(type));
		if (is_target_call(type))
		{
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, m_tid_filter); });
	EXPECT_EQ(m_expected_calls, callnum);
}

TEST_F(suppress_types, block_getrlimit)
{
	// PPME_SYSCALL_GETRLIMIT_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"getrlimit"}));
}

TEST_F(suppress_types, block_fcntl)
{
	// PPME_SYSCALL_FCNTL_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"fcntl"}));
}

TEST_F(suppress_types, block_getrlimit_and_fcntl)
{
	// PPME_SYSCALL_GETRLIMIT_(E|X) && PPME_SYSCALL_FCNTL_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"getrlimit", "fcntl"}));
}

TEST_F(suppress_types, block_none)
{
	ASSERT_NO_FATAL_FAILURE(run_test({}));
}

TEST_F(suppress_types, block_nonexistent_call)
{
	ASSERT_NO_FATAL_FAILURE(run_test({"notarealname"}));
}
