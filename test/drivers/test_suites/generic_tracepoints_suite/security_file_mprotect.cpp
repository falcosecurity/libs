#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"

#if defined(__NR_mprotect)

#include <linux/sched.h>
#include <sys/mman.h>

TEST(GenericTracepoints, security_file_mprotect)
{
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char buffer[1024];
	int ret = syscall(__NR_mprotect, buffer, 1024, PROT_READ);
	if (ret < 0)
	{
		exit(EXIT_FAILURE);
	}
	assert_syscall_state(SYSCALL_SUCCESS, "mprotect", ret, NOT_EQUAL, -1);

	evt_test->disable_capture();

	evt_test->assert_event_presence(ret);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a child event. */
	evt_test->assert_event_presence(ret);

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: addr_start (type: PT_UINT64) */
	evt_test->assert_only_param_len(2, sizeof(uint64_t));

	/* Parameter 3: addr_end (type: PT_UINT64) */
	evt_test->assert_only_param_len(3, sizeof(uint64_t));

	/* Parameter 4: reqprot (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(4, (int32_t)PROT_READ);

	/* Parameter 5: prot (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(5, (int32_t)PROT_READ);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(5);
}

#endif
