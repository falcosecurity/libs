#include "../../event_class/event_class.h"

#if defined(__NR_io_uring_setup)

#include <linux/io_uring.h>

TEST(SyscallExit, io_uring_setupX)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_setup, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* There could be cases in which the structure `io_uring_params`
	 * doesn't have the filed `feature`, so define it to `0` as default.
	 */
	uint32_t expected_features = 0;
	uint32_t expected_flags = (uint32_t)-1;
	uint32_t entries = 4;
	struct io_uring_params params = {};
	params.sq_entries = 5;
	params.cq_entries = 6;
	params.flags = (uint32_t)-1;
	/* The call should fail since we specified only `IORING_SETUP_SQ_AFF`
	 * but not `IORING_SETUP_SQPOLL`
	 */
#ifdef IORING_FEAT_SINGLE_MMAP
	params.flags = IORING_SETUP_SQ_AFF;
	expected_flags = PPM_IORING_SETUP_SQ_AFF;
#endif
	params.sq_thread_cpu = 7;
	params.sq_thread_idle = 8;
#ifdef IORING_FEAT_NODROP
	params.features = IORING_FEAT_NODROP;
	expected_features = PPM_IORING_FEAT_NODROP;
#endif
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_setup", syscall(__NR_io_uring_setup, entries, &params));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)entries);

	/* Parameter 3: sq_entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)params.sq_entries);

	/* Parameter 4: cq_entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)params.cq_entries);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(5, (uint32_t)expected_flags);

	/* Parameter 6: sq_thread_cpu (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)params.sq_thread_cpu);

	/* Parameter 7: sq_thread_idle (type: PT_UINT32) */
	evt_test->assert_numeric_param(7, (uint32_t)params.sq_thread_idle);

	/* Parameter 8: features (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(8, (uint32_t)expected_features);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

TEST(SyscallExit, io_uring_setupX_with_NULL_pointer)
{
	auto evt_test = get_syscall_event_test(__NR_io_uring_setup, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	uint32_t entries = 4;
	struct io_uring_params* params_pointer = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "io_uring_setup", syscall(__NR_io_uring_setup, entries, params_pointer));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(2, (uint32_t)entries);

	/* Parameter 3: sq_entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(3, (uint32_t)0);

	/* Parameter 4: cq_entries (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)0);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(5, (uint32_t)0);

	/* Parameter 6: sq_thread_cpu (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)0);

	/* Parameter 7: sq_thread_idle (type: PT_UINT32) */
	evt_test->assert_numeric_param(7, (uint32_t)0);

	/* Parameter 8: features (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(8, (uint32_t)0);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(8);
}

#endif
