#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"

#ifdef __NR_capset
TEST(SyscallExit, capsetX)
{
	auto evt_test = get_syscall_event_test(__NR_capset, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* In this test we don't want to modify the capabilities of the actual process
	 * so as a first step we will get the actual capabilities of the process and
	 * after it we will call `capset` with empty params just to trigger the BPF
	 * program. In case of failure, the capset exit event returns the actual
	 * capabilities of the process, in this way we can assert them against the ones
	 * we have retrieved from the previous `capget` call.
	 */

	/* On kernels >= 5.8 the suggested version should be `_LINUX_CAPABILITY_VERSION_3` */
	struct __user_cap_header_struct header = {};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	cap_user_header_t hdrp = &header;
	cap_user_data_t datap = data;

	/* Prepare the header. */
	header.pid = 0; /* `0` means the pid of the actual process. */
	header.version = _LINUX_CAPABILITY_VERSION_3;

	assert_syscall_state(SYSCALL_SUCCESS, "capget", syscall(__NR_capget, hdrp, datap), EQUAL, 0);

	assert_syscall_state(SYSCALL_FAILURE, "capset", syscall(__NR_capset, NULL, NULL));
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

	/* Parameter 2: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) | data[0].inheritable));

	/* Parameter 3: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) | data[0].permitted));

	/* Parameter 4: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) | data[0].effective));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
