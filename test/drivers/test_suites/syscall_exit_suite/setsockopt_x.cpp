#include "../../event_class/event_class.h"

#ifdef __NR_setsockopt

#include <netdb.h>
#include <time.h>

TEST(SyscallExit, setsockoptX_SO_ERROR)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_ERROR;
	int32_t option_value = 14;
	socklen_t option_len = sizeof(int32_t);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_ERROR);

	/* Parameter 5: optval (type: PT_DYN) */
	/* In case of `PPM_SOCKOPT_IDX_ERRNO` we receive the negative `option_value`*/
	int64_t negative_option_value = -option_value;
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_ERRNO, &negative_option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_SO_RCVTIMEO)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_RCVTIMEO;
	struct timeval option_value = {};
	option_value.tv_sec = 5;
	option_value.tv_usec = 10;
	socklen_t option_len = sizeof(struct timeval);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_RCVTIMEO);

	/* Parameter 5: optval (type: PT_DYN) */
	uint64_t total_timeval = option_value.tv_sec * SEC_FACTOR + option_value.tv_usec * USEC_FACTOR;
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_TIMEVAL, &total_timeval, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_SO_COOKIE)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_COOKIE;
	uint64_t option_value = 16;
	socklen_t option_len = sizeof(option_value);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_COOKIE);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT64, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_SO_PASSCRED)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_SO_PASSCRED);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UINT32, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_UNKNOWN_OPTION)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = SOL_SOCKET;
	int32_t option_name = -1; /* this is an unknown option. */
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_SOL_SOCKET);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_SOL_UNKNOWN)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 16;
	socklen_t option_len = sizeof(option_value);
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

TEST(SyscallExit, setsockoptX_ZERO_OPTLEN)
{
	auto evt_test = get_syscall_event_test(__NR_setsockopt, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	int32_t level = 7; /* Unknown level. */
	int32_t option_name = SO_PASSCRED;
	uint32_t option_value = 0;
	socklen_t option_len = 0;
	assert_syscall_state(SYSCALL_FAILURE, "setsockopt", syscall(__NR_setsockopt, mock_fd, level, option_name, &option_value, option_len));
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

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(3, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	evt_test->assert_numeric_param(4, (uint8_t)PPM_SOCKOPT_LEVEL_UNKNOWN);

	/* Parameter 5: optval (type: PT_DYN) */
	evt_test->assert_setsockopt_val(5, PPM_SOCKOPT_IDX_UNKNOWN, &option_value, option_len);

	/* Parameter 6: optlen (type: PT_UINT32) */
	evt_test->assert_numeric_param(6, (uint32_t)option_len);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(6);
}

#endif
