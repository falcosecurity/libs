#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"
#include "../../helpers/proc_parsing.h"
#include "sys/mount.h"

// note: `execve`-related tests in this file should only test failure `execve` scenarios, as success
// scenarios are tested in
// `test/drivers/test_suites/generic_tracepoints_suite/sched_process_exec.cpp`

#if defined(__NR_execve) && defined(__NR_capget) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

TEST(SyscallExit, execveX_failure) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Get all the info from proc. */
	struct proc_info info = {};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info)) {
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/*
	 * Get the process capabilities.
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

	/*
	 * Call the `execve`
	 */
	char pathname[] = "//**null-file-path**//";

	std::string too_long_arg(4096, 'x');
	const char *newargv[] =
	        {pathname, "", "first_argv", "", too_long_arg.c_str(), "second_argv", NULL};
	std::string truncated_too_long_arg(
	        4096 - (strlen(pathname) + 1) - (strlen("first_argv") + 1) - 2 * (strlen("") + 1) - 1,
	        'x');
	const char *expected_newargv[] =
	        {pathname, "", "first_argv", "", truncated_too_long_arg.c_str(), NULL};

	const char *newenviron[] = {"IN_TEST=yes",
	                            "3_ARGUMENT=yes",
	                            too_long_arg.c_str(),
	                            "2_ARGUMENT=no",
	                            NULL};
	std::string truncated_too_long_env(
	        4096 - (strlen("IN_TEST=yes") + 1) - (strlen("3_ARGUMENT=yes") + 1) - 1,
	        'x');
	const char *expected_newenviron[] = {"IN_TEST=yes",
	                                     "3_ARGUMENT=yes",
	                                     truncated_too_long_env.c_str(),
	                                     NULL};

	bool expect_truncated = true;
	if(evt_test->is_kmod_engine() && getpagesize() > 4096) {
		// for kmod, the size limit is actually PAGE_SIZE;
		// see STR_STORAGE_SIZE macro definition in driver/capture_macro.h.
		// In case PAGE_SIZE is < 4096, expect NON-truncated args/envs
		expect_truncated = false;
	}

	assert_syscall_state(SYSCALL_FAILURE,
	                     "execve",
	                     syscall(__NR_execve, pathname, newargv, newenviron));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	if(expect_truncated) {
		evt_test->assert_charbuf_array_param(3, &expected_newargv[1]);
	} else {
		evt_test->assert_charbuf_array_param(3, &newargv[1]);
	}

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)info.ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)info.file_rlimit.rlim_cur);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(9, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(10, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(11, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	if(expect_truncated) {
		evt_test->assert_charbuf_array_param(16, &expected_newenviron[0]);
	} else {
		evt_test->assert_charbuf_array_param(16, &newenviron[0]);
	}

	/* Parameter 17: tty (type: PT_UINT32) */
	evt_test->assert_numeric_param(17, (uint32_t)info.tty);

	/* Parameter 18: pgid (type: PT_PID) */
	evt_test->assert_numeric_param(18, (int64_t)info.pgid);

	/* Parameter 19: loginuid (type: PT_UID) */
	evt_test->assert_numeric_param(19, (uint32_t)info.loginuid);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        21,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) |
	                                       data[0].inheritable));

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        22,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) |
	                                       data[0].permitted));

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        23,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) |
	                                       data[0].effective));

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	/* Here we don't call the execve so the result should be the full path to the drivers test
	 * executable */
	evt_test->assert_charbuf_param(28, info.exepath);

	/* Parameter 29: pgid (type: PT_PID) */
	evt_test->assert_numeric_param(29, (int64_t)info.pgid);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

TEST(SyscallExit, execveX_failure_unresolved_filename) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char pathname[] = "/non/existent/../path";
	assert_syscall_state(SYSCALL_FAILURE, "execve", syscall(__NR_execve, pathname, NULL, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

TEST(SyscallExit, execveX_failure_args_env_NULL) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char pathname[] = "//args_env_NULL//";
	assert_syscall_state(SYSCALL_FAILURE, "execve", syscall(__NR_execve, pathname, NULL, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	/* exe is taken from the args and not from the pathname. */
	evt_test->assert_charbuf_param(2, "");

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(3);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(16);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

TEST(SyscallExit, execveX_failure_path_NULL_but_not_args) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	char pathname[] = "//path_NULL_but_not_args//";
	const char *newargv[] = {"", NULL};
	const char *newenviron[] = {"", NULL};
	assert_syscall_state(SYSCALL_FAILURE,
	                     "execve",
	                     syscall(__NR_execve, pathname, newargv, newenviron));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, "");

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(3);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &newenviron[0]);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

TEST(SyscallExit, execveX_failure_empty_arg) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Get all the info from proc. */
	struct proc_info info = {};
	pid_t pid = ::getpid();
	if(!get_proc_info(pid, &info)) {
		FAIL() << "Unable to get all the info from proc" << std::endl;
	}

	/*
	 * Get the process capabilities.
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

	/*
	 * Call the `execve`
	 */
	char pathname[] = "";
	const char *newargv[] = {pathname, "first_argv", "second_argv", "", "fourth_argv", NULL};
	const char *newenviron[] =
	        {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", "", "0_ARGUMENT=no", NULL};
	assert_syscall_state(SYSCALL_FAILURE,
	                     "execve",
	                     syscall(__NR_execve, pathname, newargv, newenviron));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &newargv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)info.ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)info.file_rlimit.rlim_cur);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(9, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	/* Right now we can't find a precise value to perform the assertion. */
	evt_test->assert_numeric_param(10, (uint64_t)0, GREATER_EQUAL);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(11, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)0, GREATER_EQUAL);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &newenviron[0]);

	/* Parameter 17: tty (type: PT_UINT32) */
	evt_test->assert_numeric_param(17, (uint32_t)info.tty);

	/* Parameter 18: pgid (type: PT_PID) */
	evt_test->assert_numeric_param(18, (int64_t)info.pgid);

	/* Parameter 19: loginuid (type: PT_UID) */
	evt_test->assert_numeric_param(19, (uint32_t)info.loginuid);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        21,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) |
	                                       data[0].inheritable));

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        22,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) |
	                                       data[0].permitted));

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(
	        23,
	        (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) |
	                                       data[0].effective));

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	/* Here we don't call the execve so the result should be the full path to the drivers test
	 * executable */
	evt_test->assert_charbuf_param(28, info.exepath);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#endif
