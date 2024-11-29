#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"
#include "../../helpers/proc_parsing.h"
#include "sys/mount.h"

#if defined(__NR_execve) && defined(__NR_capget) && defined(__NR_clone3) && defined(__NR_wait4)

#include <linux/sched.h>

#define CREATE_OVERLAY_FS                                                             \
                                                                                      \
	/* Create temp directories */                                                     \
	char work[] = "/tmp/work.XXXXXX";                                                 \
	char lower[] = "/tmp/lower.XXXXXX";                                               \
	char upper[] = "/tmp/upper.XXXXXX";                                               \
	char merge[] = "/tmp/overlay.XXXXXX";                                             \
                                                                                      \
	char *workdir = mkdtemp(work);                                                    \
	char *lowerdir = mkdtemp(lower);                                                  \
	char *upperdir = mkdtemp(upper);                                                  \
	char *mergedir = mkdtemp(merge);                                                  \
                                                                                      \
	if(workdir == NULL || lowerdir == NULL || upperdir == NULL || mergedir == NULL) { \
		FAIL() << "Cannot create temporary directories." << std::endl;                \
	}                                                                                 \
                                                                                      \
	/* 1. We create the lower layer file before mounting the overlayfs */             \
                                                                                      \
	/* Copy local bin/true to lower layer */                                          \
	int true_fd = open("/bin/true", O_RDONLY);                                        \
	if(true_fd == -1) {                                                               \
		FAIL() << "Cannot open /bin/true." << std::endl;                              \
	}                                                                                 \
                                                                                      \
	char lower_exe_path[1024];                                                        \
	snprintf(lower_exe_path, 1024, "%s/lowertrue", lowerdir);                         \
	int lower_exe_fd = open(lower_exe_path, O_WRONLY | O_CREAT, 0777);                \
	if(lower_exe_fd < 0) {                                                            \
		FAIL() << "Cannot open /tmp/merged/lowertrue." << std::endl;                  \
	}                                                                                 \
                                                                                      \
	char buf[1024];                                                                   \
	ssize_t bytes_read;                                                               \
	while((bytes_read = read(true_fd, buf, sizeof(buf))) > 0) {                       \
		if(write(lower_exe_fd, buf, bytes_read) != bytes_read) {                      \
			FAIL() << "Cannot write /tmp/merged/lowertrue." << std::endl;             \
		}                                                                             \
	}                                                                                 \
                                                                                      \
	if(bytes_read == -1) {                                                            \
		FAIL() << "Error copying /bin/true" << std::endl;                             \
	}                                                                                 \
                                                                                      \
	if(close(lower_exe_fd) == -1) {                                                   \
		FAIL() << "Error closing /tmp/merged/lowertrue" << std::endl;                 \
	}                                                                                 \
	if(close(true_fd) == -1) {                                                        \
		FAIL() << "Error closing /bin/true" << std::endl;                             \
	}                                                                                 \
                                                                                      \
	/* 2. We mount the overlayfs */                                                   \
                                                                                      \
	/* Construct the mount options string */                                          \
	char mntopts[1024];                                                               \
	snprintf(mntopts,                                                                 \
	         1024,                                                                    \
	         "lowerdir=%s,upperdir=%s,workdir=%s",                                    \
	         lowerdir,                                                                \
	         upperdir,                                                                \
	         workdir); /* Mount the overlayfs */                                      \
	if(mount("overlay", mergedir, "overlay", MS_MGC_VAL, mntopts) != 0) {             \
		FAIL() << "Cannot mount overlay." << std::endl;                               \
	} /* 3. We create a file in the upper layer */                                    \
	char upper_exe_path[1024];                                                        \
	sprintf(upper_exe_path, "%s/uppertrue", mergedir);                                \
	int upper_exe_fd = open(upper_exe_path, O_WRONLY | O_CREAT, 0777);                \
	if(upper_exe_fd == -1) {                                                          \
		FAIL() << "Cannot open /tmp/merged/uppertrue." << std::endl;                  \
	}                                                                                 \
	true_fd = open("/bin/true", O_RDONLY);                                            \
	if(true_fd == -1) {                                                               \
		FAIL() << "Cannot open /bin/true." << std::endl;                              \
	}                                                                                 \
	while((bytes_read = read(true_fd, buf, sizeof(buf))) > 0) {                       \
		if(write(upper_exe_fd, buf, bytes_read) != bytes_read) {                      \
			FAIL() << "Cannot write /tmp/merged/uppertrue." << std::endl;             \
		}                                                                             \
	}                                                                                 \
	if(bytes_read == -1) {                                                            \
		FAIL() << "Error copying /bin/true" << std::endl;                             \
	}                                                                                 \
	if(close(true_fd) == -1) {                                                        \
		FAIL() << "Error closing /bin/true" << std::endl;                             \
	}                                                                                 \
	if(close(upper_exe_fd) == -1) {                                                   \
		FAIL() << "Error closing /tmp/merged/uppertrue" << std::endl;                 \
	}

#define DESTROY_OVERLAY_FS                \
	/* Unmount the overlay file system */ \
	unlink(upper_exe_path);               \
	unlink(lower_exe_path);               \
	rmdir(upperdir);                      \
	rmdir(workdir);                       \
	rmdir(lowerdir);                      \
	umount2(mergedir, MNT_FORCE);         \
	rmdir(mergedir);

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

	/* Parameter 1: res (type: PT_ERRNO)*/
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	/* exe is taken from the args and not from the pathname. */
	evt_test->assert_charbuf_param(2, "");

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(3);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(16);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
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

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, "");

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	evt_test->assert_empty_param(3);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &newenviron[0]);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}

TEST(SyscallExit, execveX_success) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	const char *pathname = "/usr/bin/true";
	const char *comm = "true";

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

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		syscall(__NR_execve, pathname, newargv, newenviron);
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

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
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	if(expect_truncated) {
		evt_test->assert_charbuf_array_param(16, &expected_newenviron[0]);
	} else {
		evt_test->assert_charbuf_array_param(16, &newenviron[0]);
	}

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE);

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
	evt_test->assert_charbuf_param(28, pathname);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}

TEST(SyscallExit, execveX_not_upperlayer) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	CREATE_OVERLAY_FS

	/* Prepare the execve args */
	char merged_exe_path[1024];
	snprintf(merged_exe_path, 1024, "%s/lowertrue", mergedir);
	const char *comm = "lowertrue";
	const char *argv[] = {merged_exe_path, "randomarg", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	/*
	 * Call the `execve`
	 */
	if(ret_pid == 0) {
		syscall(__NR_execve, merged_exe_path, argv, envp);
		printf("execve failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	DESTROY_OVERLAY_FS

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, merged_exe_path);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &argv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE | PPM_EXE_LOWER_LAYER, EQUAL);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modifitrueion time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, merged_exe_path);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}

TEST(SyscallExit, execveX_upperlayer_success) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	CREATE_OVERLAY_FS

	/* Prepare the execve args */
	const char *pathname = upper_exe_path;
	const char *comm = "uppertrue";
	const char *argv[] = {upper_exe_path, "randomarg", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	/*
	 * Call the `execve`
	 */
	if(ret_pid == 0) {
		syscall(__NR_execve, pathname, argv, envp);
		printf("execve failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	DESTROY_OVERLAY_FS

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &argv[1]);

	/* Parameter 4: tid (type: PT_PID) */
	evt_test->assert_numeric_param(4, (int64_t)ret_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)ret_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)::getpid());

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &envp[0]);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE | PPM_EXE_UPPER_LAYER);

	/* Parameter 24: exe_file ino (type: PT_UINT64) */
	evt_test->assert_numeric_param(24, (uint64_t)1, GREATER_EQUAL);

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(25, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 26: exe_file mtime (last modifitrueion time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(26, (uint64_t)1000000000000000000, GREATER_EQUAL);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, upper_exe_path);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}

#if defined(__NR_memfd_create) && defined(__NR_openat) && defined(__NR_read) && defined(__NR_write)
#include <sys/mman.h>
TEST(SyscallExit, execveX_success_memfd) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int mem_fd = syscall(__NR_memfd_create, "malware", MFD_CLOEXEC);
	assert_syscall_state(SYSCALL_SUCCESS, "memfd_create", mem_fd, NOT_EQUAL, -1);

	/* Open the executable to copy */
	int fd_to_read = syscall(__NR_openat, 0, "/usr/bin/echo", O_RDWR);
	if(fd_to_read < 0) {
		FAIL() << "failed to open the file to read\n";
	}

	char buf[200];
	ssize_t bytes_read = 200;
	while(bytes_read != 0) {
		bytes_read = syscall(__NR_read, fd_to_read, buf, sizeof(buf));
		if(bytes_read < 0) {
			syscall(__NR_close, fd_to_read);
			syscall(__NR_close, mem_fd);
			FAIL() << "unable to read from file\n";
		}

		bytes_read = syscall(__NR_write, mem_fd, buf, bytes_read);
		if(bytes_read < 0) {
			syscall(__NR_close, fd_to_read);
			syscall(__NR_close, mem_fd);
			FAIL() << "unable to write to file\n";
		}
	}
	syscall(__NR_close, fd_to_read);

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		char pathname[200];
		snprintf(pathname, sizeof(pathname), "/proc/%d/fd/%d", getpid(), mem_fd);
		const char *newargv[] = {pathname, "[OUTPUT] SyscallExit.execveX_success_memfd", NULL};
		const char *newenviron[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
		syscall(__NR_execve, pathname, newargv, newenviron);
		exit(EXIT_FAILURE);
	}
	syscall(__NR_close, mem_fd);

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The child execve failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* PPM_EXE_WRITABLE is set when the user that executed a process can also write to the
	 * executable file that is used to spawn it or is its owner or otherwise capable.
	 */
	evt_test->assert_numeric_param(20, (uint32_t)PPM_EXE_WRITABLE | PPM_EXE_FROM_MEMFD);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	/* In the kmod, we use the "d_path" helper while in BPF we reconstruct the path
	 * by hand so the result is a little bit different.
	 */
	if(evt_test->is_kmod_engine()) {
		evt_test->assert_charbuf_param(28, "/memfd:malware (deleted)");
	} else {
		/* In BPF drivers we don't have the correct result but we can reconstruct part of it */
		evt_test->assert_charbuf_param(28, "memfd:malware");
	}

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}
#endif

#if defined(__NR_symlinkat) && defined(__NR_unlinkat)
TEST(SyscallExit, execveX_symlink) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	const char *pathname = "/usr/bin/echo";
	const char *linkpath = "target3";

	/* Create symlink */
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "symlinkat",
	                     syscall(__NR_symlinkat, pathname, AT_FDCWD, linkpath),
	                     NOT_EQUAL,
	                     -1);

	const char *comm = "target3";
	const char *argv[] = {linkpath, "[OUTPUT] SyscallExit.execveX_success test", NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		syscall(__NR_execve, linkpath, argv, envp);
		exit(EXIT_FAILURE);
	}

	assert_syscall_state(SYSCALL_SUCCESS, "clone3", ret_pid, NOT_EQUAL, -1);

	/* Catch the child before doing anything else. */
	int status = 0;
	int options = 0;
	assert_syscall_state(SYSCALL_SUCCESS,
	                     "wait4",
	                     syscall(__NR_wait4, ret_pid, &status, options, NULL),
	                     NOT_EQUAL,
	                     -1);

	if(__WEXITSTATUS(status) == EXIT_FAILURE || __WIFSIGNALED(status) != 0) {
		FAIL() << "The child execve failed." << std::endl;
	}

	assert_syscall_state(SYSCALL_SUCCESS,
	                     "unlinkat",
	                     syscall(__NR_unlinkat, AT_FDCWD, linkpath, 0),
	                     NOT_EQUAL,
	                     -1);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, linkpath);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 28: resolve_path (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(28, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}
#endif

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

	/* Parameter 1: res (type: PT_ERRNO)*/
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

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(30);
}

#endif
