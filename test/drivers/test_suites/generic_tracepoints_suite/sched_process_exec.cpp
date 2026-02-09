#include "../../event_class/event_class.h"
#include "../../helpers/proc_parsing.h"
#include "sys/mount.h"

// note: `execve{,at}`-related tests in this file should only test success `execve{,at}` scenarios,
// as failure scenarios are tested in `syscall_exit_suite/execve{,at}_x.cpp`.

#if defined(__NR_clone3) && defined(__NR_wait4)

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

#if defined(__NR_execve) || defined(__NR_execveat)
void assert_ctime_mtime_params(const std::unique_ptr<event_test> &evt_test, const char *exe_path) {
	// The following logic is motivated by the fact that sometimes stat() returns ctime and mtime
	// for the virtual inode created by overlayFS: these could be different from ctime and mtime for
	// the raw inode, as seen by kernel drivers gathering them. At least, we know for sure that
	// stat's ctime and mtime will be greater or equal than the corresponding values gathered by
	// drivers, so this is what we test. Also, we make sure that these values are greater than some
	// arbitrary lower bound: this serves to avoid dummy values (like 0s), to pass checks.

	// Retrieving some information regarding the executable.
	struct stat st;
	if(stat(exe_path, &st) != 0) {
		FAIL() << "Could not stat " << exe_path;
	}
	const auto stat_ctime_ns =
	        static_cast<uint64_t>(st.st_ctim.tv_sec) * 1000000000 + st.st_ctim.tv_nsec;
	const auto stat_mtime_ns =
	        static_cast<uint64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
	// This is used as reasonable safe lower bound for ctime and mtime.
	constexpr uint64_t safe_epoch_ns = 631152000000000000ULL;  // 1 Jan, 1990.

	/* Parameter 25: exe_file ctime (last status change time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(25, safe_epoch_ns, GREATER_EQUAL);
	evt_test->assert_numeric_param(25, stat_ctime_ns, LESS_EQUAL);

	/* Parameter 26: exe_file mtime (last modification time, epoch value in nanoseconds) (type:
	 * PT_ABSTIME) */
	evt_test->assert_numeric_param(26, safe_epoch_ns, GREATER_EQUAL);
	evt_test->assert_numeric_param(26, stat_mtime_ns, LESS_EQUAL);
}
#endif

/* execve section */
#ifdef __NR_execve

TEST(GenericTracepoints, sched_proc_exec_execve) {
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

	/* Parameter 1: res (type: PT_ERRNO) */
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

	assert_ctime_mtime_params(evt_test, pathname);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, pathname);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#if defined(__NR_memfd_create) && defined(__NR_openat) && defined(__NR_read) && defined(__NR_write)
#include <sys/mman.h>
TEST(GenericTracepoints, sched_proc_exec_execve_memfd) {
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
		const char *newargv[] = {pathname,
		                         "[OUTPUT] GenericTracepoints.sched_proc_exec_memfd",
		                         NULL};
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

	/* Parameter 1: res (type: PT_ERRNO) */
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

	/* Parameter 31: filename (type: PT_FSPATH) */
	char pathname[200];
	snprintf(pathname, sizeof(pathname), "/proc/%d/fd/%d", ret_pid, mem_fd);
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}
#endif

TEST(GenericTracepoints, sched_proc_exec_execve_not_upperlayer) {
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

	/* Parameter 1: res (type: PT_ERRNO) */
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

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, merged_exe_path);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

TEST(GenericTracepoints, sched_proc_exec_execve_upperlayer) {
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

	/* Parameter 1: res (type: PT_ERRNO) */
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

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#if defined(__NR_symlinkat) && defined(__NR_unlinkat)
TEST(GenericTracepoints, sched_proc_exec_execve_symlink) {
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
	const char *argv[] = {linkpath,
	                      "[OUTPUT] GenericTracepoints.sched_proc_exec_symlink test",
	                      NULL};
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, linkpath);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 28: trusted_exepath (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(28, pathname);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, linkpath);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}
#endif

TEST(GenericTracepoints, sched_proc_exec_execve_unresolved_filename) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	const char *pathname = "/usr/../usr/./bin/true";
	const char *resolved_pathname = "/usr/bin/true";
	const char *comm = "true";
	const char *argv[] = {pathname, "", nullptr};

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		syscall(__NR_execve, pathname, argv, nullptr);
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

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, static_cast<int64_t>(0));

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, comm);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, resolved_pathname);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#ifdef __NR_execveat

TEST(GenericTracepoints, sched_proc_exec_execveat) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execveat args */
	int dirfd = 0;
	const char *pathname = "/usr/bin/test";

	std::string too_long_arg(4096, 'x');
	const char *newargv[] =
	        {pathname, "", "first_argv", "", too_long_arg.c_str(), "second_argv", NULL};
	const char *newenviron[] = {"IN_TEST=yes",
	                            "3_ARGUMENT=yes",
	                            too_long_arg.c_str(),
	                            "2_ARGUMENT=no",
	                            NULL};

	bool expect_truncated = true;
	if(evt_test->is_kmod_engine() && getpagesize() > 4096) {
		// for kmod, the size limit is actually PAGE_SIZE;
		// see STR_STORAGE_SIZE macro definition in driver/capture_macro.h.
		// In case PAGE_SIZE is < 4096, expect NON-truncated args/envs
		expect_truncated = false;
	}

	int flags = 0;

	/* We need to use `SIGCHLD` otherwise the parent won't receive any signal
	 * when the child terminates.
	 */
	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		syscall(__NR_execveat, dirfd, pathname, newargv, newenviron, flags);
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
		FAIL() << "The child execveat failed." << std::endl;
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

	const char *comm = "test";

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	if(expect_truncated) {
		std::string truncated_too_long_arg(4096 - (strlen(pathname) + 1) -
		                                           (strlen("first_argv") + 1) -
		                                           2 * (strlen("") + 1) - 1,
		                                   'x');
		const char *expected_newargv[] =
		        {pathname, "", "first_argv", "", truncated_too_long_arg.c_str(), NULL};
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
		std::string truncated_too_long_env(
		        4096 - (strlen("IN_TEST=yes") + 1) - (strlen("3_ARGUMENT=yes") + 1) - 1,
		        'x');
		const char *expected_newenviron[] = {"IN_TEST=yes",
		                                     "3_ARGUMENT=yes",
		                                     truncated_too_long_env.c_str(),
		                                     NULL};
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

	assert_ctime_mtime_params(evt_test, pathname);

	/* Parameter 27: euid (type: PT_UID) */
	evt_test->assert_numeric_param(27, (uint32_t)geteuid(), EQUAL);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, pathname);

	/* Parameter 30: egid (type: PT_GID) */
	evt_test->assert_numeric_param(30, (uint32_t)getegid(), EQUAL);

	/* Parameter 31: filename (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#if defined(__NR_memfd_create) && defined(__NR_openat) && defined(__NR_read) && defined(__NR_write)
#include <sys/mman.h>
TEST(GenericTracepoints, sched_proc_exec_execveat_memfd) {
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
		const char *newargv[] = {pathname,
		                         "[OUTPUT] GenericTracepoints.sched_proc_exec_execveat_memfd",
		                         NULL};
		const char *newenviron[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
		syscall(__NR_execveat, 0, pathname, newargv, newenviron, 0);
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

	/* Parameter 31: filename (type: PT_FSPATH) */
	char pathname[200];
	snprintf(pathname, sizeof(pathname), "/proc/%d/fd/%d", ret_pid, mem_fd);
	evt_test->assert_charbuf_param(31, pathname);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}
#endif  // defined(__NR_memfd_create) && defined(__NR_openat) && defined(__NR_read) &&
        // defined(__NR_write)

TEST(GenericTracepoints, sched_proc_exec_execveat_comm_equal_to_fd_in_old_kernel_versions) {
	auto evt_test = get_syscall_event_test(__NR_execve, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Prepare the execve args */
	const std::string exe_path{"/usr/bin/echo"};
	int dirfd = open(exe_path.c_str(), O_RDONLY);
	if(dirfd < 0) {
		FAIL() << "failed to open the file\n";
	}

	// We will use the `AT_EMPTY_PATH` strategy
	const char *pathname = "";
	const char *argv[] = {
	        pathname,
	        "[OUTPUT] "
	        "GenericTracepoints.sched_proc_exec_execveat_comm_equal_to_fd_in_old_kernel_versions",
	        NULL};
	const char *envp[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = AT_EMPTY_PATH;

	clone_args cl_args = {};
	cl_args.exit_signal = SIGCHLD;
	pid_t ret_pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));

	if(ret_pid == 0) {
		syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
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
		FAIL() << "The child execveat failed." << std::endl;
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	/* We search for a child event. */
	evt_test->assert_event_presence(ret_pid, PPME_SYSCALL_EXECVE_19_X);

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Please note here we cannot assert all the params, we check only the possible ones. */

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: exe (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: args (type: PT_CHARBUFARRAY) */
	/* Starting from `1` because the first is `exe`. */
	evt_test->assert_charbuf_array_param(3, &argv[1]);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	// For comm parameter, we expect a different value depending on the kernel version. For kernel
	// versions lower than 6.14, if the `AT_EMPTY_PATH` flag is specified while invoking execveat,
	// we expect the comm value to be set to the dirfd numeric value. Starting from 6.14
	// (https://github.com/torvalds/linux/commit/543841d1806029889c2f69f040e88b247aba8e22), this
	// strange behaviour has been fixed, and the exact same execveat invocation results in the comm
	// value to be correctly set to the dentry's filename value. For this reason, we must account
	// for both scenarios.
	const auto dirfd_str = std::to_string(dirfd);
	const auto exe_path_basename = exe_path.substr(exe_path.find_last_of('/') + 1);
	const std::vector comm_candidates{
	        dirfd_str.c_str(),          // valid for kernel < 6.14
	        exe_path_basename.c_str(),  // valid since kernel >= 6.14
	};
	evt_test->assert_charbuf_param_any_of(14, comm_candidates);

	/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(28, exe_path.c_str());

	/* Parameter 31: filename (type: PT_FSPATH) */
	const std::string dirfd_path{"/dev/fd/" + dirfd_str};
	evt_test->assert_charbuf_param(31, dirfd_path.c_str());

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(31);
}

#endif  // __NR_execveat

#endif  // __NR_execve

#endif  // defined(__NR_clone3) && defined(__NR_wait4)
