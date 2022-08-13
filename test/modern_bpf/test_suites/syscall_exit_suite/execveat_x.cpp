#include "../../event_class/event_class.h"
#include "../../flags/flags_definitions.h"

#if defined(__NR_execveat) && defined(__NR_getrlimit) && defined(__NR_capget)

#include <sys/resource.h> // to get rlimit_resource

#define MAX_PATH 4096

TEST(SyscallExit, execveatX)
{
	auto evt_test = new event_test(__NR_execveat, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* We extract some info from proc before calling the syscall, in this way we are sure that
	 * the numbers that we will extract	in the BPF are surely greater or equal than the ones extracted now.
	 */
	pid_t process_pid = ::getpid();
	char path_to_read[MAX_PATH];

	/*
	 * Read some info regarding the stats of the process from `/proc/[pid]/stat`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/stat", process_pid);
	FILE* stat = fopen(path_to_read, "r");
	if(stat == NULL)
	{
		FAIL() << "'fopen /proc/[pid]/stat' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
	}

	int tty = 0;
	unsigned long minflt = 0;
	unsigned long majflt = 0;
	pid_t ppid = 0; /* The PID of the parent of this process. */
	pid_t pgid = 0; /* The process group ID of the process. */

	/* we could get the filename of the executable (`comm`) from proc, but it is returned
	 * in parentheses, so for example "(bpf_test)", so we prefer to use our macro `TEST_EXECUTABLE_NAME`
	 */
	if(fscanf(stat, "%*d %*s %*c %d %d %*d %d %*d %*u %lu %*u %lu", &ppid, &pgid, &tty, &minflt, &majflt) < 0)
	{
		FAIL() << "'fscanf /proc/[pid]/stat' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
	}
	fclose(stat);

	/*
	 * Read some info regarding the status of the process from `/proc/[pid]/status`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/status", process_pid);
	FILE* status = fopen(path_to_read, "r");
	if(status == NULL)
	{
		FAIL() << "'fopen /proc/[pid]/status' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
	}

	char line[MAX_PATH];
	char prefix[MAX_PATH];
	uint32_t vm_size = 0;
	uint32_t vm_rss = 0;
	uint32_t vm_swap = 0;
	uint32_t temp = 0;
	int found = 0;
	while(fgets(line, MAX_PATH, status) != NULL)
	{
		sscanf(line, "%s %d %*s\n", prefix, &temp);
		if(strncmp(prefix, "VmSize:", 8) == 0)
		{
			vm_size = temp;
			found++;
		}

		if(strncmp(prefix, "VmRSS:", 7) == 0)
		{
			vm_rss = temp;
			found++;
		}

		if(strncmp(prefix, "VmSwap:", 8) == 0)
		{
			vm_swap = temp;
			found++;
		}

		if(found == 3)
		{
			break;
		}
	}
	fclose(status);

	/*
	 * Read `loginuid` from `/proc/[pid]/loginuid`
	 */
	snprintf(path_to_read, sizeof(path_to_read), "/proc/%d/loginuid", process_pid);
	FILE* login = fopen(path_to_read, "r");
	if(login == NULL)
	{
		FAIL() << "'fopen /proc/[pid]/loginuid' must not fail: (" << errno << "), " << strerror(errno) << std::endl;
	}
	int loginuid = 0;
	if(fscanf(login, "%d", &loginuid) != 1)
	{
		FAIL() << "'fscanf /proc/[pid]/loginuid' must not fail." << std::endl;
	}
	fclose(login);

	/*
	 * Get the process capabilities.
	 */

	/* On kernels >= 5.8 the suggested version should be `_LINUX_CAPABILITY_VERSION_3` */
	struct __user_cap_header_struct header = {0};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	cap_user_header_t hdrp = &header;
	cap_user_data_t datap = data;

	/* Prepare the header. */
	header.pid = 0; /* `0` means the pid of the actual process. */
	header.version = _LINUX_CAPABILITY_VERSION_3;
	assert_syscall_state(SYSCALL_SUCCESS, "capget", syscall(__NR_capget, hdrp, datap), EQUAL, 0);

	/*
	 * Get rlimit
	 */
	struct rlimit file_rlimit = {0};
	assert_syscall_state(SYSCALL_SUCCESS, "getrlimit", syscall(__NR_getrlimit, RLIMIT_NOFILE, &file_rlimit), NOT_EQUAL, -1);

	/*
	 * Call the `execve`
	 */
	int dirfd = AT_FDCWD;
	char pathname[] = "//**null-file-path**//";
	const char* newargv[] = {pathname, "first_argv", "second_argv", NULL};
	const char* newenviron[] = {"IN_TEST=yes", "3_ARGUMENT=yes", "2_ARGUMENT=no", NULL};
	int flags = AT_SYMLINK_NOFOLLOW;
	assert_syscall_state(SYSCALL_FAILURE, "execveat", syscall(__NR_execveat, dirfd, pathname, newargv, newenviron, flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
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
	evt_test->assert_numeric_param(4, (int64_t)process_pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* We are the main thread of the process so it's equal to `tid`. */
	evt_test->assert_numeric_param(5, (int64_t)process_pid);

	/* Parameter 6: ptid (type: PT_PID) */
	evt_test->assert_numeric_param(6, (int64_t)ppid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	evt_test->assert_empty_param(7);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	evt_test->assert_numeric_param(8, (uint64_t)file_rlimit.rlim_cur);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	evt_test->assert_numeric_param(9, (uint64_t)majflt, GREATER_EQUAL);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	evt_test->assert_numeric_param(10, (uint64_t)minflt, GREATER_EQUAL);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	evt_test->assert_numeric_param(11, (uint32_t)vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	evt_test->assert_numeric_param(12, (uint32_t)vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	evt_test->assert_numeric_param(13, (uint32_t)vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	evt_test->assert_charbuf_param(14, TEST_EXECUTABLE_NAME);

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	evt_test->assert_cgroup_param(15);

	/* Parameter 16: env (type: PT_CHARBUFARRAY) */
	evt_test->assert_charbuf_array_param(16, &newenviron[0]);

	/* Parameter 17: tty (type: PT_UINT32) */
	evt_test->assert_numeric_param(17, (uint32_t)tty);

	/* Parameter 18: pgid (type: PT_PID) */
	/* If we run in a namespace different from the init one probably this will fail. */
	evt_test->assert_numeric_param(18, (int64_t)pgid);

	/* Parameter 19: loginuid (type: PT_UINT32) */
	evt_test->assert_numeric_param(19, (uint32_t)loginuid);

	/* Parameter 20: flags (type: PT_UINT32) */
	/* Right now we send always `0`. */
	evt_test->assert_numeric_param(20, (uint32_t)0);

	/* Parameter 21: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(21, (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) | data[0].inheritable));

	/* Parameter 22: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(22, (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) | data[0].permitted));

	/* Parameter 23: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(23, (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) | data[0].effective));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(23);
}
#endif
