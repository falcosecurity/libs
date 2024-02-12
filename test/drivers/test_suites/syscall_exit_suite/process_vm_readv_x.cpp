#include "../../event_class/event_class.h"

#ifdef __NR_process_vm_readv

TEST(SyscallExit, process_vm_readvX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_process_vm_readv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	char buf[16];
	iovec iov[] = {{buf, 16}};
	int32_t iovcnt = 7;

	size_t res = syscall(__NR_process_vm_readv, getpid(), iov, iovcnt, iov, iovcnt, 0);
	assert_syscall_state(SYSCALL_FAILURE, "process_vm_readv", res, EQUAL, -1);

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

	/* Parameter 1: res (type: PT_INT64) */
	evt_test->assert_numeric_param(1, (int64_t)-1, LESS_EQUAL);

	/* Parameter 2: pid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)getpid());

	/* Parameter 3: data (type: PT_BYTEBUF)*/
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, process_vm_readvX_success)
{
	auto evt_test = get_syscall_event_test(__NR_process_vm_readv, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int pipe_fd[2];

	ASSERT_GT(pipe(pipe_fd), -1);

	pid_t child_pid = fork();

	if(child_pid == 0)
	{

		char buf[10] = "QWERTYUIO";
		struct iovec remote[1];
		remote[0].iov_base = (void*)buf;
		remote[0].iov_len = sizeof(buf);
		void* target = &remote;

		close(pipe_fd[0]);

		ssize_t read = write(pipe_fd[1], &target, sizeof(void*));
		ASSERT_GT(read, 0);

		/*
		 * The following write call makes sure that the process_vm_readv
		 * has been called.
		 */
		read = write(pipe_fd[1], buf, 2);
		ASSERT_GT(read, 0);

		close(pipe_fd[1]);

		exit(EXIT_SUCCESS);
	}
	else
	{

		char buffer[10];
		struct iovec local[1];
		local[0].iov_base = buffer;
		local[0].iov_len = sizeof(buffer);
		void* target;

		close(pipe_fd[1]);

		ssize_t read = syscall(__NR_read, pipe_fd[0], &target, sizeof(void*));
		ASSERT_GT(read, 0);

		read = syscall(__NR_process_vm_readv, child_pid, local, 1, target, 1, 0);
		assert_syscall_state(SYSCALL_SUCCESS, "process_vm_readv", read, NOT_EQUAL, 0);

		close(pipe_fd[0]);

		int wstatus;
		waitpid(child_pid, &wstatus, 0);
	}

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

	/* Parameter 1: res (type: PT_INT64) */
	evt_test->assert_numeric_param(1, (int64_t)10);

	/* Parameter 2: pid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)child_pid);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_charbuf_param(3, "QWERTYUIO");

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
