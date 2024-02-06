#include "../../event_class/event_class.h"
#include <gtest/gtest.h>

#ifdef __NR_process_vm_writev

TEST(SyscallExit, process_vm_writevX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_process_vm_writev, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	size_t res = syscall(__NR_process_vm_writev, getpid(), (void*)(0x41414141), 0, (void*)(0x42424242), 0, 0);
	assert_syscall_state(SYSCALL_FAILURE, "process_vm_writev", res, EQUAL, 0);

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
	evt_test->assert_numeric_param(1, (int64_t)0);

	/* Parameter 2: pid (type: PT_PID) */
	evt_test->assert_numeric_param(2, (int64_t)getpid());

	/* Parameter 3: data (type: PT_BYTEBUF)*/
	evt_test->assert_empty_param(3);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}

TEST(SyscallExit, process_vm_writevX_success)
{
	auto evt_test = get_syscall_event_test(__NR_process_vm_writev, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int pipe_fd[2];

	ASSERT_GT(pipe(pipe_fd), -1);

	pid_t parent_pid = getpid();
	pid_t child_pid = fork();

	if(child_pid == 0)
	{

		char buf[10] = "QWERTYUIO";
		struct iovec local[1];
		local[0].iov_base = buf;
		local[0].iov_len = sizeof(buf);
		void* target;

		close(pipe_fd[1]);

		ssize_t read = syscall(__NR_read, pipe_fd[0], &target, sizeof(void*));
		ASSERT_GT(read, 0);

		read = syscall(__NR_process_vm_writev, parent_pid, local, 1, target, 1, 0);
		assert_syscall_state(SYSCALL_SUCCESS, "process_vm_writev", read, NOT_EQUAL, 0);

		close(pipe_fd[0]);

		exit(EXIT_SUCCESS);
	}
	else
	{

		char buf[10];
		struct iovec local[1];
		local[0].iov_base = (void*)buf;
		local[0].iov_len = sizeof(buf);
		void* target = &local;

		close(pipe_fd[0]);

		ssize_t res = write(pipe_fd[1], &target, sizeof(void*));
		ASSERT_GT(res, 0);

		close(pipe_fd[1]);

		int wstatus;
		waitpid(child_pid, &wstatus, 0);
	}

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence(child_pid);

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
	evt_test->assert_numeric_param(2, (int64_t)parent_pid);

	/* Parameter 3: data (type: PT_BYTEBUF) */
	evt_test->assert_charbuf_param(3, "QWERTYUIO");

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
