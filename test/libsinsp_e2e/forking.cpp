// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "event_capture.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <libscap/scap-int.h>
#include <libsinsp/event.h>
#include <poll.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <list>
#include <mutex>

#define FILENAME "test_tmpfile"

TEST_F(sys_call_test, forking)
{
	//	int callnum = 0;

	int ptid;          // parent tid
	int ctid;          // child tid
	int gptid;         // grandparent tid
	int xstatus = 33;  // child exit value

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == ptid || evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		pid_t childtid;
		int status;
		childtid = fork();

		int fd = creat(FILENAME, S_IRWXU);

		if (childtid >= 0)  // fork succeeded
		{
			if (childtid == 0)  // fork() returns 0 to the child process
			{
				ctid = getpid();
				usleep(100);  // sleep for 0.1 seconds
				close(fd);
				_exit(xstatus);  // child exits with specific return code
			}
			else  // fork() returns new pid to the parent process
			{
				ptid = getpid();
				gptid = getppid();

				close(fd);

				wait(&status);  // wait for child to exit, and store its status
				                // Use WEXITSTATUS to validate status.
			}
		}
		else
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, forking_while_scap_stopped)
{
	int ptid;          // parent tid
	int ctid;          // child tid
	int xstatus = 33;  // child exit value

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == ptid || evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		int status;

		//
		// Stop the capture just before the fork so we lose the event.
		//
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->stop_capture();
		}

		ctid = fork();

		int fd = creat(FILENAME, S_IRWXU);

		if (ctid >= 0)  // fork succeeded
		{
			if (ctid == 0)  // fork() returns 0 to the child process
			{
				//
				// Restart the capture.
				// This is a bit messy because we are in the child
				// but it works because the underlying scap's fds
				// are duplicated so the ioctl will make its way to
				// the parent process as well.
				// It's a simple way to make sure the capture is started
				// after the child's clone returned.
				//
				inspector_handle.unsafe_ptr()->start_capture();

				//
				// Wait for 5 seconds to make sure the process will still
				// exist when the sinsp will do the lookup to /proc
				//
				usleep(5000000);
				close(fd);
				_exit(xstatus);  // child exits with specific return code
			}
			else  // fork() returns new pid to the parent process
			{
				ptid = getpid();

				close(fd);

				wait(&status);  // wait for child to exit, and store its status
				// Use WEXITSTATUS to validate status.
			}
		}
		else
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	bool child_exists = false;
	bool parent_exists = false;

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if (e->get_type() == PPME_SCHEDSWITCH_1_E || e->get_type() == PPME_SCHEDSWITCH_6_E ||
		    e->get_type() == PPME_PROCINFO_E)
		{
			return;
		}

		//
		// In both cases, the process should exist
		//
		if (e->get_tid() == ptid && !parent_exists)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if (ti)
			{
				parent_exists = true;
			}

			EXPECT_NE((sinsp_threadinfo*)NULL, ti);
		}

		if (e->get_tid() == ctid && !child_exists)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if (ti)
			{
				child_exists = true;
			}

			EXPECT_NE((sinsp_threadinfo*)NULL, ti);
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_TRUE(child_exists);
	EXPECT_TRUE(parent_exists);
}

TEST_F(sys_call_test, forking_process_expired)
{
	int ptid;  // parent tid
	int ctid;  // child tid
	int status;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return evt->get_tid() == ptid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		ctid = fork();

		if (ctid >= 0)  // fork succeeded
		{
			if (ctid == 0)  // fork() returns 0 to the child process
			{
				pause();
				FAIL();
			}
			else  // fork() returns new pid to the parent process
			{
				ptid = getpid();

				//
				// Wait 10 seconds. During this time, the process should NOT be removed
				//
				struct timespec req, rem;
				req.tv_sec = 10;
				req.tv_nsec = 0;

				syscall(__NR_nanosleep, &req, &rem);

				kill(ctid, SIGUSR1);
				wait(&status);
			}
		}
		else
		{
			FAIL();
		}
	};

	bool sleep_caught = false;

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if (e->get_tid() == ptid)
		{
			if (e->get_type() == PPME_SYSCALL_NANOSLEEP_E && !sleep_caught)
			{
				//
				// The child should exist
				//
				sinsp_threadinfo* ti = param.m_inspector->get_thread_ref(ctid, false, true).get();
				EXPECT_NE((sinsp_threadinfo*)NULL, ti);
			}
			else if (e->get_type() == PPME_SYSCALL_NANOSLEEP_X && !sleep_caught)
			{
				//
				// The child should exist
				//
				sinsp_threadinfo* ti = param.m_inspector->get_thread_ref(ctid, false, true).get();
				EXPECT_NE((sinsp_threadinfo*)NULL, ti);
				sleep_caught = true;
			}
		}
		else
		{
			FAIL();
		}
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
						   event_capture::do_nothing,
						   event_capture::do_nothing,
						   event_capture::always_continue,
						   131072,
						   5 * ONE_SECOND_IN_NS,
		                   ONE_SECOND_IN_NS);
	});

	EXPECT_TRUE(sleep_caught);
}

///////////////////////////////////////////////////////////////////////////////
// CLONE VARIANTS
///////////////////////////////////////////////////////////////////////////////
int ctid;  // child tid

typedef struct
{
	int fd;
	int signal;
} clone_params;

static int clone_callback_1(void* arg)
{
	clone_params* cp;

	cp = (clone_params*)arg; /* Cast arg to true form */
	// getpid() is cached by glibc, usually is invalidated
	// correctly in case of fork() or clone() but since we are
	// using a weird clone() here something goes wrong with
	// recent version of glibc
	ctid = syscall(SYS_getpid);
	fsync(cp->fd);
	close(cp->fd);
	return 0;
}

/*
 * The `sys_call_test.forking_clone_fs` e2e test makes the assuption
 * that, if a children closes a file descriptor, the parent trying
 * to close the same file descriptor will get an error. This seems
 * not to be always the case. As the man says `It is probably unwise
 * to close file descriptors while they may be in use by system calls
 * in other threads in the same process.  Since a file descriptor may
 * be reused, there are some obscure race conditions that may cause
 * unintended side effects.` Given that we'll disable it upon further
 * investigation.
 */
TEST_F(sys_call_test, DISABLED_forking_clone_fs)
{
	int callnum = 0;
	char bcwd[1024];
	int prfd;
	int ptid;  // parent tid
	pid_t clone_tid;
	int child_tid;
	int parent_res;
	int flags = CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_PARENT_SETTID;
	int drflags = PPM_CL_CLONE_FILES | PPM_CL_CLONE_FS | PPM_CL_CLONE_VM | PPM_CL_CLONE_PARENT_SETTID;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == ptid || evt->get_tid() == child_tid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		const int STACK_SIZE = 65536; /* Stack size for cloned child */
		char* stack;                  /* Start of stack buffer area */
		char* stackTop;               /* End of stack buffer area */
		clone_params cp;              /* Passed to child function */
		int status;
		pid_t pid;

		ptid = gettid();

		/* Set up an argument structure to be passed to cloned child, and
		   set some process attributes that will be modified by child */

		cp.fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU); /* Child will close this fd */
		if (cp.fd == -1)
			FAIL();
		prfd = cp.fd;

		cp.signal = SIGTERM; /* Child will change disposition */
		if (signal(cp.signal, SIG_IGN) == SIG_ERR)
			FAIL();

		/* Initialize clone flags using command-line argument (if supplied) */

		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
			FAIL();
		stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		clone_tid = clone(clone_callback_1, stackTop, flags, &cp,
								&child_tid);
		if (clone_tid == -1)
			FAIL();

		/* Parent falls through to here. Wait for child; __WCLONE option is
		   required for child notifying with signal other than SIGCHLD. */

		pid = waitpid(clone_tid, &status, __WCLONE);
		if (pid == -1)
			FAIL();

		close(cp.fd);
		parent_res = -errno;

		free(stack);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if (e->get_type() == PPME_SYSCALL_CLONE_20_X && callnum == 0)
		{
			uint64_t res = std::stoll(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (ti->get_comm() != "libsinsp_e2e_te")
			{
				return;
			}

			if (res == 0)
			{
				EXPECT_EQ(child_tid, ti->m_tid);
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);
			}

			EXPECT_NE(std::string::npos, e->get_param_value_str("exe").find("libsinsp_e2e_tests"));
			EXPECT_EQ("libsinsp_e2e_te", ti->get_comm());
			std::string tmps = getcwd(bcwd, 1024);
			EXPECT_EQ(tmps + "/", ti->get_cwd());
			EXPECT_EQ("<NA>", e->get_param_value_str("cwd"));
			if(drflags == std::stol(e->get_param_value_str("flags", false)))
			{
				callnum++;
			}
		}
		else if (e->get_type() == PPME_SYSCALL_CLOSE_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (ti->m_tid == ptid || ti->m_tid == child_tid)
			{
				int64_t clfd = std::stoll(e->get_param_value_str("fd", false));

				if (clfd == prfd)
				{
					callnum++;
				}
			}
		}
		else if (e->get_type() == PPME_SYSCALL_CLOSE_X)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (callnum < 3)
			{
				return;
			}

			int64_t res = std::stoll(e->get_param_value_str("res", false));

			if (ti->m_tid == ptid)
			{
				sinsp_fdinfo* fdi = ti->get_fd(prfd);
				if(fdi && fdi->tostring_clean().find(FILENAME) != std::string::npos)
				{
					EXPECT_EQ(parent_res, res) << "filename: "
											   << fdi->tostring_clean() << std::endl
											   << "res: " << res << std::endl
											   << "parent tid: " << ptid << std::endl
											   << "child  tid: " << child_tid << std::endl
											   << "clone  tid: " << clone_tid << std::endl;
				}
			}
			else if (ti->m_tid == child_tid)
			{
				EXPECT_EQ(0, res);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(callnum, 4);
}

TEST_F(sys_call_test, forking_clone_nofs)
{
	int callnum = 0;
	char bcwd[1024];
	int prfd;
	int ptid;  // parent tid
	int flags = CLONE_FS | CLONE_VM;
	int drflags = PPM_CL_CLONE_FS | PPM_CL_CLONE_VM;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == ptid || evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		const int STACK_SIZE = 65536; /* Stack size for cloned child */
		char* stack;                  /* Start of stack buffer area */
		char* stackTop;               /* End of stack buffer area */
		clone_params cp;              /* Passed to child function */
		int status;
		pid_t pid;

		ptid = getpid();

		/* Set up an argument structure to be passed to cloned child, and
		   set some process attributes that will be modified by child */

		cp.fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU); /* Child will close this fd */
		if (cp.fd == -1)
			FAIL();
		prfd = cp.fd;

		cp.signal = SIGTERM; /* Child will change disposition */
		if (signal(cp.signal, SIG_IGN) == SIG_ERR)
			FAIL();

		/* Initialize clone flags using command-line argument (if supplied) */

		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
			FAIL();
		stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_1, stackTop, flags, &cp) == -1)
			FAIL();

		/* Parent falls through to here. Wait for child; __WCLONE option is
		   required for child notifying with signal other than SIGCHLD. */

		pid = waitpid(-1, &status, __WCLONE);
		if (pid == -1)
			FAIL();

		close(cp.fd);

		sleep(1);
		free(stack);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if (e->get_type() == PPME_SYSCALL_CLONE_20_X && callnum == 0)
		{
			uint64_t res = std::stoull(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (ti->get_comm() != "libsinsp_e2e_te")
			{
				return;
			}

			if (res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);
			}

			EXPECT_NE(std::string::npos, e->get_param_value_str("exe").find("libsinsp_e2e_te"));
			EXPECT_EQ("libsinsp_e2e_te", ti->get_comm());
			std::string tmps = getcwd(bcwd, 1024);
			EXPECT_EQ(tmps + "/", ti->get_cwd());
			EXPECT_EQ("<NA>", e->get_param_value_str("cwd"));
			if(drflags == std::stol(e->get_param_value_str("flags", false)))
			{
				callnum++;
			}
		}
		else if (e->get_type() == PPME_SYSCALL_CLOSE_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (ti->m_tid == ptid || ti->m_tid == ctid)
			{
				int64_t clfd = std::stoll(e->get_param_value_str("fd", false));

				if (clfd == prfd)
				{
					callnum++;
				}
			}
		}
		else if (e->get_type() == PPME_SYSCALL_CLOSE_X)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (callnum < 3)
			{
				return;
			}

			int64_t res = std::stoll(e->get_param_value_str("res", false));

			if (ti->m_tid == ptid)
			{
				EXPECT_EQ(0, res);
			}
			else if (ti->m_tid == ctid)
			{
				EXPECT_EQ(0, res);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(callnum, 4);
}

static int clone_callback_2(void* arg)
{
	char bcwd[256];

	if (chdir("/") != 0)
	{
		return -1;
	}
	std::string tmps = getcwd(bcwd, 256);
	syscall(SYS_exit);
	return -1;
}

TEST_F(sys_call_test, forking_clone_cwd)
{
	int callnum = 0;
	char oriwd[1024];
	char bcwd[256];
	int ptid;  // parent tid
	int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
	int drflags = PPM_CL_CLONE_VM | PPM_CL_CLONE_FS | PPM_CL_CLONE_FILES | PPM_CL_CLONE_SIGHAND |
	              PPM_CL_CLONE_THREAD;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return evt->get_tid() == ptid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		const int STACK_SIZE = 65536; /* Stack size for cloned child */
		char* stack;                  /* Start of stack buffer area */
		char* stackTop;               /* End of stack buffer area */
		clone_params cp;              /* Passed to child function */

		ptid = getpid();

		ASSERT_TRUE(getcwd(oriwd, 1024) != NULL);

		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
			FAIL();
		stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_2, stackTop, flags, &cp) == -1)
		{
			FAIL();
		}

		sleep(1);

		std::string tmps = getcwd(bcwd, 256);

		ASSERT_TRUE(chdir(oriwd) == 0);

		sleep(1);
		free(stack);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if (e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			uint64_t res = std::stoull(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if (ti->get_comm() != "libsinsp_e2e_te")
			{
				return;
			}

			if (res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);
			}

			EXPECT_NE(std::string::npos, e->get_param_value_str("exe").find("libsinsp_e2e_tests"));
			EXPECT_EQ("libsinsp_e2e_te", ti->get_comm());
			EXPECT_EQ(drflags, std::stol(e->get_param_value_str("flags", false)));
			callnum++;
		}
		else if (e->get_type() == PPME_SYSCALL_GETCWD_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if (ti->m_tid == ptid)
			{
				if (callnum > 1)
				{
					EXPECT_EQ(bcwd, ti->get_cwd());
				}
			}
			else if (ti->m_tid == ctid)
			{
				EXPECT_EQ("/", ti->get_cwd());
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(3, callnum);
}

TEST_F(sys_call_test, forking_main_thread_exit)
{
	int evtnum = 0;
	int callnum = 0;
	int fd;
	pid_t cpid;  // parent tid

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		sinsp_threadinfo* ti = evt->get_thread_info();
		if (ti)
		{
			return ti->m_pid == cpid;
		}
		else
		{
			return false;
		}
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		int status;

		// ptid = getpid();

		cpid = fork();
		EXPECT_NE(-1, cpid);
		if (cpid == 0)
		{
			execlp(LIBSINSP_TEST_RESOURCES_PATH "/forking_main_thread_exit",
			       LIBSINSP_TEST_RESOURCES_PATH "/forking_main_thread_exit",
			       NULL);
			perror("execlp");
			FAIL();
		}
		else
		{
			//
			// Father, just wait for termination
			//
			wait(&status);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		evtnum++;
		if (param.m_evt->get_type() == PPME_SYSCALL_OPEN_X)
		{
			if (param.m_evt->get_param_value_str("name") == "/etc/passwd")
			{
				EXPECT_EQ("<f>/etc/passwd", param.m_evt->get_param_value_str("fd"));
				fd = *(int64_t*)param.m_evt->get_param(0)->m_val;
				++callnum;
			}
		}
		else if (param.m_evt->get_type() == PPME_SYSCALL_OPENAT_2_X)
		{
			if (param.m_evt->get_param_value_str("name") == "/etc/passwd")
			{
				EXPECT_EQ("<f>/etc/passwd", param.m_evt->get_param_value_str("fd"));
				memcpy(&fd, (int64_t*)param.m_evt->get_param(0)->m_val, sizeof(fd));
				++callnum;
			}
		}
		else if (param.m_evt->get_type() == PPME_PROCEXIT_1_E && param.m_evt->get_tid() == cpid)
		{
			++callnum;
		}
		else if (param.m_evt->get_type() == PPME_SYSCALL_READ_E)
		{
			if (memcmp(&fd, param.m_evt->get_param(0)->m_val, sizeof(fd)) == 0)
			{
				EXPECT_EQ("<f>/etc/passwd", param.m_evt->get_param_value_str("fd"));
				++callnum;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(3, callnum);
}

// This test generally does the following:
//  - Ensures that a stale process exists
//  - Starts another process with the same pid as the stale process, in a pid
//    namespace (which counts as "in a container").
//  - Checks to see if the stale process information is used.
//
//  To distinguish between the stale process and up-to-date process, use the
//  working directory of the process. The stale process sets its working
//  directory to "/dev".
//
//  Prior to the fix for 664, the stale process would be used and the
//  working directory of the second process would (mistakenly) be
//  /dev. With the fix, the stale process information is detected and
//  removed.
//

// Create the initial stale process. It chdir()s to "/dev", stops the
// inspector, and returns.
static int stop_sinsp_and_exit(void* arg)
{
	// Get our own, unlocked concurrent inspector handle
	concurrent_object_handle<sinsp> inspector_handle = *(concurrent_object_handle<sinsp>*)arg;

	if (chdir("/dev") != 0)
	{
		return 1;
	}

	{
		std::scoped_lock inspector_handle_lock(inspector_handle);
		inspector_handle->stop_capture();
	}

	// Wait 5 seconds. This ensures that the state for this
	// process will be considered stale when the second process
	// with the same pid runs.
	sleep(5);

	return 0;
}

// Immediately return. Started by launcher.
static int do_nothing(void* arg)
{
	return 0;
}

struct stale_clone_ctx
{
	std::mutex m_perform_clone_mtx;
	std::condition_variable m_perform_clone;
	bool m_clone_ready;
	bool m_clone_complete;
};

static pid_t clone_helper(int (*func)(void*),
                          void* arg,
                          int addl_clone_args = 0,
                          bool wait_for_complete = true,
                          char** stackp = NULL);

// Wait until signaled by the main test thread, start a single
// do_nothing(), signal the main test thread, and exit.
static int launcher(void* arg)
{
	stale_clone_ctx* ctx = (stale_clone_ctx*)arg;
	std::unique_lock<std::mutex> lk(ctx->m_perform_clone_mtx);
	ctx->m_perform_clone.wait(lk, [&] { return ctx->m_clone_ready; });

	pid_t child = clone_helper(do_nothing, NULL);
	EXPECT_NE(child, 0);

	ctx->m_clone_complete = true;
	lk.unlock();
	ctx->m_perform_clone.notify_one();

	if (child == 0)
	{
		return 1;
	}

	return 0;
}

// Start a new thread using clone(), passing the provided arg.  On
// success, returns the process id of the thread that was created.
// On failure, returns 0. Used to start all the other actions.

static pid_t clone_helper(int (*func)(void*),
                          void* arg,
                          int addl_clone_args,
                          bool wait_for_complete,
                          char** stackp)
{
	const int STACK_SIZE = 65536; /* Stack size for cloned child */
	char* stack;                  /* Start of stack buffer area */
	char* stackTop;               /* End of stack buffer area */
	int flags = CLONE_VM | CLONE_FILES | SIGCHLD | addl_clone_args;
	pid_t pid = 0;

	/* Allocate stack for child */
	stack = (char*)malloc(STACK_SIZE);
	if (stack == NULL)
	{
		return 0;
	}

	stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

	if ((pid = clone(func, stackTop, flags, arg)) == -1)
	{
		free(stack);
		return 0;
	}

	if (wait_for_complete)
	{
		int status;

		if (waitpid(pid, &status, 0) == -1 || status != 0)
		{
			pid = 0;
		}
		free(stack);
	}
	else
	{
		*stackp = stack;
	}

	return pid;
}

TEST_F(sys_call_test, remove_stale_thread_clone_exit)
{
	std::atomic<uint32_t> clones_seen(0);
	stale_clone_ctx ctx;
	std::atomic<pid_t> recycle_pid(0);
	const char* last_pid_filename = "/proc/sys/kernel/ns_last_pid";
	struct stat info;

	ctx.m_clone_ready = false;
	ctx.m_clone_complete = false;

	// On some operating systems,
	// /proc/sys/kernel/ns_last_pid does not exist. In
	// those cases, we print a message and trivially pass
	// the test.

	if (stat(last_pid_filename, &info) == -1 && errno == ENOENT)
	{
		fprintf(stderr, "Doing nothing as %s does not exist\n", last_pid_filename);
		return;
	}

	// All events matching recycle_pid are selected. Since
	// recycle_pid is only set once the first thread exits, this
	// effectively captures the actions of the second thread that
	// uses the recycled pid.
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();
		pid_t rp = recycle_pid.load();
		return (rp != 0 && tinfo && tinfo->m_tid == rp);
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		pid_t launcher_pid;
		char* launcher_stack = NULL;

		// Start a thread that simply waits until signaled,
		// and then creates a second do-nothing thread. We'll
		// arrange that the host-facing pid is set to a known
		// value before this thread creates the second thread.
		launcher_pid = clone_helper(launcher, &ctx, CLONE_NEWPID, false, &launcher_stack);
		ASSERT_GE(launcher_pid, 0);

		// This is asynchronous so wait to make sure the thread has started.
		sleep(1);

		// Start a thread that runs and stops the inspector_handle right
		// before exiting. This gives us a pid we can use for the
		// second thread.
		recycle_pid.store(clone_helper(stop_sinsp_and_exit, &inspector_handle));
		ASSERT_GE(recycle_pid.load(), 0);

		// The first thread has started, turned off the capturing, and
		// exited, so start capturing again.
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->start_capture();
		}

		// Arrange that the next thread/process created has
		// pid ctx.m_desired pid by writing to
		// ns_last_pid. Unfortunately, this has a race
		// condition--it's possible that after writing to
		// ns_last_pid another different process is started,
		// stealing the pid. However, as long as the process
		// doesn't have a working directory of "/dev", that
		// will be enough to distinguish it from the stale
		// process.

		FILE* last_pid_file;

		{
			std::lock_guard<std::mutex> lk(ctx.m_perform_clone_mtx);

			last_pid_file = fopen(last_pid_filename, "w");

			ASSERT_NE(last_pid_file, (FILE*)NULL);

			ASSERT_EQ(flock(fileno(last_pid_file), LOCK_EX), 0);

			ASSERT_GT(fprintf(last_pid_file, "%d", recycle_pid.load() - 1), 0);

			fclose(last_pid_file);

			ctx.m_clone_ready = true;
		}

		// Signal the launcher thread telling it to start the do_nothing thread.
		ctx.m_perform_clone.notify_one();

		// Wait to be signaled back from the launcher thread that it's done.
		{
			std::unique_lock<std::mutex> lk(ctx.m_perform_clone_mtx);

			ctx.m_perform_clone.wait(lk, [&] { return ctx.m_clone_complete; });
		}

		// The launcher thread should have exited, but just to
		// make sure explicitly kill it.
		ASSERT_EQ(kill(launcher_pid, SIGTERM), 0);

		free(launcher_stack);

		return;
	};

	// To verify the actions, the filter selects all events
	// related to pid recycled_pid. It should see:
	//     - a clone() representing the second thread using the recycled pid.
	//     - events with pid=recycled_pid (the do_nothing started by
	//       create_do_nothings) and cwd=<where the test is run>
	//
	//       If any event with pid=recycled_pid has a cwd of
	//       /dev/, the test fails.

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t etype = e->get_type();
		sinsp_threadinfo* tinfo = e->get_thread_info();
		ASSERT_TRUE((tinfo != NULL));

		if ((etype == PPME_SYSCALL_CLONE_11_X || etype == PPME_SYSCALL_CLONE_16_X ||
		     etype == PPME_SYSCALL_CLONE_17_X || etype == PPME_SYSCALL_CLONE_20_X) &&
		    e->get_direction() == SCAP_ED_OUT)
		{
			++clones_seen;
		}

		EXPECT_STRNE(tinfo->get_cwd().c_str(), "/dev/");
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	// We must have seen one clone related to the recycled
	// pid. Otherwise it never actually checked the cwd at all.
	EXPECT_EQ(clones_seen.load(), 1u);
}
