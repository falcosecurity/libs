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

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/eventfd.h>
#include <sys/wait.h>
#define _GNU_SOURCE
#include <linux/sched.h>

/**
 *
 * We want a process in a pidns to end up with pid==vpid and then call fork()
 *
 * To generate this tid/vtid collision, we run two fork() loops, one in the
 * parent namespace and one in the child namespace. The point of running all
 * these forks is to advance the pid counter in the parent ns faster than in
 * the child ns, so that they meet at some point (similar to detecting cycles
 * in a linked list)
 *
 * To do this, we set up a multilevel tree of processes:
 * - the main process
 *   - spawns a subprocess
 *   - spins in a fork() loop until it gets notified (via eventfd) that we're done
 *     all children processes exit immediately (they are needed only to advance the pid counter)
 *
 * - the subprocess
 *   - calls unshare() to place its children in a new pidns
 *   - fork()s the new pidns init process
 *
 * - the pidns init
 *   - spins in a fork loop until notified (via another eventfd)
 *     every child:
 *     - checks its vpid (from getpid()) against the initns pid (from readlink("/proc/self"))
 *     - if not, exits immediately
 *     - otherwise:
 *       - sets its uid to its own pid (which should be a pretty unlikely uid value otherwise)
 *       - forks yet again, to display the child process's pid, vpid and ppid
 *    - waits for all its children to exit (otherwise all processes in the pidns
 *      get SIGKILLed when the pidns init exits)
 *
 *
 */

void waitall()
{
	int status;
	while (wait(&status) == 0 || errno == EAGAIN)
	{
	}
}

int child_main(int efd, int parent_efd)
{
	char buf[64];
	char* endptr;
	long init_ns_pid;

	unsigned long efd_counter = 0;

	while (efd_counter < 2)
	{
		switch (fork())
		{
		case -1:
			abort();

		case 0:
			if (readlink("/proc/self", buf, sizeof(buf)) <= 0)
			{
				eventfd_write(efd, 2);
				_exit(1);
			}

			init_ns_pid = strtoul(buf, &endptr, 10);

			if (getpid() == init_ns_pid)
			{
				int pid = getpid();

				usleep(100000);
				eventfd_write(efd, 2);

				if (setuid(getpid()) != 0 || seteuid(getpid()) != 0)
				{
					_exit(1);
				}

				switch (fork())
				{
				case -1:
					abort();

				case 0:
					if (readlink("/proc/self", buf, sizeof(buf)) <= 0)
					{
						_exit(1);
					}

					init_ns_pid = strtoul(buf, &endptr, 10);
					printf("vpid %d pid %ld ppid %d\n", getpid(), init_ns_pid, pid);
					fflush(stdout);
					sleep(2);
					_exit(0);

				default:
					waitall();
					_exit(0);
				}
			}

			_exit(0);

		default:
			eventfd_read(efd, &efd_counter);
			break;
		}
	}
	if (eventfd_write(parent_efd, 2) != 0)
	{
		abort();
	}
	waitall();

	return 0;
}

int parent_main(int efd)
{
	unsigned long efd_counter = 0;
	int ret;

	while (efd_counter < 2)
	{
		switch (fork())
		{
		case -1:
			abort();

		case 0:
			_exit(0);

		default:
			ret = eventfd_read(efd, &efd_counter);
			if (ret >= 2)
			{
				abort();
			}
			break;
		}
	}
	// do not wait for the pidns children to exit, we need the last level
	// subprocess still available after the parent exits
	return 0;
}

int main()
{
	printf("STARTED\n");
	fflush(stdout);
	signal(SIGCHLD, SIG_IGN);

	int efd = eventfd(1, EFD_NONBLOCK);
	int parent_efd = eventfd(1, EFD_NONBLOCK);
	switch (fork())
	{
	case -1:
		return 1;
	case 0:
		if (unshare(CLONE_NEWPID) != 0)
		{
			abort();
		}
		switch (fork())
		{
		case -1:
			abort();
		case 0:
			return child_main(efd, parent_efd);
		default:
			waitall();
			return 0;
		}
	default:
		return parent_main(parent_efd);
	}
}
