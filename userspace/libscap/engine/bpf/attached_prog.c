// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libscap/engine/bpf/attached_prog.h>
#include <stdio.h>
#include <stdlib.h>
#include <libscap/scap.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <libscap/strerror.h>
#include <libscap/compat/misc.h>
#include <libscap/compat/bpf.h>
#include <libscap/compat/perf_event.h>
#include <libscap/strl.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/*=============================== INTERNALS ===============================*/

static int __attach_raw_tp(struct bpf_attached_prog* prog, char* last_err)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.raw_tracepoint.name = (unsigned long)prog->name;
	attr.raw_tracepoint.prog_fd = prog->fd;

	prog->efd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	if(prog->efd < 0)
	{
		return scap_errprintf(last_err, -prog->efd, "BPF_RAW_TRACEPOINT_OPEN: event %s", prog->name);
	}
	return SCAP_SUCCESS;
}

static int __attach_tp(struct bpf_attached_prog* prog, char* last_err)
{
	int efd = 0;
	int err = 0;
	char buf[SCAP_MAX_PATH_SIZE];
	snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/id", prog->name);
	efd = open(buf, O_RDONLY, 0);
	if(efd < 0)
	{
		if(strcmp(prog->name, "exceptions/page_fault_user") == 0 ||
		   strcmp(prog->name, "exceptions/page_fault_kernel") == 0)
		{
			return SCAP_SUCCESS;
		}

		return scap_errprintf(last_err, errno, "failed to open event %s", prog->name);
	}

	err = read(efd, buf, sizeof(buf));
	if(err < 0 || err >= sizeof(buf))
	{
		int err = errno;
		close(efd);
		return scap_errprintf(last_err, err, "read from '%s' failed", prog->name);
	}
	close(efd);

	buf[err] = 0;
	int id = atoi(buf);

	struct perf_event_attr attr = {};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;

	efd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
	if(efd < 0)
	{
		return scap_errprintf(last_err, -efd, "event %d", id);
	}

	if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog->fd))
	{
		int err = errno;
		close(efd);
		return scap_errprintf(last_err, err, "PERF_EVENT_IOC_SET_BPF");
	}
	prog->efd = efd;
	return SCAP_SUCCESS;
}

/*=============================== INTERNALS ===============================*/

bool is_sys_enter(const char* name)
{
	/* We need the double-check because it could be a raw_tracepoint or a plain tracepoint */
	return (memcmp(name, "sys_enter", sizeof("sys_enter") - 1) == 0) ||
	       (memcmp(name, "raw_syscalls/sys_enter", sizeof("raw_syscalls/sys_enter") - 1) == 0);
}

bool is_sys_exit(const char* name)
{
	return (memcmp(name, "sys_exit", sizeof("sys_exit") - 1) == 0) ||
	       (memcmp(name, "raw_syscalls/sys_exit", sizeof("raw_syscalls/sys_exit") - 1) == 0);
}

bool is_sched_proc_exit(const char* name)
{
	return (memcmp(name, "sched_process_exit", sizeof("sched_process_exit") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_exit", sizeof("sched/sched_process_exit") - 1) == 0);
}

bool is_sched_switch(const char* name)
{
	return (memcmp(name, "sched_switch", sizeof("sched_switch") - 1) == 0) ||
	       (memcmp(name, "sched/sched_switch", sizeof("sched/sched_switch") - 1) == 0);
}

bool is_page_fault_user(const char* name)
{
	return (memcmp(name, "page_fault_user", sizeof("page_fault_user") - 1) == 0) ||
	       (memcmp(name, "exceptions/page_fault_user", sizeof("exceptions/page_fault_user") - 1) == 0);
}

bool is_page_fault_kernel(const char* name)
{
	return (memcmp(name, "page_fault_kernel", sizeof("page_fault_kernel") - 1) == 0) ||
	       (memcmp(name, "exceptions/page_fault_kernel", sizeof("exceptions/page_fault_kernel") - 1) == 0);
}

bool is_signal_deliver(const char* name)
{
	return (memcmp(name, "signal_deliver", sizeof("signal_deliver") - 1) == 0) ||
	       (memcmp(name, "signal/signal_deliver", sizeof("signal/signal_deliver") - 1) == 0);
}

bool is_sched_prog_fork_move_args(const char* name)
{
	/* Note that the `&1` is a workaround we put in place when we want to attach more than one
	 * bpf program to the same tracepoint!
	 */
	return (memcmp(name, "sched_process_fork&1", sizeof("sched_process_fork&1") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_fork&1", sizeof("sched/sched_process_fork&1") - 1) == 0);
}

bool is_sched_prog_fork_missing_child(const char* name)
{
	/* if we found the `&` char in the section name it means that we need to remove the last 2 chars from `name`
	 * this is a workaround we use to attach more than one BPF prog to the same tracepoint. We will need the 
	 * real section name to attach the program for this reason we are removing this workaround here.
	 */
	return (memcmp(name, "sched_process_fork&2", sizeof("sched_process_fork&2") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_fork&2", sizeof("sched/sched_process_fork&2") - 1) == 0);
}

bool is_sched_prog_exec_missing_exit(const char* name)
{
	return (memcmp(name, "sched_process_exec", sizeof("sched_process_exec") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_exec", sizeof("sched/sched_process_exec") - 1) == 0);
}

void fill_attached_prog_info(struct bpf_attached_prog* prog, bool raw_tp, const char* name, int fd)
{
	prog->fd = fd;
	int size_to_read = NAME_MAX;
	/* if we found the `&` char in the section name it means that we need to remove the last 2 chars from `name`
	 * this is a workaround we use to attach more than one BPF prog to the same tracepoint. We will need the 
	 * real section name to attach the program for this reason we are removing this workaround here.
	 */
	if(strrchr(name, '&') != NULL)
	{
		size_to_read = (strlen(name) - 1) < NAME_MAX ? (strlen(name) - 1) : NAME_MAX;
	}
	strlcpy(prog->name, name, size_to_read);
	prog->raw_tp = raw_tp;
	prog->efd = -1; /* not attached */
}

int attach_bpf_prog(struct bpf_attached_prog* prog, char* last_err)
{
	/* The program is already attached or is never found in the elf file (prog->fd == -1)
	 * A program might be never found in the elf file for example page_faults or tracepoints
	 * enabled only on some architectures.
	 */
	if(prog->efd != -1 || prog->fd == -1)
	{
		return SCAP_SUCCESS;
	}

	int ret = 0;

	if(prog->raw_tp)
	{
		ret = __attach_raw_tp(prog, last_err);
	}
	else
	{
		ret = __attach_tp(prog, last_err);
	}
	return ret;
}

void detach_bpf_prog(struct bpf_attached_prog* prog)
{
	/* The program is already detached */
	if(prog->efd == -1)
	{
		return;
	}
	close(prog->efd);
	prog->efd = -1;
}

void unload_bpf_prog(struct bpf_attached_prog* prog)
{
	/* The program is already unloaded */
	if(prog->fd == -1)
	{
		return;
	}
	close(prog->fd);
	prog->fd = -1;
}
