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
#include <libscap/compat/perf_event.h>
#include <libscap/strl.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/*=============================== INTERNALS ===============================*/

static int __attach_raw_tp_prog(struct bpf_attached_prog* prog, char* last_err) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.raw_tracepoint.name = (unsigned long)prog->name;
	attr.raw_tracepoint.prog_fd = prog->fd;

	prog->efd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	if(prog->efd < 0) {
		return scap_errprintf(last_err,
		                      -prog->efd,
		                      "BPF_RAW_TRACEPOINT_OPEN: event %s",
		                      prog->name);
	}
	return SCAP_SUCCESS;
}

static int __attach_tp_prog(struct bpf_attached_prog* prog, char* last_err) {
	int efd = 0;
	int err = 0;
	char buf[SCAP_MAX_PATH_SIZE];
	snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/id", prog->name);
	efd = open(buf, O_RDONLY, 0);
	if(efd < 0) {
		if(strcmp(prog->name, "exceptions/page_fault_user") == 0 ||
		   strcmp(prog->name, "exceptions/page_fault_kernel") == 0) {
			return SCAP_SUCCESS;
		}

		err = errno;
		scap_errprintf(last_err, err, "failed to open event %s", prog->name);
		if(err == ENOENT) {
			return SCAP_NOTFOUND;
		}
		return SCAP_FAILURE;
	}

	err = read(efd, buf, sizeof(buf));
	if(err < 0 || err >= sizeof(buf)) {
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
	if(efd < 0) {
		return scap_errprintf(last_err, -efd, "event %d", id);
	}

	if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog->fd)) {
		int err = errno;
		close(efd);
		return scap_errprintf(last_err, err, "PERF_EVENT_IOC_SET_BPF");
	}
	prog->efd = efd;
	return SCAP_SUCCESS;
}

const char* kprobe_events_path = "/sys/kernel/debug/tracing/kprobe_events";

int add_kprobe(const char* kprobe_name,
               const char* kernel_symbol,
               char* scratch_buf,
               const size_t scratch_buf_size,
               char* last_err) {
	const int fd = open(kprobe_events_path, O_WRONLY, O_APPEND);
	if(fd < 0) {
		return scap_errprintf(last_err, errno, "failed to open %s", kprobe_events_path);
	}

	const int written_bytes =
	        snprintf(scratch_buf, scratch_buf_size, "p:%s %s", kprobe_name, kernel_symbol);
	if(written_bytes < 0) {
		close(fd);
		return scap_errprintf(last_err,
		                      0,
		                      "not enough writing space while adding probe '%s'",
		                      kprobe_name);
	}

	const int res = write(fd, scratch_buf, written_bytes);
	if(res < 0) {
		const int err = errno;
		close(fd);
		return scap_errprintf(last_err,
		                      err,
		                      "failed to write into kprobe_events while adding probe '%s'",
		                      kprobe_name);
	}
	close(fd);
	return SCAP_SUCCESS;
}

int remove_kprobe(const char* kprobe_name,
                  char* scratch_buf,
                  const size_t scratch_buf_size,
                  char* last_err) {
	const int fd = open(kprobe_events_path, O_WRONLY, O_APPEND);
	if(fd < 0) {
		return scap_errprintf(last_err, errno, "failed to open %s", kprobe_events_path);
	}

	const int written_bytes = snprintf(scratch_buf, scratch_buf_size, "-:%s", kprobe_name);
	if(written_bytes < 0) {
		close(fd);
		return scap_errprintf(last_err,
		                      0,
		                      "not enough writing space while removing probe '%s'",
		                      kprobe_name);
	}

	errno = 0;
	const int res = write(fd, scratch_buf, written_bytes);
	if(res < 0) {
		const int err = errno;
		close(fd);
		return scap_errprintf(last_err,
		                      err,
		                      "failed to write into kprobe_events while removing probe '%s'",
		                      kprobe_name);
	}
	close(fd);
	return SCAP_SUCCESS;
}

static int get_kprobe_id(int* kprobe_id,
                         const char* kprobe_name,
                         char* scratch_buf,
                         const size_t scratch_buf_size,
                         char* last_err) {
	const int written_bytes = snprintf(scratch_buf,
	                                   scratch_buf_size,
	                                   "/sys/kernel/debug/tracing/events/kprobes/%s/id",
	                                   kprobe_name);
	if(written_bytes < 0) {
		return scap_errprintf(last_err,
		                      0,
		                      "not enough writing space while reading probe '%s' id",
		                      kprobe_name);
	}

	const int fd = open(scratch_buf, O_RDONLY, 0);
	if(fd < 0) {
		const int err = errno;
		scap_errprintf(last_err, errno, "failed to open '%s'", scratch_buf);
		if(err == ENOENT) {
			return SCAP_NOTFOUND;
		}
		return SCAP_FAILURE;
	}

	const int read_bytes = read(fd, scratch_buf, scratch_buf_size);
	if(read_bytes < 0) {
		const int err = errno;
		close(fd);
		return scap_errprintf(last_err, err, "failed to read from '%s'", scratch_buf);
	}
	close(fd);

	scratch_buf[read_bytes] = 0;
	*kprobe_id = atoi(scratch_buf);
	return SCAP_SUCCESS;
}

int test_ttm_ia32_prog_support(const char* prog_symbol, char* last_err) {
	char buf[SCAP_MAX_PATH_SIZE];
	int res = add_kprobe(prog_symbol, prog_symbol, buf, sizeof(buf), last_err);
	if(res != SCAP_SUCCESS) {
		return res;
	}

	res = remove_kprobe(prog_symbol, buf, sizeof(buf), last_err);
	if(res != SCAP_SUCCESS) {
		return res;
	}

	return SCAP_SUCCESS;
}

static int __attach_kprobe_prog(bpf_attached_prog* prog, char* last_err) {
	// Create a new kprobe event.
	const char* kprobe_name = prog->name;
	const char* kernel_symbol = prog->name;
	char buf[SCAP_MAX_PATH_SIZE];
	int res = add_kprobe(kprobe_name, kernel_symbol, buf, sizeof(buf), last_err);
	if(res != SCAP_SUCCESS) {
		return res;
	}

	// Read kprobe id.
	int kprobe_id = 0;
	res = get_kprobe_id(&kprobe_id, kprobe_name, buf, sizeof(buf), last_err);
	if(res != SCAP_SUCCESS) {
		remove_kprobe(kprobe_name, buf, sizeof(buf), last_err);
		return res;
	}

	// Open new perf event.
	struct perf_event_attr attr = {};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(struct perf_event_attr);
	attr.config = kprobe_id;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	const int efd = syscall(SYS_perf_event_open,
	                        &attr,
	                        -1,                  /* pid */
	                        0,                   /* cpu */
	                        -1,                  /* group_fd */
	                        PERF_FLAG_FD_CLOEXEC /* flags */
	);
	if(efd < 0) {
		return scap_errprintf(last_err,
		                      -efd,
		                      "failed to open new perf event event for probe '%s' id %d",
		                      kprobe_name,
		                      kprobe_id);
	}

	// Attach program to the kprobe event.
	if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog->fd)) {
		const int err = errno;
		remove_kprobe(kprobe_name, buf, sizeof(buf), last_err);
		close(efd);
		return scap_errprintf(last_err, err, "PERF_EVENT_IOC_SET_BPF");
	}
	prog->efd = efd;
	return SCAP_SUCCESS;
}

/*=============================== INTERNALS ===============================*/

bool is_sys_enter(const char* name) {
	/* We need the double-check because it could be a raw_tracepoint or a plain tracepoint */
	return (memcmp(name, "sys_enter", sizeof("sys_enter") - 1) == 0) ||
	       (memcmp(name, "raw_syscalls/sys_enter", sizeof("raw_syscalls/sys_enter") - 1) == 0);
}

bool is_sys_exit(const char* name) {
	return (memcmp(name, "sys_exit", sizeof("sys_exit") - 1) == 0) ||
	       (memcmp(name, "raw_syscalls/sys_exit", sizeof("raw_syscalls/sys_exit") - 1) == 0);
}

bool is_sched_proc_exit(const char* name) {
	return (memcmp(name, "sched_process_exit", sizeof("sched_process_exit") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_exit", sizeof("sched/sched_process_exit") - 1) == 0);
}

bool is_sched_switch(const char* name) {
	return (memcmp(name, "sched_switch", sizeof("sched_switch") - 1) == 0) ||
	       (memcmp(name, "sched/sched_switch", sizeof("sched/sched_switch") - 1) == 0);
}

bool is_page_fault_user(const char* name) {
	return (memcmp(name, "page_fault_user", sizeof("page_fault_user") - 1) == 0) ||
	       (memcmp(name, "exceptions/page_fault_user", sizeof("exceptions/page_fault_user") - 1) ==
	        0);
}

bool is_page_fault_kernel(const char* name) {
	return (memcmp(name, "page_fault_kernel", sizeof("page_fault_kernel") - 1) == 0) ||
	       (memcmp(name,
	               "exceptions/page_fault_kernel",
	               sizeof("exceptions/page_fault_kernel") - 1) == 0);
}

bool is_signal_deliver(const char* name) {
	return (memcmp(name, "signal_deliver", sizeof("signal_deliver") - 1) == 0) ||
	       (memcmp(name, "signal/signal_deliver", sizeof("signal/signal_deliver") - 1) == 0);
}

bool is_sched_prog_fork_move_args(const char* name) {
	/* Note that the `&1` is a workaround we put in place when we want to attach more than one
	 * bpf program to the same tracepoint!
	 */
	return (memcmp(name, "sched_process_fork&1", sizeof("sched_process_fork&1") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_fork&1", sizeof("sched/sched_process_fork&1") - 1) ==
	        0);
}

bool is_sched_prog_fork_missing_child(const char* name) {
	/* if we found the `&` char in the section name it means that we need to remove the last 2 chars
	 * from `name` this is a workaround we use to attach more than one BPF prog to the same
	 * tracepoint. We will need the real section name to attach the program for this reason we are
	 * removing this workaround here.
	 */
	return (memcmp(name, "sched_process_fork&2", sizeof("sched_process_fork&2") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_fork&2", sizeof("sched/sched_process_fork&2") - 1) ==
	        0);
}

bool is_sched_prog_exec_missing_exit(const char* name) {
	return (memcmp(name, "sched_process_exec", sizeof("sched_process_exec") - 1) == 0) ||
	       (memcmp(name, "sched/sched_process_exec", sizeof("sched/sched_process_exec") - 1) == 0);
}

bool is_sys_enter_connect(const char* name) {
	const char expected_64bit_prog_name[] = "syscalls/sys_enter_connect";
	const char expected_ia32_compat_prog_name[] = "__ia32_compat_sys_connect";
	const char expected_ia32_prog_name[] = "__ia32_sys_connect";
	return strcmp(name, expected_64bit_prog_name) == 0 ||
	       strcmp(name, expected_ia32_compat_prog_name) == 0 ||
	       strcmp(name, expected_ia32_prog_name) == 0;
}

bool is_sys_enter_creat(const char* name) {
	const char expected_64bit_prog_name[] = "syscalls/sys_enter_creat";
	const char expected_ia32_compat_prog_name[] = "__ia32_compat_sys_creat";
	const char expected_ia32_prog_name[] = "__ia32_sys_creat";
	return strcmp(name, expected_64bit_prog_name) == 0 ||
	       strcmp(name, expected_ia32_compat_prog_name) == 0 ||
	       strcmp(name, expected_ia32_prog_name) == 0;
}

bool is_sys_enter_open(const char* name) {
	const char expected_64bit_prog_name[] = "syscalls/sys_enter_open";
	const char expected_ia32_compat_prog_name[] = "__ia32_compat_sys_open";
	const char expected_ia32_prog_name[] = "__ia32_sys_open";
	return strcmp(name, expected_64bit_prog_name) == 0 ||
	       strcmp(name, expected_ia32_compat_prog_name) == 0 ||
	       strcmp(name, expected_ia32_prog_name) == 0;
}

bool is_sys_enter_openat(const char* name) {
	const char expected_64bit_prog_name[] = "syscalls/sys_enter_openat";
	const char expected_ia32_compat_prog_name[] = "__ia32_compat_sys_openat";
	const char expected_ia32_prog_name[] = "__ia32_sys_openat";
	return strcmp(name, expected_64bit_prog_name) == 0 ||
	       strcmp(name, expected_ia32_compat_prog_name) == 0 ||
	       strcmp(name, expected_ia32_prog_name) == 0;
}

bool is_sys_enter_openat2(const char* name) {
	const char expected_64bit_prog_name[] = "syscalls/sys_enter_openat2";
	const char expected_ia32_compat_prog_name[] = "__ia32_compat_sys_openat2";
	const char expected_ia32_prog_name[] = "__ia32_sys_openat2";
	return strcmp(name, expected_64bit_prog_name) == 0 ||
	       strcmp(name, expected_ia32_compat_prog_name) == 0 ||
	       strcmp(name, expected_ia32_prog_name) == 0;
}

void fill_attached_prog_info(struct bpf_attached_prog* prog,
                             const enum bpf_prog_type prog_type,
                             const char* name,
                             const int fd) {
	prog->fd = fd;
	int size_to_read = NAME_MAX;
	/* if we found the `&` char in the section name it means that we need to remove the last 2 chars
	 * from `name` this is a workaround we use to attach more than one BPF prog to the same
	 * tracepoint. We will need the real section name to attach the program for this reason we are
	 * removing this workaround here.
	 */
	if(strrchr(name, '&') != NULL) {
		size_to_read = (strlen(name) - 1) < NAME_MAX ? (strlen(name) - 1) : NAME_MAX;
	}
	strlcpy(prog->name, name, size_to_read);
	prog->type = prog_type;
	prog->efd = -1; /* not attached */
}

int fill_attached_ttm_prog_info(bpf_attached_ttm_progs* progs,
                                const enum bpf_ttm_prog_selector prog_selector,
                                const enum bpf_prog_type prog_type,
                                const char* name,
                                const int fd,
                                char* last_err) {
	bpf_attached_prog* prog;
	switch(prog_selector) {
	case BPF_TTM_SELECTOR_64BIT_PROG:
		prog = &progs->prog;
		break;
	case BPF_TTM_SELECTOR_IA32_COMPAT_PROG:
		prog = &progs->ia32_compat_prog;
		break;
	case BPF_TTM_SELECTOR_IA32_PROG:
		prog = &progs->ia32_prog;
		break;
	default:
		return scap_errprintf(last_err,
		                      0,
		                      "failed to fill TOCTOU program info: unknown program selector %d",
		                      prog_selector);
	}
	fill_attached_prog_info(prog, prog_type, name, fd);
	return SCAP_SUCCESS;
}

int attach_bpf_prog(struct bpf_attached_prog* prog, char* last_err) {
	/* The program is already attached (prog->efd != -1) or never found in the elf file/explicitely
	 * not loaded (prog->fd == -1). A program might be never found in the elf file for example
	 * page_faults or tracepoints enabled only on some architectures.
	 */
	if(prog->efd != -1 || prog->fd == -1) {
		return SCAP_SUCCESS;
	}

	switch(prog->type) {
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
		return __attach_raw_tp_prog(prog, last_err);
	case BPF_PROG_TYPE_TRACEPOINT:
		return __attach_tp_prog(prog, last_err);
	case BPF_PROG_TYPE_KPROBE:
		return __attach_kprobe_prog(prog, last_err);
	default:
		return scap_errprintf(last_err,
		                      0,
		                      "failed to attach: unexpected program type %d",
		                      prog->type);
	}
}

int attach_64bit_ttm_prog(bpf_attached_ttm_progs* progs, char* last_err) {
	return attach_bpf_prog(&progs->prog, last_err);
}

int attach_ia32_ttm_prog(bpf_attached_ttm_progs* progs, char* last_err) {
	if(progs->ia32_compat_prog.fd >= 0) {
		return attach_bpf_prog(&progs->ia32_compat_prog, last_err);
	}

	if(progs->ia32_prog.fd >= 0) {
		return attach_bpf_prog(&progs->ia32_prog, last_err);
	}

	return SCAP_SUCCESS;
}

int attach_bpf_ttm_progs(bpf_attached_ttm_progs* progs, bool ia32_progs_first, char* last_err) {
	if(!ia32_progs_first) {
		const int res = attach_64bit_ttm_prog(progs, last_err);
		if(res != SCAP_SUCCESS) {
			return res;
		}
		return attach_ia32_ttm_prog(progs, last_err);
	}

	const int res = attach_ia32_ttm_prog(progs, last_err);
	if(res != SCAP_SUCCESS) {
		return res;
	}
	return attach_64bit_ttm_prog(progs, last_err);
}

void detach_bpf_prog(struct bpf_attached_prog* prog) {
	/* The program is already detached */
	if(prog->efd == -1) {
		return;
	}
	close(prog->efd);
	prog->efd = -1;
}

void detach_bpf_ttm_progs(bpf_attached_ttm_progs* progs) {
	char buf[SCAP_MAX_PATH_SIZE];
	detach_bpf_prog(&progs->prog);
	detach_bpf_prog(&progs->ia32_compat_prog);
	remove_kprobe(progs->ia32_compat_prog.name, buf, sizeof(buf), NULL);
	detach_bpf_prog(&progs->ia32_prog);
	remove_kprobe(progs->ia32_prog.name, buf, sizeof(buf), NULL);
}

void unload_bpf_prog(struct bpf_attached_prog* prog) {
	/* The program is already unloaded */
	if(prog->fd == -1) {
		return;
	}
	close(prog->fd);
	prog->fd = -1;
}
