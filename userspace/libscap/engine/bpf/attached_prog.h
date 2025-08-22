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

#pragma once

#include <stdbool.h>
#include <limits.h>
#include <libscap/compat/bpf.h>

enum bpf_attached_prog_codes {
	BPF_PROG_SYS_ENTER = 0,
	BPF_PROG_SYS_EXIT = 1,
	BPF_PROG_SCHED_PROC_EXIT = 2,
	BPF_PROG_SCHED_SWITCH = 3,
	BPF_PROG_PAGE_FAULT_USER = 4,
	BPF_PROG_PAGE_FAULT_KERNEL = 5,
	BPF_PROG_SIGNAL_DELIVER = 6,
	BPF_PROG_SCHED_PROC_FORK_MOVE_ARGS = 7, /* This is only used when raw_tp are not available */
	BPF_PROG_SCHED_PROC_FORK_MISSING_CHILD =
	        8, /* This is only used on architectures where the clone/fork child event is missing.
	              Only when we have raw_tp */
	BPF_PROG_SCHED_PROC_EXEC_MISSING_EXIT = 9, /* This is only used on architectures where the
	                                              execve/execveat success event is missing */
	BPF_PROG_ATTACHED_MAX = 10,
};

enum bpf_attached_ttm_progs_codes {
	BPF_TTM_PROGS_CONNECT = 0,  /* connect syscall TOCTOU mitigation programs. */
	BPF_TTM_PROGS_CREAT = 3,    /* creat syscall TOCTOU mitigation programs. */
	BPF_TTM_PROGS_OPEN = 6,     /* open syscall TOCTOU mitigation programs. */
	BPF_TTM_PROGS_OPENAT = 9,   /* openat syscall TOCTOU mitigation programs. */
	BPF_TTM_PROGS_OPENAT2 = 12, /* openat2 syscall TOCTOU mitigation programs. */
	BPF_TTM_PROGS_ATTACHED_MAX = 15,
};

typedef struct bpf_attached_prog {
	int fd;                  /* fd used to load/unload bpf progs */
	int efd;                 /* fd used to attach/detach bpf progs */
	char name[NAME_MAX];     /* name of the program, used to attach it into the kernel */
	enum bpf_prog_type type; /* the attached program type */
} bpf_attached_prog;

typedef struct bpf_attached_ttm_progs {
	bpf_attached_prog prog;
	bpf_attached_prog ia32_compat_prog;
	bpf_attached_prog ia32_prog;
} bpf_attached_ttm_progs;

enum bpf_ttm_prog_selector {
	BPF_TTM_SELECTOR_64BIT_PROG = 0,
	BPF_TTM_SELECTOR_IA32_COMPAT_PROG = 1,
	BPF_TTM_SELECTOR_IA32_PROG = 2,
};

bool is_sys_enter(const char* name);
bool is_sys_exit(const char* name);
bool is_sched_proc_exit(const char* name);
bool is_sched_switch(const char* name);
bool is_page_fault_user(const char* name);
bool is_page_fault_kernel(const char* name);
bool is_signal_deliver(const char* name);
bool is_sched_prog_fork_move_args(const char* name);
bool is_sched_prog_fork_missing_child(const char* name);
bool is_sched_prog_exec_missing_exit(const char* name);
bool is_sys_enter_connect(const char* name);
bool is_sys_enter_creat(const char* name);
bool is_sys_enter_open(const char* name);
bool is_sys_enter_openat(const char* name);
bool is_sys_enter_openat2(const char* name);

void fill_attached_prog_info(bpf_attached_prog* prog,
                             enum bpf_prog_type prog_type,
                             const char* name,
                             int fd);
int fill_attached_ttm_prog_info(bpf_attached_ttm_progs* progs,
                                enum bpf_ttm_prog_selector prog_selector,
                                enum bpf_prog_type prog_type,
                                const char* name,
                                int fd,
                                char* last_err);
int attach_bpf_prog(struct bpf_attached_prog* prog, char* last_err);
int attach_bpf_ttm_progs(bpf_attached_ttm_progs* progs, bool ia32_progs_first, char* last_err);
void detach_bpf_prog(struct bpf_attached_prog* prog);
void detach_bpf_ttm_progs(bpf_attached_ttm_progs* progs);
void unload_bpf_prog(struct bpf_attached_prog* prog);

int test_ttm_ia32_prog_support(const char* prog_symbol, char* last_err);
