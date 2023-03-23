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

typedef enum
{
	BPF_PROG_SYS_ENTER = 0,
	BPF_PROG_SYS_EXIT = 1,
	BPF_PROG_SCHED_PROC_EXIT = 2,
	BPF_PROG_SCHED_SWITCH = 3,
	BPF_PROG_PAGE_FAULT_USER = 4,
	BPF_PROG_PAGE_FAULT_KERNEL = 5,
	BPF_PROG_SIGNAL_DELIVER = 6,
	BPF_PROG_SCHED_PROC_FORK_MOVE_ARGS = 7,	    /* This is only used when raw_tp are not available */
	BPF_PROG_SCHED_PROC_FORK_MISSING_CHILD = 8, /* This is only used on architectures where the clone/fork child event is missing. Only when we have raw_tp */
	BPF_PROG_SCHED_PROC_EXEC_MISSING_EXIT = 9,  /* This is only used on architectures where the execve/execveat success event is missing */
	BPF_PROG_ATTACHED_MAX = 10,
} bpf_attached_prog_codes;

typedef struct bpf_attached_prog
{
	int fd;		     /* fd used to load/unload bpf progs */
	int efd;	     /* fd used to attach/detach bpf progs */
	char name[NAME_MAX]; /* name of the program, used to attach it into the kernel */
	bool raw_tp;	     /* tells if a program is a raw tracepoint or not */
} bpf_attached_prog;

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

void fill_attached_prog_info(struct bpf_attached_prog* prog, bool raw_tp, const char* name, int fd);
int attach_bpf_prog(struct bpf_attached_prog* prog, char* last_err);
void detach_bpf_prog(struct bpf_attached_prog* prog);
void unload_bpf_prog(struct bpf_attached_prog* prog);
