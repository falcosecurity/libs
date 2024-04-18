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

#include "state.h"
#include <libpman.h>
#include <libscap/scap.h>

/* This function should be idempotent, every time it is called it should enforce again the state */
int pman_enforce_sc_set(bool *sc_set)
{
	/* If we fail at initialization time the BPF skeleton
	 * is not initialized when we stop the capture for example
	 */
	if(!g_state.skel)
	{
		return SCAP_FAILURE;
	}

	/* When we want to disable the capture we receive a NULL pointer here */
	bool empty_sc_set[PPM_SC_MAX] = {0};
	if(!sc_set)
	{
		sc_set = empty_sc_set;
	}

	int ret = 0;
	int syscall_id = 0;
	/* Special tracepoints, their attachment depends on interesting syscalls */
	bool sys_enter = false;
	bool sys_exit = false;
	bool sched_prog_fork = false;
	bool sched_prog_exec = false;

	/* Enforce interesting syscalls */
	for(int sc = 0; sc < PPM_SC_MAX; sc++)
	{
		syscall_id = scap_ppm_sc_to_native_id(sc);
		/* if `syscall_id` is -1 this is not a syscall */
		if(syscall_id == -1)
		{
			continue;
		}

		if(!sc_set[sc])
		{
			pman_mark_single_64bit_syscall(syscall_id, false);
		}
		else
		{
			sys_enter = true;
			sys_exit = true;
			pman_mark_single_64bit_syscall(syscall_id, true);
		}
	}

	if(sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		sched_prog_fork = true;
	}

	if(sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		sched_prog_exec = true;
	}

	/* Enable desired tracepoints */
	if(sys_enter)
		ret = ret ?: pman_attach_syscall_enter_dispatcher();
	else
		ret = ret ?: pman_detach_syscall_enter_dispatcher();

	if(sys_exit)
		ret = ret ?: pman_attach_syscall_exit_dispatcher();
	else
		ret = ret ?: pman_detach_syscall_exit_dispatcher();

	if(sched_prog_fork)
		ret = ret ?: pman_attach_sched_proc_fork();
	else
		ret = ret ?: pman_detach_sched_proc_fork();

	if(sched_prog_exec)
		ret = ret ?: pman_attach_sched_proc_exec();
	else
		ret = ret ?: pman_detach_sched_proc_exec();

	if(sc_set[PPM_SC_SCHED_PROCESS_EXIT])
		ret = ret ?: pman_attach_sched_proc_exit();
	else
		ret = ret ?: pman_detach_sched_proc_exit();

	if(sc_set[PPM_SC_SCHED_SWITCH])
		ret = ret ?: pman_attach_sched_switch();
	else
		ret = ret ?: pman_detach_sched_switch();

	if(sc_set[PPM_SC_PAGE_FAULT_USER])
		ret = ret ?: pman_attach_page_fault_user();
	else
		ret = ret ?: pman_detach_page_fault_user();

	if(sc_set[PPM_SC_PAGE_FAULT_KERNEL])
		ret = ret ?: pman_attach_page_fault_kernel();
	else
		ret = ret ?: pman_detach_page_fault_kernel();

	if(sc_set[PPM_SC_SIGNAL_DELIVER])
		ret = ret ?: pman_attach_signal_deliver();
	else
		ret = ret ?: pman_detach_signal_deliver();

	return ret;
}
