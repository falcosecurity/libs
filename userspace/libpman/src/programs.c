/*
Copyright (C) 2022 The Falco Authors.

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
#include <feature_gates.h>

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

/*=============================== ATTACH PROGRAMS ===============================*/

int pman_attach_syscall_enter_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.sys_enter != NULL)
	{
		return 0;
	}

	g_state.skel->links.sys_enter = bpf_program__attach(g_state.skel->progs.sys_enter);
	if(!g_state.skel->links.sys_enter)
	{
		pman_print_error("failed to attach the 'sys_enter' program");
		return errno;
	}
	return 0;
}

int pman_attach_syscall_exit_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.sys_exit != NULL)
	{
		return 0;
	}

	g_state.skel->links.sys_exit = bpf_program__attach(g_state.skel->progs.sys_exit);
	if(!g_state.skel->links.sys_exit)
	{
		pman_print_error("failed to attach the 'sys_exit' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_exit()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_proc_exit != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_proc_exit = bpf_program__attach(g_state.skel->progs.sched_proc_exit);
	if(!g_state.skel->links.sched_proc_exit)
	{
		pman_print_error("failed to attach the 'sched_proc_exit' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_switch()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_switch != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_switch = bpf_program__attach(g_state.skel->progs.sched_switch);
	if(!g_state.skel->links.sched_switch)
	{
		pman_print_error("failed to attach the 'sched_switch' program");
		return errno;
	}
	return 0;
}

#ifdef CAPTURE_SCHED_PROC_EXEC
int pman_attach_sched_proc_exec()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_exec != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_p_exec = bpf_program__attach(g_state.skel->progs.sched_p_exec);
	if(!g_state.skel->links.sched_p_exec)
	{
		pman_print_error("failed to attach the 'sched_proc_exec' program");
		return errno;
	}
	return 0;
}
#endif

int pman_attach_all_programs()
{
	int err;
	err = pman_attach_syscall_enter_dispatcher();
	err = err ?: pman_attach_syscall_exit_dispatcher();
	err = err ?: pman_attach_sched_proc_exit();
	err = err ?: pman_attach_sched_switch();
#ifdef CAPTURE_SCHED_PROC_EXEC
	err = err ?: pman_attach_sched_proc_exec();
#endif
	/* add all other programs. */
	return err;
}

/*=============================== ATTACH PROGRAMS ===============================*/

/*=============================== DETACH PROGRAMS ===============================*/

int pman_detach_syscall_enter_dispatcher()
{
	if(g_state.skel->links.sys_enter && bpf_link__destroy(g_state.skel->links.sys_enter))
	{
		pman_print_error("failed to detach the 'sys_enter' program");
		return errno;
	}
	g_state.skel->links.sys_enter = NULL;
	return 0;
}

int pman_detach_syscall_exit_dispatcher()
{
	if(g_state.skel->links.sys_exit && bpf_link__destroy(g_state.skel->links.sys_exit))
	{
		pman_print_error("failed to detach the 'sys_exit' program");
		return errno;
	}
	g_state.skel->links.sys_exit = NULL;
	return 0;
}

int pman_detach_sched_proc_exit()
{
	if(g_state.skel->links.sched_proc_exit && bpf_link__destroy(g_state.skel->links.sched_proc_exit))
	{
		pman_print_error("failed to detach the 'sched_proc_exit' program");
		return errno;
	}
	g_state.skel->links.sched_proc_exit = NULL;
	return 0;
}

int pman_detach_sched_switch()
{
	if(g_state.skel->links.sched_switch && bpf_link__destroy(g_state.skel->links.sched_switch))
	{
		pman_print_error("failed to detach the 'sched_switch' program");
		return errno;
	}
	g_state.skel->links.sched_switch = NULL;
	return 0;
}

#ifdef CAPTURE_SCHED_PROC_EXEC
int pman_detach_sched_proc_exec()
{
	if(g_state.skel->links.sched_p_exec && bpf_link__destroy(g_state.skel->links.sched_p_exec))
	{
		pman_print_error("failed to detach the 'sched_proc_exec' program");
		return errno;
	}
	g_state.skel->links.sched_p_exec = NULL;
	return 0;
}
#endif

int pman_detach_all_programs()
{
	int err;
	err = pman_detach_syscall_enter_dispatcher();
	err = err ?: pman_detach_syscall_exit_dispatcher();
	err = err ?: pman_detach_sched_proc_exit();
	err = err ?: pman_detach_sched_switch();
#ifdef CAPTURE_SCHED_PROC_EXEC
	err = err ?: pman_detach_sched_proc_exec();
#endif	
	/* add all other programs. */
	return err;
}

/*=============================== DETACH PROGRAMS ===============================*/
