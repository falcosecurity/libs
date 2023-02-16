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
#include <ppm_events_public.h>
#include <libpman.h>

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

int pman_update_single_program(int tp, bool enabled)
{
	int ret = 0;
	switch(tp)
	{
	case PPM_SC_SYS_ENTER:
		if (enabled)
		{
			ret = pman_attach_syscall_enter_dispatcher();
		}
		else
		{
			ret = pman_detach_syscall_enter_dispatcher();
		}
		break;

	case PPM_SC_SYS_EXIT:
		if (enabled)
		{
			ret = pman_attach_syscall_exit_dispatcher();
		}
		else
		{
			ret = pman_detach_syscall_exit_dispatcher();
		}
		break;
	case PPM_SC_SCHED_PROCESS_EXIT:
		if (enabled)
		{
			ret = pman_attach_sched_proc_exit();
		}
		else
		{
			ret = pman_detach_sched_proc_exit();
		}
		break;

	case PPM_SC_SCHED_SWITCH:
		if (enabled)
		{
			ret = pman_attach_sched_switch();
		}
		else
		{
			ret = pman_detach_sched_switch();
		}
		break;

#ifdef CAPTURE_SCHED_PROC_EXEC
	case PPM_SC_SCHED_PROCESS_EXEC:
		if (enabled)
		{
			ret = pman_attach_sched_proc_exec();
		}
		else
		{
			ret = pman_detach_sched_proc_exec();
		}
		break;
#endif

#ifdef CAPTURE_SCHED_PROC_FORK
	case PPM_SC_SCHED_PROCESS_FORK:
		if (enabled)
		{
			ret = pman_attach_sched_proc_fork();
		}
		else
		{
			ret = pman_detach_sched_proc_fork();
		}
		break;
#endif

#ifdef CAPTURE_PAGE_FAULTS
	case PPM_SC_PAGE_FAULT_USER:
		if (enabled)
		{
			ret = pman_attach_page_fault_user();
		}
		else
		{
			ret = pman_detach_page_fault_user();
		}
		break;

	case PPM_SC_PAGE_FAULT_KERNEL:
		if (enabled)
		{
			ret = pman_attach_page_fault_kernel();
		}
		else
		{
			ret = pman_detach_page_fault_kernel();
		}
		break;
#endif

	case PPM_SC_SIGNAL_DELIVER:
		if (enabled)
		{
			ret = pman_attach_signal_deliver();
		}
		else
		{
			ret = pman_detach_signal_deliver();
		}
		break;

	default:
		/* Do nothing right now. */
		break;
	}
	return ret;
}

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

#ifdef CAPTURE_SCHED_PROC_FORK
int pman_attach_sched_proc_fork()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_fork != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_p_fork = bpf_program__attach(g_state.skel->progs.sched_p_fork);
	if(!g_state.skel->links.sched_p_fork)
	{
		pman_print_error("failed to attach the 'sched_proc_fork' program");
		return errno;
	}
	return 0;
}
#endif

#ifdef CAPTURE_PAGE_FAULTS
int pman_attach_page_fault_user()
{
	/* The program is already attached. */
	if(g_state.skel->links.pf_user != NULL)
	{
		return 0;
	}

	g_state.skel->links.pf_user = bpf_program__attach(g_state.skel->progs.pf_user);
	if(!g_state.skel->links.pf_user)
	{
		pman_print_error("failed to attach the 'pf_user' program");
		return errno;
	}
	return 0;
}

int pman_attach_page_fault_kernel()
{
	/* The program is already attached. */
	if(g_state.skel->links.pf_kernel != NULL)
	{
		return 0;
	}

	g_state.skel->links.pf_kernel = bpf_program__attach(g_state.skel->progs.pf_kernel);
	if(!g_state.skel->links.pf_kernel)
	{
		pman_print_error("failed to attach the 'pf_kernel' program");
		return errno;
	}
	return 0;
}
#endif

int pman_attach_signal_deliver()
{
	/* The program is already attached. */
	if(g_state.skel->links.signal_deliver != NULL)
	{
		return 0;
	}

	g_state.skel->links.signal_deliver = bpf_program__attach(g_state.skel->progs.signal_deliver);
	if(!g_state.skel->links.signal_deliver)
	{
		pman_print_error("failed to attach the 'signal_deliver' program");
		return errno;
	}
	return 0;
}

int pman_attach_all_programs()
{
	int ret = 0;
	for (int i = PPM_SC_TP_START; i < PPM_SC_MAX && ret == 0; i++)
	{
		ret = pman_update_single_program(i, true);
	}
	return ret;
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

#ifdef CAPTURE_SCHED_PROC_FORK
int pman_detach_sched_proc_fork()
{
	if(g_state.skel->links.sched_p_fork && bpf_link__destroy(g_state.skel->links.sched_p_fork))
	{
		pman_print_error("failed to detach the 'sched_proc_fork' program");
		return errno;
	}
	g_state.skel->links.sched_p_fork = NULL;
	return 0;
}
#endif

#ifdef CAPTURE_PAGE_FAULTS
int pman_detach_page_fault_user()
{
	if(g_state.skel->links.pf_user && bpf_link__destroy(g_state.skel->links.pf_user))
	{
		pman_print_error("failed to detach the 'pf_user' program");
		return errno;
	}
	g_state.skel->links.pf_user = NULL;
	return 0;
}

int pman_detach_page_fault_kernel()
{
	if(g_state.skel->links.pf_kernel && bpf_link__destroy(g_state.skel->links.pf_kernel))
	{
		pman_print_error("failed to detach the 'pf_kernel' program");
		return errno;
	}
	g_state.skel->links.pf_kernel = NULL;
	return 0;
}
#endif

int pman_detach_signal_deliver()
{
	if(g_state.skel->links.signal_deliver && bpf_link__destroy(g_state.skel->links.signal_deliver))
	{
		pman_print_error("failed to detach the 'signal_deliver' program");
		return errno;
	}
	g_state.skel->links.signal_deliver = NULL;
	return 0;
}

int pman_detach_all_programs()
{
	int ret = 0;
	for (int i = PPM_SC_TP_START; i < PPM_SC_MAX && ret == 0; i++)
	{
		ret = pman_update_single_program(i, false);

	}
	return ret;
}

/*=============================== DETACH PROGRAMS ===============================*/
