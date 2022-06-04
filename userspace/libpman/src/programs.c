#include "state.h"

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

/*=============================== ATTACH PROGRAMS ===============================*/
int libpman__attach_syscall_enter_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.dispatch_syscall_enter_events != NULL)
	{
		return 0;
	}

	g_state.skel->links.dispatch_syscall_enter_events = bpf_program__attach(g_state.skel->progs.dispatch_syscall_enter_events);
	if(!g_state.skel->links.dispatch_syscall_enter_events)
	{
		libpman__print_error("failed to attach the 'dispatch_syscall_enter_events' program");
		return errno;
	}
	return 0;
}

int libpman__attach_syscall_exit_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.dispatch_syscall_exit_events != NULL)
	{
		return 0;
	}

	g_state.skel->links.dispatch_syscall_exit_events = bpf_program__attach(g_state.skel->progs.dispatch_syscall_exit_events);
	if(!g_state.skel->links.dispatch_syscall_exit_events)
	{
		libpman__print_error("failed to attach the 'dispatch_syscall_exit_events' program");
		return errno;
	}
	return 0;
}

int libpman__attach_all_programs()
{
	int err;
	err = libpman__attach_syscall_enter_dispatcher();
	err = err ?: libpman__attach_syscall_exit_dispatcher();
	/* add all other programs. */
	return err;
}

/*=============================== ATTACH PROGRAMS ===============================*/

/*=============================== DETACH PROGRAMS ===============================*/

int libpman__detach_syscall_enter_dispatcher()
{
	if(g_state.skel->links.dispatch_syscall_enter_events && bpf_link__destroy(g_state.skel->links.dispatch_syscall_enter_events))
	{
		libpman__print_error("failed to detach the 'dispatch_syscall_enter_events' program");
		return errno;
	}
	g_state.skel->links.dispatch_syscall_enter_events = NULL;
	return 0;
}

int libpman__detach_syscall_exit_dispatcher()
{
	if(g_state.skel->links.dispatch_syscall_exit_events && bpf_link__destroy(g_state.skel->links.dispatch_syscall_exit_events))
	{
		libpman__print_error("failed to detach the 'dispatch_syscall_exit_events' program");
		return errno;
	}
	g_state.skel->links.dispatch_syscall_exit_events = NULL;
	return 0;
}

int libpman__detach_all_programs()
{
	int err;
	err = libpman__detach_syscall_enter_dispatcher();
	err = err ?: libpman__detach_syscall_exit_dispatcher();
	/* add all other programs. */
	return err;
}

/*=============================== DETACH PROGRAMS ===============================*/
