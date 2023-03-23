#pragma once

/* | name | path | */
#define KMOD_PROGS                                          \
	X(KMOD_PROG_SYS_ENTER, "sys_enter")                 \
	X(KMOD_PROG_SYS_EXIT, "sys_exit")                   \
	X(KMOD_PROG_SCHED_PROC_EXIT, "sched_process_exit")  \
	X(KMOD_PROG_SCHED_SWITCH, "sched_switch")           \
	X(KMOD_PROG_PAGE_FAULT_USER, "page_fault_user")     \
	X(KMOD_PROG_PAGE_FAULT_KERNEL, "page_fault_kernel") \
	X(KMOD_PROG_SIGNAL_DELIVER, "signal_deliver")       \
	X(KMOD_PROG_SCHED_PROC_FORK, "sched_process_fork")  \
	X(KMOD_PROG_SCHED_PROC_EXEC, "sched_process_exec")

typedef enum
{
#define X(name, path) name,
	KMOD_PROGS
#undef X
	KMOD_PROG_ATTACHED_MAX,
} kmod_prog_codes;

extern const char *kmod_prog_names[];
