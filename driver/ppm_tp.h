#pragma once

/* | name | name | */
#define TP_FIELDS \
	X(SYS_ENTER, "sys_enter")    \
	X(SYS_EXIT, "sys_exit")      \
	X(SCHED_PROC_EXIT, "sched_process_exit")      \
        X(SCHED_SWITCH, "sched_switch")    \
	X(PAGE_FAULT_USER, "page_fault_user")      \
	X(PAGE_FAULT_KERN, "page_fault_kernel")      \
        X(SIGNAL_DELIVER, "signal_deliver")   \
	X(SCHED_PROC_FORK, "sched_process_fork")      \
	X(SCHED_PROC_EXEC, "sched_process_exec")

typedef enum {
#define X(name, path) name,
	TP_FIELDS
#undef X
	TP_VAL_MAX,
} tp_values;

extern const char *tp_names[];