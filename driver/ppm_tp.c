#include "ppm_tp.h"

const char *tp_names[] = {
#define X(name, path) path,
	TP_FIELDS
#undef X
};

#ifndef __KERNEL__
#include <string.h>
#include "ppm_events_public.h"

typedef struct {
	ppm_sc_code sc_code;
	ppm_tp_code tp_code;
} sc_to_tp_map;

static sc_to_tp_map ppm_sc_to_tp_table[] = {
	{ PPM_SC_SCHED_PROCESS_EXIT, SCHED_PROC_EXIT},
	{ PPM_SC_SCHED_SWITCH, SCHED_SWITCH },
	{ PPM_SC_PAGE_FAULT_USER, PAGE_FAULT_USER },
	{ PPM_SC_PAGE_FAULT_KERNEL, PAGE_FAULT_KERN },
	{ PPM_SC_SIGNAL_DELIVER, SIGNAL_DELIVER },
};

_Static_assert(sizeof(ppm_sc_to_tp_table) / sizeof(*ppm_sc_to_tp_table) == PPM_SC_TP_LEN, "Wrong number of ppm_sc_to_tp_table entries.");

void tp_set_from_sc_set(const bool *sc_set, bool *tp_set)
{
	memset(tp_set, 0, TP_VAL_MAX * sizeof(*tp_set));
	if (!sc_set)
	{
		for (int i = 0; i < TP_VAL_MAX; i++)
		{
			tp_set[i] = true;
		}
		return;
	}

	for (int i = 0; i < PPM_SC_MAX; i++)
	{
		if (sc_set[i])
		{
			if (i < PPM_SC_SYSCALL_END)
			{
				// It's a syscall and is enabled!
				// Enable sys_enter and sys_exit
				// and skip to tracepoint events
				tp_set[SYS_ENTER] = true;
				tp_set[SYS_EXIT] = true;
				i = PPM_SC_TP_START - 1; // i++ will start from first tp
			}
			else
			{
				for (int j = 0; j < PPM_SC_TP_LEN; j++)
				{
					if (ppm_sc_to_tp_table[j].sc_code == i)
					{
						tp_set[ppm_sc_to_tp_table[j].tp_code] = true;
						break;
					}
				}
			}
		}
	}

	/*==============================================================
	 *
	 * Force-set tracepoints that are not mapped to a single event
	 * Ie: PPM_SC_SCHED_PROCESS_FORK, PPM_SC_SCHED_PROCESS_EXEC
	 *
	 *==============================================================*/
	// If users requested CLONE3, CLONE, FORK, VFORK,
	// enable also tracepoint to receive them on arm64
	if (sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		tp_set[SCHED_PROC_FORK] = true;
	}

	// If users requested EXECVE, EXECVEAT
	// enable also tracepoint to receive them on arm64
	if (sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		tp_set[SCHED_PROC_EXEC] = true;
	}
}

ppm_tp_code tp_from_name(const char *tp_path)
{
	// Find last '/' occurrence to take only the basename
	const char *tp_name = strrchr(tp_path, '/');
	if (tp_name == NULL || strlen(tp_name) <= 1)
	{
		return -1;
	}

	tp_name++;
	for (int i = 0; i < TP_VAL_MAX; i++)
	{
		if (strcmp(tp_name, tp_names[i]) == 0)
		{
			return i;
		}
	}
	return -1;
}
#endif