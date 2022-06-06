#pragma once

#include <ppm_events_public.h>

/* For every event here we have the name of the corresponding bpf program. */
static const char* event_prog_names[PPM_EVENT_MAX] = {
	[PPME_SYSCALL_MKDIR_2_E] = "mkdir_e",
	[PPME_SYSCALL_MKDIR_2_X] = "mkdir_x",
};

/* Some events can require more than one bpf program to collect all the data. */
static const char* extra_event_prog_names[TAIL_EXTRA_EVENT_PROG_MAX] = {};
