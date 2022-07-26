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

#pragma once

#include <ppm_events_public.h>

/* For every event here we have the name of the corresponding bpf program. */
static const char* event_prog_names[PPM_EVENT_MAX] = {
	[PPME_SYSCALL_MKDIR_2_E] = "mkdir_e",
	[PPME_SYSCALL_MKDIR_2_X] = "mkdir_x",
	[PPME_SYSCALL_OPEN_E] = "open_e",
	[PPME_SYSCALL_OPEN_X] = "open_x",
	[PPME_SYSCALL_OPENAT_2_E] = "openat_e",
	[PPME_SYSCALL_OPENAT_2_X] = "openat_x",
	[PPME_SYSCALL_OPENAT2_E] = "openat2_e",
	[PPME_SYSCALL_OPENAT2_X] = "openat2_x",
	[PPME_SYSCALL_OPEN_BY_HANDLE_AT_E] = "open_by_handle_at_e",
	[PPME_SYSCALL_OPEN_BY_HANDLE_AT_X] = "open_by_handle_at_x",
};

/* Some events can require more than one bpf program to collect all the data. */
static const char* extra_event_prog_names[TAIL_EXTRA_EVENT_PROG_MAX] = {};
