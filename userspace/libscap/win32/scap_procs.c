/*
Copyright (C) 2021 The Falco Authors.

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scap.h"
#include "scap-int.h"

#include <io.h>
#define R_OK 4
#include <process.h>
#include "windows_hal.h"

int32_t scap_os_getpid_global(struct scap_engine_handle engine, int64_t *pid, char* error)
{
	*pid = _getpid();
	return SCAP_SUCCESS;
}
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error)
{
	return scap_get_procs_windows(handle, error);
}

struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets)
{
	return NULL;
}

bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm)
{
	return false;
}

void scap_refresh_proc_table(scap_t* handle)
{
}

int32_t scap_procfs_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr)
{
	return SCAP_FAILURE;
}
