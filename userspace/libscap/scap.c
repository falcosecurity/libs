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

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif // _WIN32

#include "scap.h"
#include "../common/strlcpy.h"
#ifdef HAS_CAPTURE
#if !defined(_WIN32) && !defined(CYGWING_AGENT)
#include "driver_config.h"
#endif // _WIN32 && CYGWING_AGENT
#endif // HAS_CAPTURE
#include "../../driver/ppm_ringbuffer.h"
#include "scap_savefile.h"
#include "scap-int.h"
#include "scap_engine_util.h"

#if defined(_WIN32) || defined(CYGWING_AGENT)
#define DRAGENT_WIN_HAL_C_ONLY
#include "windows_hal.h"
#endif

#include "gettimeofday.h"
#include "sleep.h"
#include "scap_engines.h"

//#define NDEBUG
#include <assert.h>

const char* scap_getlasterr(scap_t* handle)
{
	return handle ? handle->m_lasterr : "null scap handle";
}

static int32_t copy_comms(scap_t *handle, const char **suppressed_comms)
{
	if(suppressed_comms)
	{
		uint32_t i;
		const char *comm;
		for(i = 0, comm = suppressed_comms[i]; comm && i < SCAP_MAX_SUPPRESSED_COMMS; i++, comm = suppressed_comms[i])
		{
			int32_t res;
			if((res = scap_suppress_events_comm(handle, comm)) != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
scap_t* scap_open_live_int(char *error, int32_t *rc, scap_open_args* oargs)
{
	snprintf(error, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
}
#endif

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
scap_t* scap_open_udig_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char **suppressed_comms)
{
	snprintf(error, SCAP_LASTERR_SIZE, "udig capture not supported on %s", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
}
#else

#ifndef _WIN32
scap_t* scap_open_live_int(char *error, int32_t *rc, scap_open_args* oargs)
{
	char filename[SCAP_MAX_PATH_SIZE] = {0};
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*) calloc(sizeof(scap_t), 1);
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_LIVE;
	if(strncmp(oargs->engine_name, BPF_ENGINE, BPF_ENGINE_LEN) == 0)
	{
		handle->m_vtable = &scap_bpf_engine;
	}
	else if(strncmp(oargs->engine_name, KMOD_ENGINE, KMOD_ENGINE_LEN) == 0)
	{
		handle->m_vtable = &scap_kmod_engine;
	}
#ifdef HAS_ENGINE_MODERN_BPF
	else if(strncmp(oargs->engine_name, MODERN_BPF_ENGINE, MODERN_BPF_ENGINE_LEN) == 0)
	{
		handle->m_vtable = &scap_modern_bpf_engine;
	}
#endif /* HAS_ENGINE_MODERN_BPF */
	else
	{
		snprintf(error, SCAP_LASTERR_SIZE, "libscap: unknown engine called `scap_open_live_int()`");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = oargs->proc_callback;
	handle->m_proclist.m_proc_callback_context = oargs->proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	//
	// Extract machine information
	//
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = 0;

#ifdef CYGWING_AGENT
	handle->m_whh = NULL;
	handle->m_win_buf_handle = NULL;
	handle->m_win_descs_handle = NULL;
#endif

	//
	// Create the interface list
	//
	if((*rc = scap_create_iflist(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
		return NULL;
	}

	//
	// Create the user list
	//
	if(oargs->import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the user list");
			return NULL;
		}
	}
	else
	{
		handle->m_userlist = NULL;
	}

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

	if ((*rc = copy_comms(handle, oargs->suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	//
	// Open and initialize all the devices
	//
	if((*rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	*rc = check_api_compatibility(handle, handle->m_lasterr);
	if(*rc != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	scap_stop_dropping_mode(handle);

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	char proc_scan_err[SCAP_LASTERR_SIZE];
	if((*rc = scap_proc_scan_proc_dir(handle, filename, proc_scan_err)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "scap_open_live_int() error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		return NULL;
	}

	//
	// Now that /proc parsing has been done, start the capture
	//
	if((*rc = scap_start_capture(handle)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	return handle;
}

#endif // _WIN32

scap_t* scap_open_udig_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char **suppressed_comms)
{
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*) calloc(sizeof(scap_t), 1);
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_LIVE;
	handle->m_ncpus = 1;

	handle->m_vtable = &scap_udig_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	// TODO: we don't have open_args here. thankfully the udig init method
	//       doesn't need them
	*rc = handle->m_vtable->init(handle, NULL);
	if(*rc != SCAP_SUCCESS)
	{
		scap_close(handle);
		free(handle);
		return NULL;
	}

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = proc_callback;
	handle->m_proclist.m_proc_callback_context = proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	//
	// Extract machine information
	//
#ifdef _WIN32
	scap_get_machine_info_windows(&handle->m_machine_info.num_cpus, &handle->m_machine_info.memory_size_bytes);
#else
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
#endif
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = 0;

	//
	// Create the interface list
	//
	if((*rc = scap_create_iflist(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
		return NULL;
	}

	//
	// Create the user list
	//
	if(import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the user list");
			return NULL;
		}
	}
	else
	{
		handle->m_userlist = NULL;
	}

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

#ifdef _WIN32
	handle->m_whh = scap_windows_hal_open(error);
	if(handle->m_whh == NULL)
	{
		scap_close(handle);
		return NULL;
	}

	handle->m_win_buf_handle = NULL;
	handle->m_win_descs_handle = NULL;
#endif

	if ((*rc = copy_comms(handle, suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	//
	// Additional initializations
	//
	scap_stop_dropping_mode(handle);

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	char procerr[SCAP_LASTERR_SIZE];
	if((*rc = scap_proc_scan_proc_dir(handle, filename, procerr)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "%s", procerr);
		return NULL;
	}

	//
	// Now that /proc parsing has been done, start the capture
	//
	if(udig_begin_capture(handle->m_engine, error) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}

	return handle;
}
#endif // !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)

#ifdef HAS_ENGINE_TEST_INPUT
scap_t* scap_open_test_input_int(char *error, int32_t *rc, scap_open_args *oargs)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*) calloc(1, sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_vtable = &scap_test_input_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	*rc = handle->m_vtable->init(handle, oargs);
	if(*rc != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_LIVE;

	handle->m_ncpus = 1;

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = oargs->proc_callback;
	handle->m_proclist.m_proc_callback_context = oargs->proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	if ((*rc = copy_comms(handle, oargs->suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	if ((*rc = scap_proc_scan_vtable(error, handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}

	if(handle->m_vtable->start_capture(handle->m_engine) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}
	return handle;
}
#else
scap_t* scap_open_test_input_int(char *error, int32_t *rc, scap_open_args *oargs)
{
	snprintf(error, SCAP_LASTERR_SIZE, "the test_input engine is only available for testing");
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
}
#endif

#ifdef HAS_ENGINE_GVISOR
scap_t* scap_open_gvisor_int(char *error, int32_t *rc, scap_open_args *oargs)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*) calloc(1, sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_vtable = &scap_gvisor_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	*rc = handle->m_vtable->init(handle, oargs);
	if(*rc != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_LIVE;

	handle->m_ncpus = 1;

	// XXX - interface list initialization and user list initalization goes here if necessary

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = oargs->proc_callback;
	handle->m_proclist.m_proc_callback_context = oargs->proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	if ((*rc = copy_comms(handle, oargs->suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	if ((*rc = scap_proc_scan_vtable(error, handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}

	if(handle->m_vtable->start_capture(handle->m_engine) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}
	return handle;
}
#else
scap_t* scap_open_gvisor_int(char *error, int32_t *rc, scap_open_args *oargs)
{
	snprintf(error, SCAP_LASTERR_SIZE, "gvisor not supported on this build (platform: %s)", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
}
#endif // HAS_ENGINE_GVISOR


scap_t* scap_open_offline_int(scap_open_args* oargs, int* rc, char* error)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_CAPTURE;
	handle->m_vtable = &scap_savefile_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	handle->m_dev_list = NULL;
	handle->m_evtcnt = 0;
	handle->m_addrlist = NULL;
	handle->m_userlist = NULL;
	handle->m_machine_info.num_cpus = (uint32_t)-1;
	handle->m_driver_procinfo = NULL;
	handle->refresh_proc_table_when_saving = true;
	handle->m_fd_lookup_limit = 0;
#if CYGWING_AGENT || _WIN32
	handle->m_whh = NULL;
	handle->m_win_buf_handle = NULL;
	handle->m_win_descs_handle = NULL;
#endif
	handle->m_suppressed_comms = NULL;
	handle->m_suppressed_tids = NULL;

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = oargs->proc_callback;
	handle->m_proclist.m_proc_callback_context = oargs->proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	if((*rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	//
	// Add the fake process for kernel threads
	//
	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;

	handle->m_num_suppressed_comms = 0;
	handle->m_num_suppressed_evts = 0;

	if ((*rc = copy_comms(handle, oargs->suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	return handle;
}

scap_t* scap_open_nodriver_int(char *error, int32_t *rc,
			       proc_entry_callback proc_callback,
			       void* proc_callback_context,
			       bool import_users)
{
#if !defined(HAS_CAPTURE)
	snprintf(error, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
#else
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	memset(handle, 0, sizeof(scap_t));
	handle->m_mode = SCAP_MODE_NODRIVER;
	handle->m_vtable = &scap_nodriver_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = proc_callback;
	handle->m_proclist.m_proc_callback_context = proc_callback_context;
	handle->m_proclist.m_proclist = NULL;

	//
	// Extract machine information
	//
#ifdef _WIN32
	handle->m_machine_info.num_cpus = 0;
	handle->m_machine_info.memory_size_bytes = 0;
#else
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
#endif
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = SCAP_NODRIVER_MAX_FD_LOOKUP; // fd lookup is limited here because is very expensive

	//
	// If this is part of the windows agent, open the windows HAL
	//
#ifdef CYGWING_AGENT
	handle->m_whh = wh_open(error);
	if(handle->m_whh == NULL)
	{
		scap_close(handle);
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_win_buf_handle = NULL;
	handle->m_win_descs_handle = NULL;
#endif

	//
	// Create the interface list
	//
	if((*rc = scap_create_iflist(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
		return NULL;
	}

	//
	// Create the user list
	//
	if(import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the user list");
			return NULL;
		}
	}
	else
	{
		handle->m_userlist = NULL;
	}

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	char proc_scan_err[SCAP_LASTERR_SIZE];
	if((*rc = scap_proc_scan_proc_dir(handle, filename, proc_scan_err)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		return NULL;
	}

	return handle;
#endif // HAS_CAPTURE
}

scap_t* scap_open_plugin_int(char *error, int32_t *rc, scap_open_args* oargs)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	memset(handle, 0, sizeof(scap_t));
	handle->m_mode = SCAP_MODE_PLUGIN;
	handle->m_vtable = &scap_source_plugin_engine;
	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		free(handle);
		return NULL;
	}

	handle->m_proclist.m_main_handle = handle;
	handle->m_proclist.m_proc_callback = NULL;
	handle->m_proclist.m_proc_callback_context = NULL;
	handle->m_proclist.m_proclist = NULL;

	//
	// Extract machine information
	//
#ifdef _WIN32
	handle->m_machine_info.num_cpus = 0;
	handle->m_machine_info.memory_size_bytes = 0;
#else
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
#endif
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = SCAP_NODRIVER_MAX_FD_LOOKUP; // fd lookup is limited here because is very expensive
	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	if((*rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	return handle;
}

scap_t* scap_open(scap_open_args* oargs, char *error, int32_t *rc)
{

#ifdef CYGWING_AGENT
	if(oargs->mode == SCAP_MODE_LIVE)
	{
		snprintf(error,	SCAP_LASTERR_SIZE, "libscap: live mode currently not supported on Windows.");
		*rc = SCAP_NOT_SUPPORTED;
		return NULL;
	}
#endif
	const char* engine_name = oargs->engine_name;
	/* At the end of the `v-table` work we can use just one function
	 * with an internal switch that selects the right vtable! For the moment
	 * let's keep different functions.
	 */
	if(strncmp(engine_name, SAVEFILE_ENGINE, SAVEFILE_ENGINE_LEN) == 0)
	{
		return scap_open_offline_int(oargs, rc, error);
	}
	else if(strncmp(engine_name, UDIG_ENGINE, UDIG_ENGINE_LEN) == 0)
	{
		return scap_open_udig_int(error, rc, oargs->proc_callback,
								oargs->proc_callback_context,
								oargs->import_users,
								oargs->suppressed_comms);
	}
	else if(strncmp(engine_name, GVISOR_ENGINE, GVISOR_ENGINE_LEN) == 0)
	{
		return scap_open_gvisor_int(error, rc, oargs);
	}
	else if(strncmp(engine_name, TEST_INPUT_ENGINE, TEST_INPUT_ENGINE_LEN) == 0)
	{
		return scap_open_test_input_int(error, rc, oargs);
	}
	else if(strncmp(engine_name, KMOD_ENGINE, KMOD_ENGINE_LEN) == 0 ||
			strncmp(engine_name, BPF_ENGINE, BPF_ENGINE_LEN) == 0 ||
			strncmp(engine_name, MODERN_BPF_ENGINE, MODERN_BPF_ENGINE_LEN) == 0)
	{
		return scap_open_live_int(error, rc, oargs);
	}
	else if(strncmp(engine_name, NODRIVER_ENGINE, NODRIVER_ENGINE_LEN) == 0)
	{
		return scap_open_nodriver_int(error, rc, oargs->proc_callback,
					      oargs->proc_callback_context,
					      oargs->import_users);
	}
	else if(strncmp(engine_name, SOURCE_PLUGIN_ENGINE, SOURCE_PLUGIN_ENGINE_LEN) == 0)
	{
		return scap_open_plugin_int(error, rc, oargs);
	}

	snprintf(error, SCAP_LASTERR_SIZE, "incorrect engine '%s'", engine_name);
	*rc = SCAP_FAILURE;
	return NULL;
}

static inline void scap_deinit_state(scap_t* handle)
{
	// Free the process table
	if(handle->m_proclist.m_proclist != NULL)
	{
		scap_proc_free_table(handle);
		handle->m_proclist.m_proclist = NULL;
	}

	// Free the device table
	if(handle->m_dev_list != NULL)
	{
		scap_free_device_table(handle);
		handle->m_dev_list = NULL;
	}

	// Free the interface list
	if(handle->m_addrlist)
	{
		scap_free_iflist(handle->m_addrlist);
		handle->m_addrlist = NULL;
	}

	// Free the user list
	if(handle->m_userlist)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	if(handle->m_driver_procinfo)
	{
		free(handle->m_driver_procinfo);
		handle->m_driver_procinfo = NULL;
	}
}

uint32_t scap_restart_capture(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		scap_deinit_state(handle);
		return handle->m_vtable->savefile_ops->restart_capture(handle);
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "capture restart supported only in capture mode");
		return SCAP_FAILURE;
	}
}

void scap_close(scap_t* handle)
{
#if CYGWING_AGENT || _WIN32
	if(handle->m_whh != NULL)
	{
		scap_windows_hal_close(handle->m_whh);
	}
#endif
	scap_deinit_state(handle);

	if(handle->m_suppressed_comms)
	{
		uint32_t i;
		for(i=0; i < handle->m_num_suppressed_comms; i++)
		{
			free(handle->m_suppressed_comms[i]);
		}
		free(handle->m_suppressed_comms);
		handle->m_suppressed_comms = NULL;
	}

	if(handle->m_suppressed_tids)
	{
		struct scap_tid *tid;
		struct scap_tid *ttid;
		HASH_ITER(hh, handle->m_suppressed_tids, tid, ttid)
		{
			HASH_DEL(handle->m_suppressed_tids, tid);
			free(tid);
		}

		handle->m_suppressed_tids = NULL;
	}

	if(handle->m_vtable)
	{
		handle->m_vtable->close(handle->m_engine);
		handle->m_vtable->free_handle(handle->m_engine);
	}

	//
	// Release the handle
	//
	free(handle);
}

scap_os_platform scap_get_os_platform(scap_t* handle)
{
#if defined(_M_IX86) || defined(__i386__)
#ifdef linux
	return SCAP_PFORM_LINUX_I386;
#else
	return SCAP_PFORM_WINDOWS_I386;
#endif // linux
#else
#if defined(_M_X64) || defined(__AMD64__)
#ifdef linux
	return SCAP_PFORM_LINUX_X64;
#else
	return SCAP_PFORM_WINDOWS_X64;
#endif // linux
#else
	return SCAP_PFORM_UNKNOWN;
#endif // defined(_M_X64) || defined(__AMD64__)
#endif // defined(_M_IX86) || defined(__i386__)
}

uint32_t scap_get_ndevs(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_devs(handle->m_engine);
	}
	return 1;
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len)
{
	// engines do not even necessarily have a concept of a buffer
	// that you read events from
	return SCAP_NOT_SUPPORTED;
}

#endif // HAS_CAPTURE

uint64_t scap_max_buf_used(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_max_buf_used(handle->m_engine);
	}
	return 0;
}

int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	int32_t res = SCAP_FAILURE;
	if(handle->m_vtable)
	{
		res = handle->m_vtable->next(handle->m_engine, pevent, pcpuid);
	}
	else
	{
		ASSERT(false);
		res = SCAP_FAILURE;
	}

	if(res == SCAP_SUCCESS)
	{
		bool suppressed;

		// Check to see if the event should be suppressed due
		// to coming from a supressed tid
		if((res = scap_check_suppressed(handle, *pevent, &suppressed)) != SCAP_SUCCESS)
		{
			return res;
		}

		if(suppressed)
		{
			handle->m_num_suppressed_evts++;
			return SCAP_TIMEOUT;
		}
		else
		{
			handle->m_evtcnt++;
		}
	}

	return res;
}

//
// Return the process list for the given handle
//
scap_threadinfo* scap_get_proc_table(scap_t* handle)
{
	return handle->m_proclist.m_proclist;
}

//
// Return the number of dropped events for the given handle
//
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	stats->n_evts = 0;
	stats->n_drops = 0;
	stats->n_drops_buffer = 0;
	stats->n_drops_buffer_clone_fork_enter = 0;
	stats->n_drops_buffer_clone_fork_exit = 0;
	stats->n_drops_buffer_execve_enter = 0;
	stats->n_drops_buffer_execve_exit = 0;
	stats->n_drops_buffer_connect_enter = 0;
	stats->n_drops_buffer_connect_exit = 0;
	stats->n_drops_buffer_open_enter = 0;
	stats->n_drops_buffer_open_exit = 0;
	stats->n_drops_buffer_dir_file_enter = 0;
	stats->n_drops_buffer_dir_file_exit = 0;
	stats->n_drops_buffer_other_interest_enter = 0;
	stats->n_drops_buffer_other_interest_exit = 0;
	stats->n_drops_scratch_map = 0;
	stats->n_drops_pf = 0;
	stats->n_drops_bug = 0;
	stats->n_preemptions = 0;
	stats->n_suppressed = handle->m_num_suppressed_evts;
	stats->n_tids_suppressed = HASH_COUNT(handle->m_suppressed_tids);

	if(handle->m_vtable)
	{
		return handle->m_vtable->get_stats(handle->m_engine, stats);
	}

	return SCAP_SUCCESS;
}

int scap_get_modifies_state_ppm_sc(OUT uint32_t ppm_sc_array[PPM_SC_MAX])
{
	if(ppm_sc_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(ppm_sc_array, 0, sizeof(*ppm_sc_array) * PPM_SC_MAX);

#ifdef __linux__
	// Collect EF_MODIFIES_STATE events
	for (int event_nr = 0; event_nr < PPM_EVENT_MAX; event_nr++)
	{
		if (g_event_info[event_nr].flags & EF_MODIFIES_STATE)
		{
			for (int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
			{
				if (g_syscall_table[syscall_nr].exit_event_type == event_nr || g_syscall_table[syscall_nr].enter_event_type == event_nr)
				{
					uint32_t ppm_sc_code = g_syscall_table[syscall_nr].ppm_sc;
					ppm_sc_array[ppm_sc_code] = 1;
				}
			}
		}
	}

	// Collect UF_NEVER_DROP syscalls
	for (int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if (g_syscall_table[syscall_nr].flags & UF_NEVER_DROP)
		{
			uint32_t ppm_sc_code = g_syscall_table[syscall_nr].ppm_sc;
			ppm_sc_array[ppm_sc_code] = 1;
		}
	}
#endif
	return SCAP_SUCCESS;
}

int scap_get_events_from_ppm_sc(IN uint32_t ppm_sc_array[PPM_SC_MAX], OUT uint32_t events_array[PPM_EVENT_MAX])
{
	if(ppm_sc_array == NULL || events_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(events_array, 0, sizeof(*events_array) * PPM_EVENT_MAX);

#ifdef __linux__
	for(int ppm_code = 0; ppm_code< PPM_SC_MAX; ppm_code++)
	{
		if(!ppm_sc_array[ppm_code])
		{
			continue;
		}
		
		/* If we arrive here we want to know the events associated with this ppm_code. */
		for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
		{
			struct syscall_evt_pair pair = g_syscall_table[syscall_nr];
			if(pair.ppm_sc == ppm_code)
			{
				events_array[pair.enter_event_type] = 1;
				events_array[pair.exit_event_type] = 1;
			}
		}
	}
#endif
	return SCAP_SUCCESS;
}

int scap_get_modifies_state_tracepoints(OUT uint32_t tp_array[TP_VAL_MAX])
{
	if(tp_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(tp_array, 0, sizeof(*tp_array) * TP_VAL_MAX);

	tp_array[SYS_ENTER] = 1;
	tp_array[SYS_EXIT] = 1;
	tp_array[SCHED_PROC_EXIT] = 1;
	tp_array[SCHED_SWITCH] = 1;
	/* With `aarch64` and `s390x` we need also this, 
	 * in `x86` they are not considered at all.
	 */
	tp_array[SCHED_PROC_FORK] = 1;
	tp_array[SCHED_PROC_EXEC] = 1;
	return SCAP_SUCCESS;
}

unsigned long scap_get_system_page_size()
{
	long page_size = 0;
#ifdef __linux__
	page_size = sysconf(_SC_PAGESIZE);
	if(page_size <= 0)
	{
		return SCAP_FAILURE;
	}
#endif
	/// TODO: if needed we have to implement how to recover the page size in not Linux systems
	return page_size;
}

//
// Stop capturing the events
//
int32_t scap_stop_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->stop_capture(handle->m_engine);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot stop offline live captures");
	ASSERT(false);
	return SCAP_FAILURE;
#endif // HAS_CAPTURE
}

//
// Start capturing the events
//
int32_t scap_start_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->start_capture(handle->m_engine);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot start offline live captures");
	ASSERT(false);
	return SCAP_FAILURE;
#endif // HAS_CAPTURE
}

int32_t scap_enable_tracers_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_TRACERS_CAPTURE, 1, 0);
	}
#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT) && ! defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_tracers_capture not supported on this scap mode");
	ASSERT(false);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_tracers_capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#endif
}

int32_t scap_stop_dropping_mode(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, 1, 0);
	}
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_stop_dropping_mode not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_stop_dropping_mode not supported on this scap mode");
	ASSERT(false);
	return SCAP_FAILURE;
#endif
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, sampling_ratio, 1);
	}
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_start_dropping_mode not supported on this scap mode");
	ASSERT(false);
	return SCAP_FAILURE;
#endif
}

//
// Return the list of device addresses
//
scap_addrlist* scap_get_ifaddr_list(scap_t* handle)
{
	return handle->m_addrlist;
}

//
// Return the list of machine users
//
scap_userlist* scap_get_user_list(scap_t* handle)
{
	return handle->m_userlist;
}

//
// Get the machine information
//
const scap_machine_info* scap_get_machine_info(scap_t* handle)
{
	if(handle->m_machine_info.num_cpus != (uint32_t)-1)
	{
		return (const scap_machine_info*)&handle->m_machine_info;
	}
	else
	{
		//
		// Reading from a file with no process info block
		//
		return NULL;
	}
}

int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SNAPLEN, snaplen, 0);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
	return SCAP_FAILURE;
#endif
}

int64_t scap_get_readfile_offset(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->get_readfile_offset(handle->m_engine);
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_readfile_offset only works on captures");
		return SCAP_FAILURE;
	}
}

static int32_t scap_handle_eventmask(scap_t* handle, uint32_t op, uint32_t ppm_sc)
{
	if(handle == NULL)
	{
		return SCAP_FAILURE;
	}

	switch(op)
	{
	case SCAP_EVENTMASK_SET:
	case SCAP_EVENTMASK_UNSET:
	case SCAP_EVENTMASK_ZERO:
		break;
	
	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) internal error", __FUNCTION__, op);
		ASSERT(false);
		return SCAP_FAILURE;
		break;
	}

	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_EVENTMASK, op, ppm_sc);
	}
#if !defined(HAS_CAPTURE) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "manipulating eventmasks not supported on this scap mode");
	return SCAP_FAILURE;
#endif // HAS_CAPTURE
}

int32_t scap_clear_eventmask(scap_t* handle) {
	return(scap_handle_eventmask(handle, SCAP_EVENTMASK_ZERO, 0));
}

int32_t scap_set_eventmask(scap_t* handle, uint32_t ppm_sc, bool enabled) {
	return(scap_handle_eventmask(handle, enabled ? SCAP_EVENTMASK_SET : SCAP_EVENTMASK_UNSET, ppm_sc));
}

uint32_t scap_event_get_dump_flags(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->get_event_dump_flags(handle->m_engine);
	}
	else
	{
		return 0;
	}
}

int32_t scap_enable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 1, 0);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
	return SCAP_FAILURE;
#endif
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 0, 0);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
	return SCAP_FAILURE;
#endif // HAS_CAPTURE
}

const char* scap_get_host_root()
{
	char* p = getenv(SCAP_HOST_ROOT_ENV_VAR_NAME);
	static char env_str[SCAP_MAX_PATH_SIZE + 1];
	static bool inited = false;
	if (! inited) {
		strlcpy(env_str, p ? p : "", sizeof(env_str));
		inited = true;
	}

	return env_str;
}

bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error)
{
	uint32_t memsize;

	if(n_entries >= SCAP_DRIVER_PROCINFO_MAX_SIZE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list too big");
		return false;
	}

	memsize = sizeof(struct ppm_proclist_info) +
		sizeof(struct ppm_proc_info) * n_entries;

	struct ppm_proclist_info *procinfo = (struct ppm_proclist_info*) realloc(*proclist_p, memsize);
	if(procinfo == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list allocation error");
		return false;
	}

	if(*proclist_p == NULL)
	{
		procinfo->n_entries = 0;
	}

	procinfo->max_entries = n_entries;
	*proclist_p = procinfo;

	return true;
}

struct ppm_proclist_info* scap_get_threadlist(scap_t* handle)
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return NULL;
#else
	int res = handle->m_vtable->get_threadlist(handle->m_engine, &handle->m_driver_procinfo, handle->m_lasterr);
	if(res != SCAP_SUCCESS)
	{
		return NULL;
	}

	return handle->m_driver_procinfo;
#endif	// HAS_CAPTURE
}

void scap_set_refresh_proc_table_when_saving(scap_t* handle, bool refresh)
{
	handle->refresh_proc_table_when_saving = refresh;
}

uint64_t scap_ftell(scap_t *handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->ftell_capture(handle->m_engine);
	}
	else
	{
		return 0;
	}
}

void scap_fseek(scap_t *handle, uint64_t off)
{
	if(handle->m_vtable->savefile_ops)
	{
		handle->m_vtable->savefile_ops->fseek_capture(handle->m_engine, off);
	}
}

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_tracepoint_hit(handle->m_engine, ret);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "getting n_tracepoint_hit not supported on this scap mode");
	return SCAP_FAILURE;
#endif
}

#ifdef CYGWING_AGENT
wh_t* scap_get_wmi_handle(scap_t* handle)
{
	return handle->m_whh;
}
#endif

bool scap_check_current_engine(scap_t *handle, const char* engine_name)
{
	if(engine_name && handle && handle->m_vtable)
	{
		return strcmp(handle->m_vtable->name, engine_name) == 0;
	}
	return false;
}

int32_t scap_suppress_events_comm(scap_t *handle, const char *comm)
{
	// If the comm is already present in the list, do nothing
	uint32_t i;
	for(i=0; i<handle->m_num_suppressed_comms; i++)
	{
		if(strcmp(handle->m_suppressed_comms[i], comm) == 0)
		{
			return SCAP_SUCCESS;
		}
	}

	if(handle->m_num_suppressed_comms >= SCAP_MAX_SUPPRESSED_COMMS)
	{
		return SCAP_FAILURE;
	}

	handle->m_num_suppressed_comms++;
	handle->m_suppressed_comms = (char **) realloc(handle->m_suppressed_comms,
						       handle->m_num_suppressed_comms * sizeof(char *));

	handle->m_suppressed_comms[handle->m_num_suppressed_comms-1] = strdup(comm);

	return SCAP_SUCCESS;
}

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid)
{
	scap_tid *stid;
	HASH_FIND_INT64(handle->m_suppressed_tids, &tid, stid);

	return (stid != NULL);
}

int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_FULLCAPTURE_PORT_RANGE, range_start, range_end);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_set_fullcapture_port_range not supported on this scap mode");
	return SCAP_FAILURE;
#endif
}

int32_t scap_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_STATSD_PORT, port, 0);
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr,
	         SCAP_LASTERR_SIZE,
	         "scap_set_statsd_port not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	snprintf(handle->m_lasterr,
		 SCAP_LASTERR_SIZE,
		 "scap_set_statsd_port not supported on this scap mode");
	return SCAP_FAILURE;
#endif
}

bool scap_is_api_compatible(unsigned long driver_api_version, unsigned long required_api_version)
{
	unsigned long driver_major = PPM_API_VERSION_MAJOR(driver_api_version);
	unsigned long driver_minor = PPM_API_VERSION_MINOR(driver_api_version);
	unsigned long driver_patch = PPM_API_VERSION_PATCH(driver_api_version);
	unsigned long required_major = PPM_API_VERSION_MAJOR(required_api_version);
	unsigned long required_minor = PPM_API_VERSION_MINOR(required_api_version);
	unsigned long required_patch = PPM_API_VERSION_PATCH(required_api_version);

	if(driver_major != required_major)
	{
		// major numbers disagree
		return false;
	}

	if(driver_minor < required_minor)
	{
		// driver's minor version is < ours
		return false;
	}
	if(driver_minor == required_minor && driver_patch < required_patch)
	{
		// driver's minor versions match and patch level is < ours
		return false;
	}

	return true;
}

uint64_t scap_get_driver_api_version(scap_t* handle)
{
	return handle->m_api_version;
}

uint64_t scap_get_driver_schema_version(scap_t* handle)
{
	return handle->m_schema_version;
}
