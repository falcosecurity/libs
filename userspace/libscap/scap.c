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
scap_t* scap_open_live_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char *bpf_probe,
			   const char **suppressed_comms,
			   interesting_ppm_sc_set *ppm_sc_of_interest)
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

static uint32_t get_max_consumers()
{
#ifndef _WIN32
	uint32_t max;
	FILE *pfile = fopen("/sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers", "r");
	if(pfile != NULL)
	{
		int w = fscanf(pfile, "%"PRIu32, &max);
		if(w == 0)
		{
			return 0;
		}

		fclose(pfile);
		return max;
	}
#endif

	return 0;
}

#ifndef _WIN32
scap_t* scap_open_live_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char *bpf_probe,
			   const char **suppressed_comms,
			   interesting_ppm_sc_set *ppm_sc_of_interest)
{
	uint32_t j;
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;
	uint32_t ndevs;

	scap_open_args oargs;
	oargs.proc_callback = proc_callback;
	oargs.proc_callback_context = proc_callback_context;
	oargs.import_users = import_users;
	oargs.bpf_probe = bpf_probe;
	memcpy(&oargs.suppressed_comms, suppressed_comms, sizeof(*suppressed_comms));
	memcpy(&oargs.ppm_sc_of_interest, ppm_sc_of_interest, sizeof(*ppm_sc_of_interest));

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

	if(scap_bpf_engine.match(&oargs))
	{
		handle->m_vtable = &scap_bpf_engine;
		handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
		if(!handle->m_engine.m_handle)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error allocating the engine structure");
			free(handle);
			return NULL;
		}
	}
	else
	{
		handle->m_engine.m_handle = &handle->m_kmod_engine;
		handle->m_kmod_engine.m_lasterr = handle->m_lasterr;
	}

	//
	// Extract machine information
	//
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
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
	if(import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
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

	if ((*rc = copy_comms(handle, suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	//
	// Open and initialize all the devices
	//
	if(handle->m_vtable == &scap_bpf_engine)
	{
		if((*rc = handle->m_vtable->init(handle, &oargs)) != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
			scap_close(handle);
			return NULL;
		}
	}
	else
	{
		int len;
		uint32_t all_scanned_devs;
		uint64_t api_version;
		uint64_t schema_version;

		handle->m_ncpus = sysconf(_SC_NPROCESSORS_CONF);
		if(handle->m_ncpus == -1)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "_SC_NPROCESSORS_CONF: %s", scap_strerror(handle, errno));
			*rc = SCAP_FAILURE;
			return NULL;
		}

		//
		// Find out how many devices we have to open, which equals to the number of CPUs
		//
		ndevs = sysconf(_SC_NPROCESSORS_ONLN);
		if(ndevs == -1)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "_SC_NPROCESSORS_ONLN: %s", scap_strerror(handle, errno));
			*rc = SCAP_FAILURE;
			return NULL;
		}

		*rc = devset_init(&handle->m_kmod_engine.m_dev_set, ndevs, error);
		if(*rc != SCAP_SUCCESS)
		{
			scap_close(handle);
			return NULL;
		}
		fill_syscalls_of_interest(ppm_sc_of_interest, &handle->syscalls_of_interest);

		//
		// Allocate the device descriptors.
		//
		len = RING_BUF_SIZE * 2;

		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		for(j = 0, all_scanned_devs = 0; j < devset->m_ndevs && all_scanned_devs < handle->m_ncpus; ++all_scanned_devs)
		{
			struct scap_device *dev = &devset->m_devs[j];

			//
			// Open the device
			//
			snprintf(filename, sizeof(filename), "%s/dev/" DRIVER_DEVICE_NAME "%d", scap_get_host_root(), all_scanned_devs);

			if((dev->m_fd = open(filename, O_RDWR | O_SYNC)) < 0)
			{
				if(errno == ENODEV)
				{
					//
					// This CPU is offline, so we just skip it
					//
					continue;
				}
				else if(errno == EBUSY)
				{
					uint32_t curr_max_consumers = get_max_consumers();
					snprintf(error, SCAP_LASTERR_SIZE, "Too many consumers attached to device %s. Current value for /sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers is '%"PRIu32"'.", filename, curr_max_consumers);
				}
				else
				{
					snprintf(error, SCAP_LASTERR_SIZE, "error opening device %s. Make sure you have root credentials and that the " DRIVER_NAME " module is loaded.", filename);
				}

				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			// Set close-on-exec for the fd
			if (fcntl(dev->m_fd, F_SETFD, FD_CLOEXEC) == -1) {
				snprintf(error, SCAP_LASTERR_SIZE, "Can not set close-on-exec flag for fd for device %s (%s)", filename, scap_strerror(handle, errno));
				close(dev->m_fd);
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			// Check the API version reported
			if (ioctl(dev->m_fd, PPM_IOCTL_GET_API_VERSION, &api_version) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "Kernel module does not support PPM_IOCTL_GET_API_VERSION");
				close(dev->m_fd);
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}
			// Make sure all devices report the same API version
			if (handle->m_api_version != 0 && handle->m_api_version != api_version)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "API version mismatch: device %s reports API version %llu.%llu.%llu, expected %llu.%llu.%llu",
					filename,
					PPM_API_VERSION_MAJOR(api_version),
					PPM_API_VERSION_MINOR(api_version),
					PPM_API_VERSION_PATCH(api_version),
					PPM_API_VERSION_MAJOR(handle->m_api_version),
					PPM_API_VERSION_MINOR(handle->m_api_version),
					PPM_API_VERSION_PATCH(handle->m_api_version)
				);
				close(dev->m_fd);
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}
			// Set the API version from the first device
			// (for subsequent devices it's a no-op thanks to the check above)
			handle->m_api_version = api_version;

			// Check the schema version reported
			if (ioctl(dev->m_fd, PPM_IOCTL_GET_SCHEMA_VERSION, &schema_version) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "Kernel module does not support PPM_IOCTL_GET_SCHEMA_VERSION");
				close(dev->m_fd);
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}
			// Make sure all devices report the same schema version
			if (handle->m_schema_version != 0 && handle->m_schema_version != schema_version)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "Schema version mismatch: device %s reports schema version %llu.%llu.%llu, expected %llu.%llu.%llu",
					filename,
					PPM_API_VERSION_MAJOR(schema_version),
					PPM_API_VERSION_MINOR(schema_version),
					PPM_API_VERSION_PATCH(schema_version),
					PPM_API_VERSION_MAJOR(handle->m_schema_version),
					PPM_API_VERSION_MINOR(handle->m_schema_version),
					PPM_API_VERSION_PATCH(handle->m_schema_version)
				);
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}
			// Set the schema version from the first device
			// (for subsequent devices it's a no-op thanks to the check above)
			handle->m_schema_version = schema_version;

			//
			// Map the ring buffer
			//
			dev->m_buffer = (char*)mmap(0,
						len,
						PROT_READ,
						MAP_SHARED,
						dev->m_fd,
						0);

			if(dev->m_buffer == MAP_FAILED)
			{
				// we cleanup this fd and then we let scap_close() take care of the other ones
				close(dev->m_fd);

				scap_close(handle);
				snprintf(error, SCAP_LASTERR_SIZE, "error mapping the ring buffer for device %s", filename);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			//
			// Map the ppm_ring_buffer_info that contains the buffer pointers
			//
			dev->m_bufinfo = (struct ppm_ring_buffer_info*)mmap(0,
						sizeof(struct ppm_ring_buffer_info),
						PROT_READ | PROT_WRITE,
						MAP_SHARED,
						dev->m_fd,
						0);

			if(dev->m_bufinfo == MAP_FAILED)
			{
				// we cleanup this fd and then we let scap_close() take care of the other ones
				munmap(dev->m_buffer, len);
				close(dev->m_fd);

				scap_close(handle);

				snprintf(error, SCAP_LASTERR_SIZE, "error mapping the ring buffer info for device %s", filename);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			++j;
		}

		for (int i = 0; i < SYSCALL_TABLE_SIZE; i++)
		{
			if (!handle->syscalls_of_interest[i])
			{
				// Kmod driver event_mask check uses event_types instead of syscall nr
				enum ppm_event_type enter_ev = g_syscall_table[i].enter_event_type;
				enum ppm_event_type exit_ev = g_syscall_table[i].exit_event_type;
				// Filter unmapped syscalls (that have a g_syscall_table entry with both enter_ev and exit_ev 0ed)
				if (enter_ev != 0 && exit_ev != 0)
				{
					scap_unset_eventmask(handle, enter_ev);
					scap_unset_eventmask(handle, exit_ev);
				}
			}
		}
	}

	*rc = check_api_compatibility(handle, handle->m_lasterr);
	if(*rc != SCAP_SUCCESS)
	{
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

	//
	// Extract machine information
	//
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
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
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
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

scap_t* scap_open_offline_int(scap_reader_t* reader,
			      char *error,
			      int32_t *rc,
			      proc_entry_callback proc_callback,
			      void* proc_callback_context,
			      bool import_users,
			      uint64_t start_offset,
			      const char **suppressed_comms)
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
	handle->m_vtable = NULL;
	handle->m_mode = SCAP_MODE_CAPTURE;
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
	handle->m_proclist = NULL;
	handle->m_dev_list = NULL;
	handle->m_evtcnt = 0;
	handle->m_addrlist = NULL;
	handle->m_userlist = NULL;
	handle->m_machine_info.num_cpus = (uint32_t)-1;
	handle->m_last_evt_dump_flags = 0;
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

	handle->m_reader_evt_buf = (char*)malloc(READER_BUF_SIZE);
	if(!handle->m_reader_evt_buf)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the read buffer");
		scap_close(handle);
		*rc = SCAP_FAILURE;
		return NULL;
	}
	handle->m_reader_evt_buf_size = READER_BUF_SIZE;

	handle->m_reader = reader;
	handle->m_unexpected_block_readsize = 0;

	//
	// If this is a merged file, we might have to move the read offset to the next section
	//
	if(start_offset != 0)
	{
		scap_fseek(handle, start_offset);
	}

	//
	// Validate the file and load the non-event blocks
	//
	if((*rc = scap_read_init(handle, handle->m_reader)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not initialize reader: %s", scap_getlasterr(handle));
		scap_close(handle);
		return NULL;
	}

	if(!import_users)
	{
		if(handle->m_userlist != NULL)
		{
			scap_free_userlist(handle->m_userlist);
			handle->m_userlist = NULL;
		}
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

	if ((*rc = copy_comms(handle, suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	return handle;
}

scap_t* scap_open_offline(const char* fname, char *error, int32_t* rc)
{
	gzFile gzfile = gzopen(fname, "rb");
	if(gzfile == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open file %s", fname);
		*rc = SCAP_FAILURE;
		return NULL;
	}
	scap_reader_t* reader = scap_reader_open_gzfile(gzfile);

	return scap_open_offline_int(reader, error, rc, NULL, NULL, true, 0, NULL);
}

scap_t* scap_open_offline_fd(int fd, char *error, int32_t *rc)
{
	gzFile gzfile = gzdopen(fd, "rb");
	if(gzfile == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		*rc = SCAP_FAILURE;
		return NULL;
	}
	scap_reader_t* reader = scap_reader_open_gzfile(gzfile);

	return scap_open_offline_int(reader, error, rc, NULL, NULL, true, 0, NULL);
}

scap_t* scap_open_live(char *error, int32_t *rc)
{
	return scap_open_live_int(error, rc, NULL, NULL, true, NULL, NULL, NULL);
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

	//
	// Extract machine information
	//
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
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
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
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
		snprintf(error, SCAP_LASTERR_SIZE, "scap_open_live() error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		return NULL;
	}

	return handle;
#endif // HAS_CAPTURE
}

scap_t* scap_open_plugin_int(char *error, int32_t *rc, scap_source_plugin * input_plugin, char* input_plugin_params)
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

	//
	// Extract machine information
	//
	handle->m_proc_callback = NULL;
	handle->m_proc_callback_context = NULL;
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

	return handle;
}

scap_t* scap_open(scap_open_args args, char *error, int32_t *rc)
{
	scap_t *handle;
	switch(args.mode)
	{
	case SCAP_MODE_CAPTURE:
	{
		gzFile gzfile;

		if(args.fd != 0)
		{
			gzfile = gzdopen(args.fd, "rb");
		}
		else
		{
			gzfile = gzopen(args.fname, "rb");
		}

		if(gzfile == NULL)
		{
			if(args.fd != 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't open fd %d", args.fd);
			}
			else
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't open file %s", args.fname);
			}
			*rc = SCAP_FAILURE;
			return NULL;
		}

		scap_reader_t* reader = scap_reader_open_gzfile(gzfile);
		return scap_open_offline_int(reader, error, rc,
					     args.proc_callback, args.proc_callback_context,
					     args.import_users, args.start_offset,
					     args.suppressed_comms);
	}
	case SCAP_MODE_LIVE:
#ifndef CYGWING_AGENT
		if(args.udig)
		{
			return scap_open_udig_int(error, rc, args.proc_callback,
						args.proc_callback_context,
						args.import_users,
						args.suppressed_comms);
		}
		else
		{
			return scap_open_live_int(error, rc, args.proc_callback,
						args.proc_callback_context,
						args.import_users,
						args.bpf_probe,
						args.suppressed_comms,
						&args.ppm_sc_of_interest);
		}
#else
		snprintf(error,	SCAP_LASTERR_SIZE, "scap_open: live mode currently not supported on Windows.");
		*rc = SCAP_NOT_SUPPORTED;
		return NULL;
#endif
	case SCAP_MODE_NODRIVER:
		return scap_open_nodriver_int(error, rc, args.proc_callback,
					      args.proc_callback_context,
					      args.import_users);
	case SCAP_MODE_PLUGIN:
		handle = scap_open_plugin_int(error, rc, args.input_plugin, args.input_plugin_params);
		if(handle && handle->m_vtable)
		{
			int32_t res = handle->m_vtable->init(handle, &args);
			if(res != SCAP_SUCCESS)
			{
				strlcpy(error, handle->m_lasterr, SCAP_LASTERR_SIZE);
				scap_close(handle);
				handle = NULL;
			}
			*rc = res;
			return handle;
		}
	case SCAP_MODE_NONE:
		// error
		break;
	}


	snprintf(error, SCAP_LASTERR_SIZE, "incorrect mode %d", args.mode);
	*rc = SCAP_FAILURE;
	return NULL;
}

static inline void scap_deinit_state(scap_t* handle)
{
	// Free the process table
	if(handle->m_proclist != NULL)
	{
		scap_proc_free_table(handle);
		handle->m_proclist = NULL;
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
	uint32_t res;
	if (handle->m_mode != SCAP_MODE_CAPTURE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "capture restart supported only in capture mode");
		res = SCAP_FAILURE;
	}
	else
	{
		scap_deinit_state(handle);
		if (handle->m_unexpected_block_readsize > 0)
		{
			scap_reader_seek(handle->m_reader, (int64_t)0 - (int64_t)handle->m_unexpected_block_readsize, SEEK_CUR);
			handle->m_unexpected_block_readsize = 0;
		}
		if((res = scap_read_init(handle, handle->m_reader)) != SCAP_SUCCESS)
		{
			char error[SCAP_LASTERR_SIZE];
			snprintf(error, SCAP_LASTERR_SIZE, "could not restart capture: %s", scap_getlasterr(handle));
			strncpy(handle->m_lasterr, error, SCAP_LASTERR_SIZE);
		}
	}
	return res;
}

void scap_close(scap_t* handle)
{
	if(handle->m_mode == SCAP_MODE_CAPTURE)
	{
		if (handle->m_reader)
		{
			scap_reader_close(handle->m_reader);
			handle->m_reader = NULL;
		}
	}
	else if(handle->m_mode == SCAP_MODE_LIVE)
	{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		ASSERT(handle->m_reader == NULL);

		if(devset->m_devs != NULL)
		{
#ifndef _WIN32
			{
				//
				// Destroy all the device descriptors
				//
				uint32_t j;
				for(j = 0; j < devset->m_ndevs; j++)
				{
					struct scap_device *dev = &devset->m_devs[j];
					if(dev->m_buffer != MAP_FAILED)
					{
						munmap(dev->m_bufinfo, sizeof(struct ppm_ring_buffer_info));
						munmap(dev->m_buffer, RING_BUF_SIZE * 2);
						close(dev->m_fd);
					}
				}
			}
#endif
			//
			// Free the memory
			//
			free(devset->m_devs);
		}
#endif // HAS_CAPTURE
	}

#if CYGWING_AGENT || _WIN32
	if(handle->m_whh != NULL)
	{
		scap_windows_hal_close(handle->m_whh);
	}
#endif

	if(handle->m_reader_evt_buf)
	{
		free(handle->m_reader_evt_buf);
		handle->m_reader_evt_buf = NULL;
	}

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
	return handle->m_kmod_engine.m_dev_set.m_ndevs;
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)

#ifndef _WIN32
static inline void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint64_t* pread_size)
#else
void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint64_t* pread_size)
#endif
{
	*phead = bufinfo->head;
	*ptail = bufinfo->tail;

	if(*ptail > *phead)
	{
		*pread_size = RING_BUF_SIZE - *ptail + *phead;
	}
	else
	{
		*pread_size = *phead - *ptail;
	}
}

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len)
{
	uint32_t thead;
	uint32_t ttail;
	uint64_t read_size;
	struct scap_device* dev;

	if(handle->m_vtable)
	{
		// engines do not even necessarily have a concept of a buffer
		// that you read events from
		return SCAP_NOT_SUPPORTED;
	}

	dev = &handle->m_kmod_engine.m_dev_set.m_devs[cpuid];

	//
	// Read the pointers.
	//
	get_buf_pointers(dev->m_bufinfo, &thead, &ttail, &read_size);

	//
	// Remember read_size so we can update the tail at the next call
	//
	dev->m_lastreadsize = (uint32_t)read_size;

	//
	// Return the results
	//
	*len = (uint32_t)read_size;
	*buf = dev->m_buffer + ttail;

	return SCAP_SUCCESS;
}

static uint64_t buf_size_used(struct scap_device *dev)
{
	uint64_t read_size;

	{
		uint32_t thead;
		uint32_t ttail;

		get_buf_pointers(dev->m_bufinfo, &thead, &ttail, &read_size);
	}

	return read_size;
}

#endif // HAS_CAPTURE

int32_t scap_next_kmod(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);

uint64_t scap_max_buf_used(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_max_buf_used(handle->m_engine);
	}
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	uint64_t i;
	uint64_t max = 0;
	struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;

	for(i = 0; i < devset->m_ndevs; i++)
	{
		uint64_t size = buf_size_used(&devset->m_devs[i]);
		max = size > max ? size : max;
	}

	return max;
#else
	return 0;
#endif
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
		switch(handle->m_mode)
		{
		case SCAP_MODE_CAPTURE:
			res = scap_next_offline(handle, pevent, pcpuid);
			break;
		case SCAP_MODE_LIVE:
			res = scap_next_kmod(handle, pevent, pcpuid);
			break;
		case SCAP_MODE_PLUGIN:
		case SCAP_MODE_NODRIVER:
		case SCAP_MODE_NONE:
			res = SCAP_FAILURE;
		}
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
	return handle->m_proclist;
}

//
// Return the number of dropped events for the given handle
//
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	stats->n_evts = 0;
	stats->n_drops = 0;
	stats->n_drops_buffer = 0;
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
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		uint32_t j;

		for(j = 0; j < devset->m_ndevs; j++)
		{
			struct scap_device *dev = &devset->m_devs[j];
			stats->n_evts += dev->m_bufinfo->n_evts;
			stats->n_drops_buffer += dev->m_bufinfo->n_drops_buffer;
			stats->n_drops_pf += dev->m_bufinfo->n_drops_pf;
			stats->n_drops += dev->m_bufinfo->n_drops_buffer +
						dev->m_bufinfo->n_drops_pf;
			stats->n_preemptions += dev->m_bufinfo->n_preemptions;
		}
	}
#endif

	return SCAP_SUCCESS;
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
	uint32_t j;

	//
	// Not supported for files
	//
	if(handle->m_mode == SCAP_MODE_LIVE)
	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		//
		// Disable capture on all the rings
		//
		for(j = 0; j < devset->m_ndevs; j++)
		{
			struct scap_device *dev = &devset->m_devs[j];
			{
#ifndef _WIN32
				if(ioctl(dev->m_fd, PPM_IOCTL_DISABLE_CAPTURE))
				{
					snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_stop_capture failed for device %" PRIu32, j);
					ASSERT(false);
					return SCAP_FAILURE;
				}
#endif
			}
		}
	}
	else
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot stop offline live captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
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

	//
	// Not supported for files
	//
	if(handle->m_mode == SCAP_MODE_LIVE)
	{
		//
		// Enable capture on all the rings
		//
		{
#ifndef _WIN32
			uint32_t j;
			struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
			for(j = 0; j < devset->m_ndevs; j++)
			{
				if(ioctl(devset->m_devs[j].m_fd, PPM_IOCTL_ENABLE_CAPTURE))
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_start_capture failed for device %" PRIu32, j);
					ASSERT(false);
					return SCAP_FAILURE;
				}
			}
#endif
		}
	}
	else
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot start offline live captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
static int32_t scap_set_dropping_mode(scap_t* handle, int request, uint32_t sampling_ratio)
{
#ifndef _WIN32
	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s: dropping not supported in replay mode", __FUNCTION__);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
	if(devset->m_ndevs)
	{
		ASSERT((request == PPM_IOCTL_ENABLE_DROPPING_MODE &&
			((sampling_ratio == 1)  ||
				(sampling_ratio == 2)  ||
				(sampling_ratio == 4)  ||
				(sampling_ratio == 8)  ||
				(sampling_ratio == 16) ||
				(sampling_ratio == 32) ||
				(sampling_ratio == 64) ||
				(sampling_ratio == 128))) || (request == PPM_IOCTL_DISABLE_DROPPING_MODE));

		if(ioctl(devset->m_devs[0].m_fd, request, sampling_ratio))
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "%s, request %d for sampling ratio %u: %s",
					__FUNCTION__, request, sampling_ratio, scap_strerror(handle, errno));
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}
#endif
	return SCAP_SUCCESS;
}
#endif

int32_t scap_enable_tracers_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_TRACERS_CAPTURE, 1, 0);
	}
#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT) && ! defined(_WIN32)
	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_tracers_capture not supported on this scap mode");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
	if(devset->m_ndevs)
	{
		{
			if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_TRACERS_CAPTURE))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s failed", __FUNCTION__);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_tracers_capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#endif
}

int32_t scap_enable_page_faults(scap_t *handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_PAGE_FAULTS, 1, 0);
	}
#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT) && ! defined(_WIN32)
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_page_faults not supported on this scap mode");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
	if(devset->m_ndevs)
	{
		{
			if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_ENABLE_PAGE_FAULTS))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s failed", __FUNCTION__);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
#else
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_page_faults not supported on %s", PLATFORM_NAME);
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
	{
		return scap_set_dropping_mode(handle, PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
	}
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
	{
		return scap_set_dropping_mode(handle, PPM_IOCTL_ENABLE_DROPPING_MODE, sampling_ratio);
	}
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
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

#ifndef _WIN32
	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		//
		// Tell the driver to change the snaplen
		//
		if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_SNAPLEN, snaplen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_set_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't capture events with the old snaplen
			//
			for(j = 0; j < devset->m_ndevs; j++)
			{
				scap_readbuf(handle,
							j,
							&devset->m_devs[j].m_sn_next_event,
							&devset->m_devs[j].m_sn_len);

				devset->m_devs[j].m_sn_len = 0;
			}
		}
	}
#endif // _WIN32

	return SCAP_SUCCESS;
#endif
}

int64_t scap_get_readfile_offset(scap_t* handle)
{
	if(handle->m_mode != SCAP_MODE_CAPTURE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_get_readfile_offset only works on captures");
		return -1;
	}

	return scap_reader_offset(handle->m_reader);
}

static int32_t scap_handle_eventmask(scap_t* handle, uint32_t op, uint32_t event_id)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_EVENTMASK, op, event_id);
	}
#if !defined(HAS_CAPTURE) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	if (handle == NULL)
	{
		return SCAP_FAILURE;
	}

	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "manipulating eventmasks not supported on this scap mode");
		return SCAP_FAILURE;
	}

	//
	// Tell the driver to change the snaplen
	//

	switch(op) {
	case PPM_IOCTL_MASK_ZERO_EVENTS:
	case PPM_IOCTL_MASK_SET_EVENT:
	case PPM_IOCTL_MASK_UNSET_EVENT:
		break;

	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) internal error", __FUNCTION__, op);
		ASSERT(false);
		return SCAP_FAILURE;
		break;
	}

	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		if(ioctl(devset->m_devs[0].m_fd, op, event_id))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE,
				 "%s(%d) failed for event type %d",
				 __FUNCTION__, op, event_id);
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't capture events with the old snaplen
			//
			for(j = 0; j < devset->m_ndevs; j++)
			{
				scap_readbuf(handle,
					j,
					&devset->m_devs[j].m_sn_next_event,
					&devset->m_devs[j].m_sn_len);

				devset->m_devs[j].m_sn_len = 0;
			}
		}
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

int32_t scap_clear_eventmask(scap_t* handle) {
	return(scap_handle_eventmask(handle, SCAP_EVENTMASK_ZERO, 0));
}

int32_t scap_set_eventmask(scap_t* handle, uint32_t event_id) {
	return(scap_handle_eventmask(handle, SCAP_EVENTMASK_SET, event_id));
}

int32_t scap_unset_eventmask(scap_t* handle, uint32_t event_id) {
	return(scap_handle_eventmask(handle, SCAP_EVENTMASK_UNSET, event_id));
}

uint32_t scap_event_get_dump_flags(scap_t* handle)
{
	return handle->m_last_evt_dump_flags;
}

int32_t scap_enable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 1, 0);
	}
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
#ifndef _WIN32
	{
		if(ioctl(handle->m_kmod_engine.m_dev_set.m_devs[0].m_fd, PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_dynamic_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}
#endif // _WIN32

	return SCAP_SUCCESS;
#endif
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 0, 0);
	}
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
#ifndef _WIN32
	//
	// Tell the driver to change the snaplen
	//
	{
		if(ioctl(handle->m_kmod_engine.m_dev_set.m_devs[0].m_fd, PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_disable_dynamic_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}
#endif // _WIN32
	return SCAP_SUCCESS;
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

int32_t scap_kmod_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p)
{
	struct kmod_engine* kmod_engine = engine.m_handle;
	int ioctlres = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_PROCLIST, procinfo_p);
	if(ioctlres)
	{
		if(errno == ENOSPC)
		{
			if(scap_alloc_proclist_info(procinfo_p, (*procinfo_p)->n_entries + 256, kmod_engine->m_lasterr) == false)
			{
				return SCAP_FAILURE;
			}
			else
			{
				return scap_kmod_get_threadlist(engine, procinfo_p);
			}
		}
		else
		{
			snprintf(kmod_engine->m_lasterr, SCAP_LASTERR_SIZE, "Error calling PPM_IOCTL_GET_PROCLIST");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

struct ppm_proclist_info* scap_get_threadlist(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_threadlist not supported on this scap mode");
		return NULL;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return NULL;
#else
	if(handle->m_driver_procinfo == NULL)
	{
		if(scap_alloc_proclist_info(&handle->m_driver_procinfo, SCAP_DRIVER_PROCINFO_INITIAL_SIZE, handle->m_lasterr) == false)
		{
			return NULL;
		}
	}

	int res;
	if(handle->m_vtable)
	{
		res = handle->m_vtable->get_threadlist(handle->m_engine, &handle->m_driver_procinfo, handle->m_lasterr);
	}
	else
	{
		res = scap_kmod_get_threadlist(handle->m_engine, &handle->m_driver_procinfo);
	}
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

uint64_t scap_get_unexpected_block_readsize(scap_t* handle)
{
	return handle->m_unexpected_block_readsize;
}

int32_t scap_enable_simpledriver_mode(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SIMPLEDRIVER_MODE, 1, 0);
	}
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting simpledriver mode not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	{
		if(ioctl(handle->m_kmod_engine.m_dev_set.m_devs[0].m_fd, PPM_IOCTL_SET_SIMPLE_MODE))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_simpledriver_mode failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_tracepoint_hit(handle->m_engine, ret);
	}
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "getting n_tracepoint_hit not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	else
	{
		int ioctl_ret = 0;

		ioctl_ret = ioctl(handle->m_kmod_engine.m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_N_TRACEPOINT_HIT, ret);
		if(ioctl_ret != 0)
		{
			if(errno == ENOTTY)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_n_tracepoint_hit failed, ioctl not supported");
			}
			else
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_n_tracepoint_hit failed (%s)", scap_strerror(handle, errno));
			}

			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

#ifdef CYGWING_AGENT
wh_t* scap_get_wmi_handle(scap_t* handle)
{
	return handle->m_whh;
}
#endif

bool scap_get_bpf_enabled(scap_t *handle)
{
	if(handle && handle->m_vtable)
	{
		return !strcmp(handle->m_vtable->name, "bpf");
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
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_set_fullcapture_port_range not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		//
		// Encode the port range
		//
		uint32_t arg = (range_end << 16) + range_start;

		//
		// Beam the value down to the module
		//
		if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE, arg))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_set_fullcapture_port_range failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't capture events with the old snaplen
			//
			for(j = 0; j < devset->m_ndevs; j++)
			{
				scap_readbuf(handle,
							j,
							&devset->m_devs[j].m_sn_next_event,
							&devset->m_devs[j].m_sn_len);

				devset->m_devs[j].m_sn_len = 0;
			}
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_STATSD_PORT, port, 0);
	}
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr,
		         SCAP_LASTERR_SIZE,
		         "scap_set_statsd_port not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT) || defined(_WIN32)
	snprintf(handle->m_lasterr,
	         SCAP_LASTERR_SIZE,
	         "scap_set_statsd_port not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	{
		struct scap_device_set *devset = &handle->m_kmod_engine.m_dev_set;
		//
		// Beam the value down to the module
		//
		if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_STATSD_PORT, port))
		{
			snprintf(handle->m_lasterr,
			         SCAP_LASTERR_SIZE,
			         "scap_set_statsd_port: ioctl failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't
			// capture events with the old snaplen
			//
			for(j = 0; j < devset->m_ndevs; j++)
			{
				scap_readbuf(handle,
				             j,
				             &devset->m_devs[j].m_sn_next_event,
				             &devset->m_devs[j].m_sn_len);

				devset->m_devs[j].m_sn_len = 0;
			}
		}
	}

	return SCAP_SUCCESS;
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
