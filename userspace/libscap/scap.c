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

#include "scap.h"
#include "strerror.h"
#include "strl.h"
#include "scap-int.h"
#include "scap_api_version.h"
#include "scap_platform.h"

#define SCAP_HANDLE_T void
#include "scap_engines.h"

#ifdef __linux__
#include "scap_linux_platform.h"
#else
// The test_input and source_plugin engines can optionally use a linux_platform
// but only on an actual Linux system.
//
// Still, to compile properly on non-Linux, provide an implementation
// of scap_linux_alloc_platform() that always fails at runtime.
struct scap_platform* scap_linux_alloc_platform()
{
	return NULL;
}
#endif

const char* scap_getlasterr(scap_t* handle)
{
	return handle ? handle->m_lasterr : "null scap handle";
}

int32_t scap_init_int(scap_t* handle, scap_open_args* oargs, const struct scap_vtable* vtable, struct scap_platform* platform)
{
	int32_t rc;

	//
	// Preliminary initializations
	//
	handle->m_vtable = vtable;
	handle->m_platform = platform;

	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		return SCAP_FAILURE;
	}

	if((rc = scap_generic_init_platform(handle->m_platform, handle->m_lasterr, oargs)) != SCAP_SUCCESS)
	{
		return rc;
	}

	handle->m_debug_log_fn = oargs->debug_log_fn;

	if(handle->m_vtable->init && (rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS)
	{
		return rc;
	}

	if((rc = scap_platform_init(handle->m_platform, handle->m_lasterr, handle->m_engine, oargs)) != SCAP_SUCCESS)
	{
		return rc;
	}

	rc = check_api_compatibility(handle->m_vtable, handle->m_engine, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	scap_stop_dropping_mode(handle);

	return SCAP_SUCCESS;
}

scap_t* scap_alloc(void)
{
	return malloc(sizeof(scap_t));
}

int32_t scap_init(scap_t* handle, scap_open_args* oargs)
{
	const char* engine_name = oargs->engine_name;
	struct scap_platform* platform = NULL;
	const struct scap_vtable* vtable = NULL;

	memset(handle, 0, sizeof(*handle));

	/* At the end of the `v-table` work we can use just one function
	 * with an internal switch that selects the right vtable! For the moment
	 * let's keep different functions.
	 */
#ifdef HAS_ENGINE_SAVEFILE
	if(strcmp(engine_name, SAVEFILE_ENGINE) == 0)
	{
		vtable = &scap_savefile_engine;
		platform = scap_savefile_alloc_platform();
	}
#endif
#ifdef HAS_ENGINE_UDIG
	if(strcmp(engine_name, UDIG_ENGINE) == 0)
	{
		vtable = &scap_udig_engine;
		platform = scap_linux_alloc_platform();
	}
#endif
#ifdef HAS_ENGINE_GVISOR
	if(strcmp(engine_name, GVISOR_ENGINE) == 0)
	{
		vtable = &scap_gvisor_engine;
		platform = scap_gvisor_alloc_platform();
	}
#endif
#ifdef HAS_ENGINE_TEST_INPUT
	if(strcmp(engine_name, TEST_INPUT_ENGINE) == 0)
	{
		vtable = &scap_test_input_engine;
		if(oargs->mode == SCAP_MODE_LIVE)
		{
			platform = scap_linux_alloc_platform();
		}
		else
		{
			platform = scap_test_input_alloc_platform();
		}
	}
#endif
#ifdef HAS_ENGINE_KMOD
	if(strcmp(engine_name, KMOD_ENGINE) == 0)
	{
		vtable = &scap_kmod_engine;
		platform = scap_linux_alloc_platform();
		if(platform)
		{
			((struct scap_linux_platform*)platform)->m_linux_vtable = &scap_kmod_linux_vtable;
		}
	}
#endif
#ifdef HAS_ENGINE_BPF
	if(strcmp(engine_name, BPF_ENGINE) == 0)
	{
		vtable = &scap_bpf_engine;
		platform = scap_linux_alloc_platform();
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	if(strcmp(engine_name, MODERN_BPF_ENGINE) == 0)
	{
		vtable = &scap_modern_bpf_engine;
		platform = scap_linux_alloc_platform();
	}
#endif
#ifdef HAS_ENGINE_NODRIVER
	if(strcmp(engine_name, NODRIVER_ENGINE) == 0)
	{
		vtable = &scap_nodriver_engine;
		platform = scap_linux_alloc_platform();
		struct scap_nodriver_engine_params* engine_params = oargs->engine_params;

		if(platform)
		{
			if(!engine_params || !engine_params->full_proc_scan)
			{
				((struct scap_linux_platform*)platform)->m_fd_lookup_limit = SCAP_NODRIVER_MAX_FD_LOOKUP;
				((struct scap_linux_platform*)platform)->m_minimal_scan = true;
			}
		}
		else
		{
			platform = scap_generic_alloc_platform();
		}
	}
#endif
#ifdef HAS_ENGINE_SOURCE_PLUGIN
	if(strcmp(engine_name, SOURCE_PLUGIN_ENGINE) == 0)
	{
		vtable = &scap_source_plugin_engine;
		if(oargs->mode == SCAP_MODE_LIVE)
		{
			platform = scap_linux_alloc_platform();
		}
		else
		{
			platform = scap_generic_alloc_platform();
		}
	}
#endif

	if(!vtable)
	{
		return scap_errprintf(handle->m_lasterr, 0, "incorrect engine '%s'", engine_name);
	}

	if(!platform)
	{
		return scap_errprintf(handle->m_lasterr, 0, "failed to allocate platform data");
	}

	return scap_init_int(handle, oargs, vtable, platform);
}

scap_t* scap_open(scap_open_args* oargs, char *error, int32_t *rc)
{
	scap_t* handle = scap_alloc();
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not allocatet memory for the scap handle");
		return NULL;
	}

	*rc = scap_init(handle, oargs);
	if(*rc != SCAP_SUCCESS)
	{
		strlcpy(error, handle->m_lasterr, SCAP_LASTERR_SIZE);
		scap_close(handle);
		return NULL;
	}

	return handle;
}

uint32_t scap_restart_capture(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->restart_capture(handle);
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "capture restart supported only in capture mode");
		return SCAP_FAILURE;
	}
}

void scap_deinit(scap_t* handle)
{
	if(handle->m_platform)
	{
		scap_platform_close(handle->m_platform);
		scap_platform_free(handle->m_platform);
	}

	if(handle->m_vtable)
	{
		/* The capture should be stopped before
		 * closing the engine, here we only enforce it.
		 * Please note that there are some corner cases in which
		 * we call `scap_close` before the engine is validated
		 * so we need to pay attention to NULL pointers in the
		 * following v-table methods.
		 */
		handle->m_vtable->stop_capture(handle->m_engine);
		handle->m_vtable->close(handle->m_engine);
		handle->m_vtable->free_handle(handle->m_engine);
	}
}

void scap_free(scap_t* handle)
{
	//
	// Release the handle
	//
	free(handle);
}

void scap_close(scap_t* handle)
{
	scap_deinit(handle);
	scap_free(handle);
}
uint32_t scap_get_ndevs(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_devs(handle->m_engine);
	}
	return 1;
}

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len)
{
	// engines do not even necessarily have a concept of a buffer
	// that you read events from
	return SCAP_NOT_SUPPORTED;
}

uint64_t scap_max_buf_used(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_max_buf_used(handle->m_engine);
	}
	return 0;
}

int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pdevid)
{
	// Note: devid is like cpuid but not 1:1, e.g. consider CPU1 offline:
	// CPU0 CPU1 CPU2 CPU3
	// DEV0 DEV1 DEV2 DEV3 <- CPU1  online
	// DEV0 XXXX DEV1 DEV2 <- CPU1 offline
	int32_t res = SCAP_FAILURE;
	if(handle->m_vtable)
	{
		res = handle->m_vtable->next(handle->m_engine, pevent, pdevid);
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
		if((res = scap_check_suppressed(&handle->m_platform->m_suppress, *pevent, *pdevid, &suppressed, handle->m_lasterr)) != SCAP_SUCCESS)
		{
			return res;
		}

		if(suppressed)
		{
			handle->m_platform->m_suppress.m_num_suppressed_evts++;
			return SCAP_FILTERED_EVENT;
		}
		else
		{
			handle->m_evtcnt++;
		}
	}

	return res;
}

//
// Return the number of dropped events for the given handle.
//
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	if(stats == NULL)
	{
		return SCAP_FAILURE;
	}

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
	stats->n_drops_buffer_close_exit = 0;
	stats->n_drops_buffer_proc_exit = 0;
	stats->n_drops_scratch_map = 0;
	stats->n_drops_pf = 0;
	stats->n_drops_bug = 0;
	stats->n_preemptions = 0;
	stats->n_suppressed = handle->m_platform->m_suppress.m_num_suppressed_evts;
	stats->n_tids_suppressed = HASH_COUNT(handle->m_platform->m_suppress.m_suppressed_tids);

	if(handle->m_vtable)
	{
		return handle->m_vtable->get_stats(handle->m_engine, stats);
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

//
// Return engine statistics (including counters and `bpftool prog show` like stats)
//
const struct scap_stats_v2* scap_get_stats_v2(scap_t* handle, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_stats_v2(handle->m_engine, flags, nstats, rc);
	}
	ASSERT(false);
	*nstats = 0;
	*rc = SCAP_FAILURE;
	return NULL;
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

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
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

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_enable_tracers_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_TRACERS_CAPTURE, 1, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_stop_dropping_mode(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, 1, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	switch(sampling_ratio)
	{
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			break;
		default:
			return snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "invalid sampling ratio size");
	}

	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, sampling_ratio, 1);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SNAPLEN, snaplen, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
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

int32_t scap_set_ppm_sc(scap_t* handle, ppm_sc_code ppm_sc, bool enabled)
{
	if (handle == NULL)
	{
		return SCAP_FAILURE;
	}
	if (ppm_sc >= PPM_SC_MAX)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) wrong param", __FUNCTION__, ppm_sc);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	uint32_t op =  enabled ? SCAP_PPM_SC_MASK_SET : SCAP_PPM_SC_MASK_UNSET;

	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_PPM_SC_MASK, op, ppm_sc);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_set_dropfailed(scap_t* handle, bool enabled) {
	if(handle && handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DROP_FAILED, enabled, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
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

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 0, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
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
		free(*proclist_p);
		*proclist_p = NULL;
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

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

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
	return scap_suppress_events_comm_impl(&handle->m_platform->m_suppress, comm);
}

int32_t scap_suppress_events_tid(scap_t *handle, int64_t tid)
{
	return scap_suppress_events_tid_impl(&handle->m_platform->m_suppress, tid);
}

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid)
{
	return scap_check_suppressed_tid_impl(&handle->m_platform->m_suppress, tid);
}

int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_FULLCAPTURE_PORT_RANGE, range_start, range_end);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_STATSD_PORT, port, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

uint64_t scap_get_driver_api_version(scap_t* handle)
{
	if(handle->m_vtable && handle->m_vtable->get_api_version)
	{
		return handle->m_vtable->get_api_version(handle->m_engine);
	}

	return 0;
}

uint64_t scap_get_driver_schema_version(scap_t* handle)
{
	if(handle->m_vtable && handle->m_vtable->get_schema_version)
	{
		return handle->m_vtable->get_schema_version(handle->m_engine);
	}

	return 0;
}
