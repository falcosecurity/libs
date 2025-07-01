// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libscap/compat/misc.h>
#include <libscap/scap.h>
#include <libscap/strerror.h>
#include <libscap/strl.h>
#include <libscap/scap-int.h>
#include <libscap/scap_api_version.h>
#include <libscap/scap_platform.h>

#include <libscap/scap_engines.h>

#ifdef __linux__
#include <libscap/linux/scap_linux_platform.h>
#else
// The test_input and source_plugin engines can optionally use a linux_platform
// but only on an actual Linux system.
//
// Still, to compile properly on non-Linux, provide implementations
// of scap_linux_alloc_platform() and scap_linux_hostinfo_alloc_platform() that always fail at
// runtime.
struct scap_platform* scap_linux_alloc_platform(scap_proc_callbacks proc_callbacks) {
	return NULL;
}
struct scap_platform* scap_linux_hostinfo_alloc_platform() {
	return NULL;
}
#endif

const char* scap_getlasterr(scap_t* handle) {
	return handle ? handle->m_lasterr : "null scap handle";
}

int32_t scap_init_engine(scap_t* handle, scap_open_args* oargs, const struct scap_vtable* vtable) {
	int32_t rc;

	if(!handle) {
		return SCAP_FAILURE;
	}

	//
	// Preliminary initializations
	//
	handle->m_vtable = vtable;

	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle) {
		return scap_errprintf(handle->m_lasterr, 0, "error allocating the engine structure");
	}

	handle->m_log_fn = oargs->log_fn;

	if(handle->m_vtable->init && (rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS) {
		return rc;
	}

	rc = check_api_compatibility(handle->m_vtable, handle->m_engine, handle->m_lasterr);
	if(rc != SCAP_SUCCESS) {
		return rc;
	}

	scap_stop_dropping_mode(handle);
	return SCAP_SUCCESS;
}

scap_t* scap_alloc(void) {
	return calloc(1, sizeof(scap_t));
}

int32_t scap_init(scap_t* handle, scap_open_args* oargs, const struct scap_vtable* vtable) {
	int32_t rc;

	if(!handle) {
		return SCAP_FAILURE;
	}

	ASSERT(vtable != NULL);

	// Initialize the engine before the platform
	//
	// While the two would ideally be independent, the linux platform can delegate some
	// functionality to an engine through a scap_linux_vtable (currently only the kmod
	// engine provides this).
	//
	// The kmod hooks in the scap_linux_vtable need an initialized engine, since they call
	// ioctls on the driver fd, so we need to initialize the engine before the platform.

	rc = scap_init_engine(handle, oargs, vtable);
	if(rc != SCAP_SUCCESS) {
		return rc;
	}
	return SCAP_SUCCESS;
}

scap_t* scap_open(scap_open_args* oargs,
                  const struct scap_vtable* vtable,
                  char* error,
                  int32_t* rc) {
	scap_t* handle = scap_alloc();
	if(!handle) {
		scap_errprintf(error, 0, "Could not allocate memory for the scap handle");
		return NULL;
	}

	*rc = scap_init(handle, oargs, vtable);
	if(*rc != SCAP_SUCCESS) {
		scap_errprintf(error, 0, "%s", handle->m_lasterr);
		scap_close(handle);
		return NULL;
	}

	return handle;
}

uint32_t scap_restart_capture(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable->savefile_ops) {
		return handle->m_vtable->savefile_ops->restart_capture(handle);
	}

	return scap_errprintf(handle->m_lasterr, 0, "capture restart supported only in capture mode");
}

void scap_deinit(scap_t* handle) {
	if(handle->m_vtable) {
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

void scap_free(scap_t* handle) {
	//
	// Release the handle
	//
	free(handle);
}

void scap_close(scap_t* handle) {
	if(!handle) {
		return;
	}

	scap_deinit(handle);
	scap_free(handle);
}

uint64_t scap_get_engine_flags(scap_t* handle) {
	if(handle && handle->m_vtable && handle->m_vtable->get_flags) {
		return handle->m_vtable->get_flags(handle->m_engine);
	}
	return 0;
}

uint32_t scap_get_ndevs(scap_t* handle) {
	if(handle && handle->m_vtable) {
		return handle->m_vtable->get_n_devs(handle->m_engine);
	}
	return 1;
}

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, char** buf, uint32_t* len) {
	// engines do not even necessarily have a concept of a buffer
	// that you read events from
	return SCAP_NOT_SUPPORTED;
}

uint64_t scap_max_buf_used(scap_t* handle) {
	if(handle && handle->m_vtable) {
		return handle->m_vtable->get_max_buf_used(handle->m_engine);
	}
	return 0;
}

int32_t scap_next(scap_t* handle, scap_evt** pevent, uint16_t* pdevid, uint32_t* pflags) {
	// Note: devid is like cpuid but not 1:1, e.g. consider CPU1 offline:
	// CPU0 CPU1 CPU2 CPU3
	// DEV0 DEV1 DEV2 DEV3 <- CPU1  online
	// DEV0 XXXX DEV1 DEV2 <- CPU1 offline
	int32_t res = SCAP_FAILURE;
	if(handle && handle->m_vtable) {
		res = handle->m_vtable->next(handle->m_engine, pevent, pdevid, pflags);
	} else {
		res = SCAP_FAILURE;
	}

	if(res == SCAP_SUCCESS) {
		handle->m_evtcnt++;
	}

	return res;
}

//
// Return the number of dropped events for the given handle.
//
int32_t scap_get_stats(scap_t* handle, scap_stats* stats) {
	if(!handle || stats == NULL) {
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
	stats->n_suppressed = 0;
	stats->n_tids_suppressed = 0;

	if(handle->m_vtable) {
		return handle->m_vtable->get_stats(handle->m_engine, stats);
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

//
// Return engine statistics (including counters and `bpftool prog show` like stats)
//
const struct metrics_v2* scap_get_stats_v2(scap_t* handle,
                                           uint32_t flags,
                                           uint32_t* nstats,
                                           int32_t* rc) {
	// If we enable per-cpu counters, we also enable kernel global counters by default.
	if(flags & METRICS_V2_KERNEL_COUNTERS_PER_CPU) {
		flags |= METRICS_V2_KERNEL_COUNTERS;
	}

	if(handle && handle->m_vtable) {
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
int32_t scap_stop_capture(scap_t* handle) {
	if(handle == NULL) {
		return SCAP_SUCCESS;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->stop_capture(handle->m_engine);
	}

	scap_err_opnotsup(handle->m_lasterr);
	ASSERT(false);
	return SCAP_FAILURE;
}

//
// Start capturing the events
//
int32_t scap_start_capture(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->start_capture(handle->m_engine);
	}

	scap_err_opnotsup(handle->m_lasterr);
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_stop_dropping_mode(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, 1, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	switch(sampling_ratio) {
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
		return scap_errprintf(handle->m_lasterr, 0, "invalid sampling ratio size");
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine,
		                                   SCAP_SAMPLING_RATIO,
		                                   sampling_ratio,
		                                   1);
	}

	scap_err_opnotsup(handle->m_lasterr);
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_SNAPLEN, snaplen, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

int64_t scap_get_readfile_offset(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable->savefile_ops) {
		return handle->m_vtable->savefile_ops->get_readfile_offset(handle->m_engine);
	} else {
		return scap_errprintf(handle->m_lasterr,
		                      0,
		                      "scap_get_readfile_offset only works on captures");
	}
}

int32_t scap_set_ppm_sc(scap_t* handle, ppm_sc_code ppm_sc, bool enabled) {
	if(handle == NULL) {
		return SCAP_FAILURE;
	}

	if(ppm_sc >= PPM_SC_MAX) {
		scap_errprintf(handle->m_lasterr, 0, "%s(%d) wrong param", __FUNCTION__, ppm_sc);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	uint32_t op = enabled ? SCAP_PPM_SC_MASK_SET : SCAP_PPM_SC_MASK_UNSET;

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_PPM_SC_MASK, op, ppm_sc);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

int32_t scap_set_dropfailed(scap_t* handle, bool enabled) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle && handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_DROP_FAILED, enabled, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

int32_t scap_enable_dynamic_snaplen(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 1, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 0, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

const char* scap_get_host_root() {
	char* p = getenv(SCAP_HOST_ROOT_ENV_VAR_NAME);
	static char env_str[SCAP_MAX_PATH_SIZE + 1];
	static bool inited = false;
	if(!inited) {
		strlcpy(env_str, p ? p : "", sizeof(env_str));
		inited = true;
	}

	return env_str;
}

uint64_t scap_ftell(scap_t* handle) {
	if(handle && handle->m_vtable->savefile_ops) {
		return handle->m_vtable->savefile_ops->ftell_capture(handle->m_engine);
	} else {
		return 0;
	}
}

void scap_fseek(scap_t* handle, uint64_t off) {
	if(handle && handle->m_vtable->savefile_ops) {
		handle->m_vtable->savefile_ops->fseek_capture(handle->m_engine, off);
	}
}

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->get_n_tracepoint_hit(handle->m_engine, ret);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

bool scap_check_current_engine(scap_t* handle, const char* engine_name) {
	if(engine_name && handle && handle->m_vtable) {
		return strcmp(handle->m_vtable->name, engine_name) == 0;
	}
	return false;
}

int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine,
		                                   SCAP_FULLCAPTURE_PORT_RANGE,
		                                   range_start,
		                                   range_end);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

int32_t scap_set_statsd_port(scap_t* const handle, const uint16_t port) {
	if(!handle) {
		return SCAP_FAILURE;
	}

	if(handle->m_vtable) {
		return handle->m_vtable->configure(handle->m_engine, SCAP_STATSD_PORT, port, 0);
	}

	scap_err_opnotsup(handle->m_lasterr);
	return SCAP_FAILURE;
}

uint64_t scap_get_driver_api_version(scap_t* handle) {
	if(handle && handle->m_vtable && handle->m_vtable->get_api_version) {
		return handle->m_vtable->get_api_version(handle->m_engine);
	}

	return 0;
}

uint64_t scap_get_driver_schema_version(scap_t* handle) {
	if(handle && handle->m_vtable && handle->m_vtable->get_schema_version) {
		return handle->m_vtable->get_schema_version(handle->m_engine);
	}

	return 0;
}
