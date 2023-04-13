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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define SCAP_HANDLE_T struct modern_bpf_engine
#include "scap_modern_bpf.h"
#include <libpman.h>
#include "scap.h"
#include "scap-int.h"
#include "scap_procs.h"
#include "noop.h"
#include "strlcpy.h"
#include <sys/utsname.h>
#include "ringbuffer/ringbuffer.h"

static struct modern_bpf_engine* scap_modern_bpf__alloc_engine(scap_t* main_handle, char* lasterr_ptr)
{
	struct modern_bpf_engine* engine = calloc(1, sizeof(struct modern_bpf_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static void scap_modern_bpf__free_engine(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

/* The third parameter is not the CPU number from which we extract the event but the ring buffer number.
 * For the old BPF probe and the kernel module the number of CPUs is equal to the number of buffers since we always use a per-CPU approach.
 */
static int32_t scap_modern_bpf__next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* buffer_id)
{
	pman_consume_first_event((void**)pevent, buffer_id);

	if((*pevent) == NULL)
	{
		/* The first time we sleep 500 us, if we have consecutive timeouts we can reach also 30 ms. */
		usleep(engine.m_handle->m_retry_us);
		engine.m_handle->m_retry_us = MIN(engine.m_handle->m_retry_us * 2, BUFFER_EMPTY_WAIT_TIME_US_MAX);
		return SCAP_TIMEOUT;
	}
	else
	{
		engine.m_handle->m_retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio)
{
	pman_set_sampling_ratio(sampling_ratio);
	pman_set_dropping_mode(true);
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_stop_dropping_mode()
{
	pman_set_sampling_ratio(1);
	pman_set_dropping_mode(false);
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf_handle_sc(struct scap_engine_handle engine, uint32_t op, uint32_t sc)
{
	struct modern_bpf_engine* handle = engine.m_handle;
	handle->curr_sc_set.ppm_sc[sc] = op == SCAP_PPM_SC_MASK_SET;
	/* We update the system state only if the capture is started */
	if(handle->capturing)
	{
		return pman_enforce_sc_set(handle->curr_sc_set.ppm_sc);
	}
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf__configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0)
		{
			return scap_modern_bpf_stop_dropping_mode();
		}
		else
		{
			return scap_modern_bpf_start_dropping_mode(engine, arg1);
		}
	case SCAP_TRACERS_CAPTURE:
		/* Not supported */
		return SCAP_SUCCESS;
	case SCAP_SNAPLEN:
		pman_set_snaplen(arg1);
		break;
	case SCAP_PPM_SC_MASK:
		return scap_modern_bpf_handle_sc(engine, arg1, arg2);
	case SCAP_DROP_FAILED:
		pman_set_drop_failed(arg1);
		break;
	case SCAP_DYNAMIC_SNAPLEN:
		pman_set_do_dynamic_snaplen(arg1);
		break;
	case SCAP_FULLCAPTURE_PORT_RANGE:
		pman_set_fullcapture_port_range(arg1, arg2);
		break;
	case SCAP_STATSD_PORT:
		pman_set_statsd_port(arg1);
		break;
	default:
	{
		char msg[SCAP_LASTERR_SIZE];
		snprintf(msg, sizeof(msg), "Unsupported setting %d (args %lu, %lu)", setting, arg1, arg2);
		struct modern_bpf_engine* handle = engine.m_handle;
		strlcpy(handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}
	}

	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__start_capture(struct scap_engine_handle engine)
{
	struct modern_bpf_engine* handle = engine.m_handle;
	handle->capturing = true;
	return pman_enforce_sc_set(handle->curr_sc_set.ppm_sc);
}

int32_t scap_modern_bpf__stop_capture(struct scap_engine_handle engine)
{
	struct modern_bpf_engine* handle = engine.m_handle;
	handle->capturing = false;
	/* NULL is equivalent to an empty array */
	return pman_enforce_sc_set(NULL);
}

int32_t scap_modern_bpf__init(scap_t* handle, scap_open_args* oargs)
{
	int ret = 0;
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_modern_bpf_engine_params* params = oargs->engine_params;

	pman_clear_state();

	/* Some checks to test if we can use the modern BPF probe
	 * - check the ring-buffer dimension in bytes.
	 * - check the presence of ring buffer and of BTF.
	 */
	if(check_buffer_bytes_dim(handle->m_lasterr, params->buffer_bytes_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(!pman_check_support())
	{
		return SCAP_FAILURE;
	}

	/* Initialize the libpman internal state.
	 * Validation of `cpus_for_each_buffer` is made inside libpman
	 * since this is the unique place where we have the number of CPUs
	 */
	if(pman_init_state(params->verbose, params->buffer_bytes_dim, params->cpus_for_each_buffer, params->allocate_online_only))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unable to configure the libpman state.");
		return SCAP_FAILURE;
	}

	/* Set an initial sleep time in case of timeouts. */
	engine.m_handle->m_retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;

	/* Load and attach */
	ret = pman_open_probe();
	ret = ret ?: pman_prepare_ringbuf_array_before_loading();
	ret = ret ?: pman_prepare_maps_before_loading();
	ret = ret ?: pman_load_probe();
	ret = ret ?: pman_finalize_maps_after_loading();
	ret = ret ?: pman_finalize_ringbuf_array_after_loading();
	if(ret != SCAP_SUCCESS)
	{
		return ret;
	}

	/* Here we are covering the case in which some syscalls don't have an associated ppm_sc
	 * and so we cannot set them as (un)interesting. For this reason, we default them to 0.
	 * Please note this is an extra check since our ppm_sc should already cover all possible syscalls.
	 */
	for(int i = 0; i < SYSCALL_TABLE_SIZE; i++)
	{
		pman_mark_single_64bit_syscall(i, false);
	}

	/* Store interesting sc codes */
	memcpy(&engine.m_handle->curr_sc_set, &oargs->ppm_sc_of_interest, sizeof(interesting_ppm_sc_set));

	/* Set the boot time */
	uint64_t boot_time = 0;
	if(scap_get_precise_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}
	pman_set_boot_time(boot_time);

	engine.m_handle->m_api_version = pman_get_probe_api_ver();
	engine.m_handle->m_schema_version = pman_get_probe_schema_ver();

	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__close(struct scap_engine_handle engine)
{
	pman_close_probe();
	return SCAP_SUCCESS;
}

static uint32_t scap_modern_bpf__get_n_devs(struct scap_engine_handle engine)
{
	return pman_get_required_buffers();
}

int32_t scap_modern_bpf__get_stats(struct scap_engine_handle engine, OUT scap_stats* stats)
{
	if(pman_get_scap_stats((void*)stats))
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

size_t scap_modern_bpf__get_stats_size_hint()
{
	return pman_get_stats_size_hint();
}

int32_t scap_modern_bpf__get_stats_v2(struct scap_engine_handle engine, size_t buf_size, OUT scap_stats_v2* stats)
{
	if(pman_get_scap_stats_v2(buf_size, (void*)stats))
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__get_n_tracepoint_hit(struct scap_engine_handle engine, OUT long* ret)
{
	if(pman_get_n_tracepoint_hit(ret))
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

uint64_t scap_modern_bpf__get_api_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_api_version;
}

uint64_t scap_modern_bpf__get_schema_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_schema_version;
}

struct scap_vtable scap_modern_bpf_engine = {
	.name = MODERN_BPF_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = scap_modern_bpf__alloc_engine,
	.init = scap_modern_bpf__init,
	.free_handle = scap_modern_bpf__free_engine,
	.close = scap_modern_bpf__close,
	.next = scap_modern_bpf__next,
	.start_capture = scap_modern_bpf__start_capture,
	.stop_capture = scap_modern_bpf__stop_capture,
	.configure = scap_modern_bpf__configure,
	.get_stats = scap_modern_bpf__get_stats,
	.get_stats_size_hint = scap_modern_bpf__get_stats_size_hint,
	.get_stats_v2 = scap_modern_bpf__get_stats_v2,
	.get_n_tracepoint_hit = scap_modern_bpf__get_n_tracepoint_hit,
	.get_n_devs = scap_modern_bpf__get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_threadlist = scap_procfs_get_threadlist,
	.get_vpid = noop_get_vxid,
	.get_vtid = noop_get_vxid,
	.getpid_global = scap_os_getpid_global,
	.get_api_version = scap_modern_bpf__get_api_version,
	.get_schema_version = scap_modern_bpf__get_schema_version,
};
