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
#include <libpman.h>

#define SCAP_HANDLE_T struct modern_bpf_engine
#include "scap_modern_bpf.h"
#include "scap.h"
#include "scap-int.h"
#include "scap_procs.h"
#include "noop.h"
#include "strlcpy.h"
#include <sys/utsname.h>
#include "ringbuffer/ringbuffer.h"

#define REQUIRED_MAJOR 5
#define REQUIRED_MINOR 8
#define REQUIRED_PATCH 0

/*=============================== UTILS ===============================*/

/// TODO: in the next future, from `oargs` we should directly receive a table of internal syscall code, not ppm_sc.
static int32_t populate_64bit_interesting_syscalls_table()
{
	int ret = SCAP_SUCCESS;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		pman_mark_single_ppm_sc(ppm_sc, false);
	}
	return ret;
}

static int32_t check_minimum_kernel_version(char* last_err)
{
	uint32_t major = 0;
	uint32_t minor = 0;
	uint32_t patch = 0;

	struct utsname info;
	if(uname(&info) != 0)
	{
		if(last_err != NULL)
		{
			snprintf(last_err, SCAP_LASTERR_SIZE, "unable to get the kernel version with uname: %s", strerror(errno));
		}
		return SCAP_FAILURE;
	}

	if(sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3)
	{
		if(last_err != NULL)
		{
			snprintf(last_err, SCAP_LASTERR_SIZE, "unable to parse info.release '%s'. %s", info.release, strerror(errno));
		}
		return SCAP_FAILURE;
	}

	if(major > REQUIRED_MAJOR)
	{
		return SCAP_SUCCESS;
	}

	if(major == REQUIRED_MAJOR && minor > REQUIRED_MINOR)
	{
		return SCAP_SUCCESS;
	}

	if(major == REQUIRED_MAJOR && minor == REQUIRED_MINOR && patch >= REQUIRED_PATCH)
	{
		return SCAP_SUCCESS;
	}
	snprintf(last_err, SCAP_LASTERR_SIZE, "Actual kernel version is: '%d.%d.%d' while the minimum required is: '%d.%d.%d'\n", major, minor, patch, REQUIRED_MAJOR, REQUIRED_MINOR, REQUIRED_PATCH);
	return SCAP_FAILURE;
}

/*=============================== UTILS ===============================*/

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

static int32_t scap_modern_bpf_handle_ppm_sc_mask(struct scap_engine_handle engine, uint32_t op, uint32_t ppm_sc)
{
	struct modern_bpf_engine* handle = engine.m_handle;
	int32_t ret = SCAP_SUCCESS;

	// Load initial tp_set
	bool curr_tp_set[TP_VAL_MAX];
	tp_set_from_sc_set(handle->curr_sc_set.ppm_sc, curr_tp_set);
	switch(op)
	{
	case SCAP_PPM_SC_MASK_SET:
		if(handle->curr_sc_set.ppm_sc[ppm_sc])
		{
			// nothing to do
			return ret;
		}
		handle->curr_sc_set.ppm_sc[ppm_sc] = true;
		break;
	case SCAP_PPM_SC_MASK_UNSET:
		if(!handle->curr_sc_set.ppm_sc[ppm_sc])
		{
			// nothing to do
			return ret;
		}
		handle->curr_sc_set.ppm_sc[ppm_sc] = false;
		break;

	default:
		return SCAP_FAILURE;
	}


	// Only if the sc code maps a syscall
	if(ppm_sc_is_tp(ppm_sc))
	{
		pman_mark_single_ppm_sc(ppm_sc, op == SCAP_PPM_SC_MASK_SET);
	}

	// Load final tp_set
	bool final_tp_set[TP_VAL_MAX];
	tp_set_from_sc_set(handle->curr_sc_set.ppm_sc, final_tp_set);
	for (int tp = 0; tp < TP_VAL_MAX && ret == SCAP_SUCCESS; tp++)
	{
		if (curr_tp_set[tp] != final_tp_set[tp])
		{
			ret = pman_update_single_program(tp, final_tp_set[tp]);
		}
	}
	return ret;
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
	case SCAP_PPM_SC_MASK:
		return scap_modern_bpf_handle_ppm_sc_mask(engine, arg1, arg2);
	case SCAP_DYNAMIC_SNAPLEN:
		/* Not supported */
		return SCAP_SUCCESS;
	case SCAP_FULLCAPTURE_PORT_RANGE:
		/* Not supported */
		return SCAP_SUCCESS;
	case SCAP_STATSD_PORT:
		/* Not supported */
		return SCAP_SUCCESS;
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
	return pman_enable_capture(handle->curr_sc_set.ppm_sc);
}

int32_t scap_modern_bpf__stop_capture(struct scap_engine_handle engine)
{
	return pman_disable_capture();
}

int32_t scap_modern_bpf__init(scap_t* handle, scap_open_args* oargs)
{
	int ret = 0;
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_modern_bpf_engine_params* params = oargs->engine_params;
	bool libbpf_verbosity = false;

	pman_clear_state();

	/* Some checks to test if we can use the modern BPF probe
	 * - check the ring-buffer dimension in bytes.
	 * - check the minimum required kernel version.
	 *
	 * Please note the presence of BTF is directly checked by `libbpf` see `bpf_object__load_vmlinux_btf` method.
	 */
	if(check_buffer_bytes_dim(handle->m_lasterr, params->buffer_bytes_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(check_minimum_kernel_version(handle->m_lasterr) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* Initialize the libpman internal state.
	 * Validation of `cpus_for_each_buffer` is made inside libpman
	 * since this is the unique place where we have the number of CPUs
	 */
	if(pman_init_state(libbpf_verbosity, params->buffer_bytes_dim, params->cpus_for_each_buffer, params->allocate_online_only))
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
	ret = ret ?: populate_64bit_interesting_syscalls_table(oargs->ppm_sc_of_interest.ppm_sc);
	// Do not attach tracepoints at this stage.
	if(ret != SCAP_SUCCESS)
	{
		return ret;
	}

	/* Store interesting sc codes */
	memcpy(&engine.m_handle->curr_sc_set, &oargs->ppm_sc_of_interest, sizeof(interesting_ppm_sc_set));

	/* Set the boot time */
	uint64_t boot_time = 0;
	if(scap_get_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS)
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
