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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <libpman.h>

#include "scap_modern_bpf.h"
#include "scap.h"
#include "scap-int.h"
#include "scap_procs.h"
#include "noop.h"
#include "../common/strlcpy.h"
#include "ringbuffer/ringbuffer.h"

/*=============================== UTILS ===============================*/

static int32_t update_single_tp_of_interest(int tp, bool interesting)
{
	int ret = SCAP_SUCCESS;
	switch(tp)
	{
	case SYS_ENTER:
		if (interesting)
		{
			ret = pman_attach_syscall_enter_dispatcher();
		}
		else
		{
			ret = pman_detach_syscall_enter_dispatcher();
		}
		break;

	case SYS_EXIT:
		if (interesting)
		{
			ret = pman_attach_syscall_exit_dispatcher();
		}
		else
		{
			ret = pman_detach_syscall_exit_dispatcher();
		}
		break;
	case SCHED_PROC_EXIT:
		if (interesting)
		{
			ret = pman_attach_sched_proc_exit();
		}
		else
		{
			ret = pman_detach_sched_proc_exit();
		}
		break;

	case SCHED_SWITCH:
		if (interesting)
		{
			ret = pman_attach_sched_switch();
		}
		else
		{
			ret = pman_detach_sched_switch();
		}
		break;

#ifdef CAPTURE_SCHED_PROC_EXEC
	case SCHED_PROC_EXEC:
		if (interesting)
		{
			ret = pman_attach_sched_proc_exec();
		}
		else
		{
			ret = pman_detach_sched_proc_exec();
		}
		break;
#endif

#ifdef CAPTURE_SCHED_PROC_FORK
	case SCHED_PROC_FORK:
		if (interesting)
		{
			ret = pman_attach_sched_proc_fork();
		}
		else
		{
			ret = pman_detach_sched_proc_fork();
		}
		break;
#endif

	default:
		/* Do nothing right now. */
		break;
	}
	return ret;
}

static int32_t attach_interesting_tracepoints(bool* tp_array)
{
	int ret = SCAP_SUCCESS;
	if(tp_array == NULL)
	{
		return SCAP_FAILURE;
	}

	for(int tp = 0; tp < TP_VAL_MAX && ret == SCAP_SUCCESS; tp++)
	{
		/* If the tracepoint is not interesting, continue */
		if(!tp_array[tp])
		{
			continue;
		}
		ret = update_single_tp_of_interest(tp, true);
	}
	return ret;
}

static void update_single_64bit_syscall_of_interest(int ppm_sc, bool interesting)
{
	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if (g_syscall_table[syscall_nr].ppm_sc == ppm_sc)
		{
			pman_mark_single_64bit_syscall(syscall_nr, interesting);
		}
	}
}

/// TODO: from `oargs` we should directly receive a table of internal syscall code, not ppm_sc.
static int32_t populate_64bit_interesting_syscalls_table(bool* ppm_sc_array)
{
	int ret = SCAP_SUCCESS;
	if(ppm_sc_array == NULL)
	{
		return SCAP_FAILURE;
	}

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		update_single_64bit_syscall_of_interest(ppm_sc, ppm_sc_array[ppm_sc]);
	}
	return ret;
}

/*=============================== UTILS ===============================*/

/* Right now this is not used */
bool scap_modern_bpf__match(scap_open_args* oargs)
{
	return strcmp(oargs->engine_name, MODERN_BPF_ENGINE) == 0;
}

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

static int32_t scap_modern_bpf__next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	pman_consume_first_from_buffers((void**)pevent, pcpuid);
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

static int32_t scap_modern_bpf__configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		/* Not supported */
		return SCAP_SUCCESS;
	case SCAP_TRACERS_CAPTURE:
		/* Not supported */
		return SCAP_SUCCESS;
	case SCAP_SNAPLEN:
		pman_set_snaplen(arg1);
	case SCAP_EVENTMASK:
		/* We use this setting just to modify the interesting syscalls. */
		if(arg1 == SCAP_EVENTMASK_SET || arg1 == SCAP_EVENTMASK_UNSET)
		{
			update_single_64bit_syscall_of_interest(arg2, arg1 == SCAP_EVENTMASK_SET);
		}
		else if(arg1 == SCAP_EVENTMASK_ZERO)
		{
			pman_clean_all_64bit_interesting_syscalls();
		}
		return SCAP_SUCCESS;
	case SCAP_TPMASK:
		return update_single_tp_of_interest(arg2, arg1 == SCAP_TPMASK_SET);
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
	pman_enable_capture();
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__stop_capture(struct scap_engine_handle engine)
{
	pman_disable_capture();
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__init(scap_t* handle, scap_open_args* oargs)
{
	int ret = 0;
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_modern_bpf_engine_params* params = oargs->engine_params;
	bool libbpf_verbosity = false;

	if(check_buffer_bytes_dim(handle->m_lasterr, params->buffer_bytes_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* Initialize the libpman internal state */
	if(pman_init_state(libbpf_verbosity, params->buffer_bytes_dim))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unable to configure the libpman state.");
		return SCAP_FAILURE;
	}

	/* Set an initial sleep time in case of timeouts. */
	engine.m_handle->m_retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;

	/* Return the number of system available CPUs, not online CPUs. */
	engine.m_handle->m_num_cpus = pman_get_cpus_number();

	/* Load and attach */
	ret = pman_open_probe();
	ret = ret ?: pman_prepare_ringbuf_array_before_loading();
	ret = ret ?: pman_prepare_maps_before_loading();
	ret = ret ?: pman_load_probe();
	ret = ret ?: pman_finalize_maps_after_loading();
	ret = ret ?: pman_finalize_ringbuf_array_after_loading();
	ret = ret ?: populate_64bit_interesting_syscalls_table(oargs->ppm_sc_of_interest.ppm_sc);
	ret = ret ?: attach_interesting_tracepoints(oargs->tp_of_interest.tp);
	if(ret != SCAP_SUCCESS)
	{
		return ret;
	}

	/* Set the boot time */
	uint64_t boot_time = 0;
	if(scap_get_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}
	pman_set_boot_time(boot_time);

	handle->m_api_version = pman_get_probe_api_ver();
	handle->m_schema_version = pman_get_probe_schema_ver();

	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__close(struct scap_engine_handle engine)
{
	pman_close_probe();
	return SCAP_SUCCESS;
}

static uint32_t scap_modern_bpf__get_n_devs(struct scap_engine_handle engine)
{
	return engine.m_handle->m_num_cpus;
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

struct scap_vtable scap_modern_bpf_engine = {
	.name = MODERN_BPF_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.match = scap_modern_bpf__match,
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
};
