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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define HANDLE(engine) ((struct modern_bpf_engine*)(engine.m_handle))

#include <libscap/engine/modern_bpf/scap_modern_bpf.h>
#include <libpman.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_procs.h>
#include <libscap/engine/noop/noop.h>
#include <libscap/strl.h>
#include <sys/utsname.h>
#include <libscap/ringbuffer/ringbuffer.h>
#include <libscap/scap_engine_util.h>
#include <libscap/strerror.h>
#include <driver/syscall_compat.h>

static void* scap_modern_bpf__alloc_engine(scap_t* main_handle, char* lasterr_ptr) {
	struct modern_bpf_engine* engine = calloc(1, sizeof(struct modern_bpf_engine));
	if(engine) {
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static void scap_modern_bpf__free_engine(struct scap_engine_handle engine) {
	free(engine.m_handle);
}

/* The third parameter is not the CPU number from which we extract the event but the ring buffer
 * number. For the old BPF probe and the kernel module the number of CPUs is equal to the number of
 * buffers since we always use a per-CPU approach.
 */
static int32_t scap_modern_bpf__next(struct scap_engine_handle engine,
                                     scap_evt** pevent,
                                     uint16_t* buffer_id,
                                     uint32_t* pflags) {
	pman_consume_first_event((void**)pevent, (int16_t*)buffer_id);

	if((*pevent) == NULL) {
		/* The first time we sleep 500 us, if we have consecutive timeouts we can reach also 30 ms.
		 */
		usleep(HANDLE(engine)->m_retry_us);
		HANDLE(engine)->m_retry_us =
		        MIN(HANDLE(engine)->m_retry_us * 2, BUFFER_EMPTY_WAIT_TIME_US_MAX);
		return SCAP_TIMEOUT;
	} else {
		HANDLE(engine)->m_retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	}
	*pflags = 0;
	return SCAP_SUCCESS;
}

// Use the 32 bits of the buffer handle as follows:
// - the lower 16 bits encode the ring buffer handle
// - the upper 16 bits encode the number of microseconds to wait if the ring buffer is empty
#define BUFFER(x) ((pman_ringbuf_t)(x))
#define RETRY_US(x) ((uint16_t)((x) >> 16))
#define SET_BUFFER(x, b) (x = ((x & 0xFFFF0000) | (b & 0x0000FFFF)))
#define SET_RETRY_US(x, r) (x = ((x & 0x0000FFFF) | ((r & 0x0000FFFF) << 16)))

static int32_t scap_modern_bpf__next_from_buffer(struct scap_engine_handle engine,
                                                 scap_buffer_t buffer_h,
                                                 scap_evt** pevent,
                                                 uint32_t* pflags) {
	pman_consume_first_event_from_ringbuf(BUFFER(buffer_h), (void**)pevent);

	if(*pevent == NULL) {
		/* The first time we sleep 500 us, if we have consecutive timeouts we can reach also 30 ms.
		 */
		uint16_t const retry_us = RETRY_US(buffer_h);
		usleep(retry_us);
		SET_RETRY_US(buffer_h, MIN(retry_us * 2, BUFFER_EMPTY_WAIT_TIME_US_MAX));
		return SCAP_TIMEOUT;
	}
	SET_RETRY_US(buffer_h, BUFFER_EMPTY_WAIT_TIME_US_START);
	*pflags = 0;
	return SCAP_SUCCESS;
}

static uint16_t scap_modern_bpf__get_n_allocated_buffer_handles(struct scap_engine_handle engine) {
	return pman_get_n_allocated_ringbuf_handles();
}

static scap_buffer_t scap_modern_bpf__reserve_buffer_handle(struct scap_engine_handle engine) {
	pman_ringbuf_t const ringbuf_h = pman_reserve_ringbuf_handle();
	if(ringbuf_h == PMAN_INVALID_RING_BUFFER_HANDLE) {
		return SCAP_INVALID_BUFFER_HANDLE;
	}

	scap_buffer_t buffer_h = 0;
	SET_BUFFER(buffer_h, ringbuf_h);
	SET_RETRY_US(buffer_h, BUFFER_EMPTY_WAIT_TIME_US_START);
	return buffer_h;
}

static int32_t scap_modern_bpf_start_dropping_mode(struct scap_engine_handle engine,
                                                   uint32_t sampling_ratio) {
	pman_set_sampling_ratio(sampling_ratio);
	pman_set_dropping_mode(true);
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_stop_dropping_mode() {
	pman_set_sampling_ratio(1);
	pman_set_dropping_mode(false);
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf_handle_sc(struct scap_engine_handle engine,
                                         uint32_t op,
                                         uint32_t sc) {
	struct modern_bpf_engine* handle = engine.m_handle;
	handle->curr_sc_set.ppm_sc[sc] = op == SCAP_PPM_SC_MASK_SET;
	/* We update the system state only if the capture is started */
	if(handle->capturing) {
		return pman_enforce_sc_set(handle->curr_sc_set.ppm_sc);
	}
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf__configure(struct scap_engine_handle engine,
                                          enum scap_setting setting,
                                          unsigned long arg1,
                                          unsigned long arg2) {
	switch(setting) {
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0) {
			return scap_modern_bpf_stop_dropping_mode();
		} else {
			return scap_modern_bpf_start_dropping_mode(engine, arg1);
		}
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
	default: {
		struct modern_bpf_engine* handle = engine.m_handle;
		return scap_errprintf(handle->m_lasterr,
		                      0,
		                      "Unsupported setting %d (args %lu, %lu)",
		                      setting,
		                      arg1,
		                      arg2);
	}
	}

	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__start_capture(struct scap_engine_handle engine) {
	struct modern_bpf_engine* handle = engine.m_handle;
	/* Here we are covering the case in which some syscalls don't have an associated ppm_sc
	 * and so we cannot set them as (un)interesting. For this reason, we default them to 0.
	 * Please note this is an extra check since our ppm_sc should already cover all possible
	 * syscalls. Ideally we should do this only once, but right now in our code we don't have a
	 * "right" place to do it. We need to move it, if `scap_start_capture` will be called frequently
	 * in our flow, right now in live mode, it should be called only once...
	 */
	for(int i = 0; i < SYSCALL_TABLE_SIZE; i++) {
		pman_mark_single_64bit_syscall(i, false);
	}
	handle->capturing = true;
	return pman_enforce_sc_set(handle->curr_sc_set.ppm_sc);
}

int32_t scap_modern_bpf__stop_capture(struct scap_engine_handle engine) {
	struct modern_bpf_engine* handle = engine.m_handle;
	handle->capturing = false;
	/* NULL is equivalent to an empty array */
	return pman_enforce_sc_set(NULL);
}

static int32_t calibrate_socket_file_ops(struct scap_engine_handle engine) {
	/* Set the scap_tid for the socket calibration.
	 * If we are in a container this is the virtual tid.
	 */
	pid_t scap_tid = syscall(__NR_gettid);
	pman_set_scap_tid(scap_tid);

	/* We just need to enable the socket syscall for the socket calibration */
	HANDLE(engine)->curr_sc_set.ppm_sc[PPM_SC_SOCKET] = 1;
	if(scap_modern_bpf__start_capture(engine) != SCAP_SUCCESS) {
		return scap_errprintf(HANDLE(engine)->m_lasterr,
		                      errno,
		                      "unable to start the capture for the socket calibration");
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1) {
		return scap_errprintf(HANDLE(engine)->m_lasterr,
		                      errno,
		                      "unable to create a socket for the calibration");
	}
	close(fd);

	/* We need to stop the capture */
	if(scap_modern_bpf__stop_capture(engine) != SCAP_SUCCESS) {
		return scap_errprintf(HANDLE(engine)->m_lasterr,
		                      errno,
		                      "unable to stop the capture after the calibration");
	}

	/* We need to read the socket event from the buffer */
	scap_evt* pevent = NULL;
	uint16_t attempts = 0;
	uint16_t buffer_id = 0;
	uint32_t flags = 0;
	int32_t res = 0;
	bool found = false;

	while(attempts <= 1) {
		res = scap_modern_bpf__next(engine, &pevent, &buffer_id, &flags);
		if(res == SCAP_SUCCESS && pevent != NULL) {
			/* This is not a socket event or this is not our socket event */
			if(pevent->type != PPME_SOCKET_SOCKET_X || pevent->tid != scap_tid) {
				continue;
			}

			/* BPF side we send this special event with nparams = 0 */
			if(pevent->nparams == 0) {
				/* We don't want to stop here because we want to clean all the buffers. */
				found = true;
			}
		} else if(res == SCAP_TIMEOUT) {
			/* We need more than one attempt because the first time we just need to read the
			 * producers' positions. */
			attempts++;
		}
	}

	if(!found) {
		return scap_errprintf(
		        HANDLE(engine)->m_lasterr,
		        0,
		        "unable to find the socket event for the calibration in the ringbuffers");
	}
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf__init(scap_t* handle, scap_open_args* oargs) {
	int ret = 0;
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_modern_bpf_engine_params* params = oargs->engine_params;

	pman_clear_state();

	/* Some checks to test if we can use the modern BPF probe
	 * - check the ring-buffer dimension in bytes.
	 * - check the presence of ring buffer and of BTF.
	 */
	if(check_buffer_bytes_dim(handle->m_lasterr, params->buffer_bytes_dim) != SCAP_SUCCESS) {
		return ENOTSUP;
	}

	if(!pman_check_support()) {
		return ENOTSUP;
	}

	/* Initialize the libpman internal state.
	 * Validation of `buffers_num` is made inside libpman
	 * since this is the unique place where we have the number of CPUs
	 */
	if(pman_init_state(oargs->log_fn,
	                   params->buffer_bytes_dim,
	                   params->buffers_num,
	                   params->allocate_online_only)) {
		return scap_errprintf(handle->m_lasterr, 0, "unable to configure the libpman state.");
	}

	/* Set an initial sleep time in case of timeouts. */
	HANDLE(engine)->m_retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;

	/* Load and attach */
	ret = pman_open_probe();
	ret = ret ?: pman_prepare_ringbuf_array_before_loading();
	ret = ret ?: pman_prepare_maps_before_loading();
	ret = ret ?: pman_prepare_progs_before_loading();
	ret = ret ?: pman_load_probe();
	ret = ret ?: pman_finalize_maps_after_loading();
	ret = ret ?: pman_finalize_ringbuf_array_after_loading();
	if(ret != SCAP_SUCCESS) {
		return ret;
	}

	/* Set the boot time */
	uint64_t boot_time = 0;
	if(scap_get_precise_boot_time(handle->m_lasterr, &boot_time) != SCAP_SUCCESS) {
		return SCAP_FAILURE;
	}
	pman_set_boot_time(boot_time);

	/* Calibrate the socket at init time */
	if(calibrate_socket_file_ops(engine) != SCAP_SUCCESS) {
		return SCAP_FAILURE;
	}

	/* Store interesting sc codes */
	memcpy(&HANDLE(engine)->curr_sc_set,
	       &oargs->ppm_sc_of_interest,
	       sizeof(interesting_ppm_sc_set));

	HANDLE(engine)->m_api_version = pman_get_probe_api_ver();
	HANDLE(engine)->m_schema_version = pman_get_probe_schema_ver();

	HANDLE(engine)->m_flags = 0;
	if(scap_get_bpf_stats_enabled()) {
		HANDLE(engine)->m_flags |= ENGINE_FLAG_BPF_STATS_ENABLED;
	}

	return SCAP_SUCCESS;
}

static uint64_t scap_modern_bpf__get_flags(struct scap_engine_handle engine) {
	return HANDLE(engine)->m_flags;
}

int32_t scap_modern_bpf__close(struct scap_engine_handle engine) {
	pman_close_probe();
	return SCAP_SUCCESS;
}

static uint32_t scap_modern_bpf__get_n_devs(struct scap_engine_handle engine) {
	return pman_get_required_buffers();
}

int32_t scap_modern_bpf__get_stats(struct scap_engine_handle engine, scap_stats* stats) {
	if(pman_get_scap_stats(stats)) {
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

const struct metrics_v2* scap_modern_bpf__get_stats_v2(struct scap_engine_handle engine,
                                                       uint32_t flags,
                                                       uint32_t* nstats,
                                                       int32_t* rc) {
	struct modern_bpf_engine* handle = engine.m_handle;
	if(!(handle->m_flags & ENGINE_FLAG_BPF_STATS_ENABLED)) {
		// we can't collect libbpf stats if bpf stats are not enabled
		flags &= ~METRICS_V2_LIBBPF_STATS;
	}
	return pman_get_metrics_v2(flags, nstats, rc);
}

int32_t scap_modern_bpf__get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret) {
	if(pman_get_n_tracepoint_hit(ret)) {
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

uint64_t scap_modern_bpf__get_api_version(struct scap_engine_handle engine) {
	return HANDLE(engine)->m_api_version;
}

uint64_t scap_modern_bpf__get_schema_version(struct scap_engine_handle engine) {
	return HANDLE(engine)->m_schema_version;
}

struct scap_vtable scap_modern_bpf_engine = {
        .name = MODERN_BPF_ENGINE,
        .savefile_ops = NULL,

        .alloc_handle = scap_modern_bpf__alloc_engine,
        .init = scap_modern_bpf__init,
        .get_flags = scap_modern_bpf__get_flags,
        .free_handle = scap_modern_bpf__free_engine,
        .close = scap_modern_bpf__close,
        .next = scap_modern_bpf__next,
        .next_from_buffer = scap_modern_bpf__next_from_buffer,
        .get_n_allocated_buffer_handles = scap_modern_bpf__get_n_allocated_buffer_handles,
        .reserve_buffer_handle = scap_modern_bpf__reserve_buffer_handle,
        .start_capture = scap_modern_bpf__start_capture,
        .stop_capture = scap_modern_bpf__stop_capture,
        .configure = scap_modern_bpf__configure,
        .get_stats = scap_modern_bpf__get_stats,
        .get_stats_v2 = scap_modern_bpf__get_stats_v2,
        .get_n_tracepoint_hit = scap_modern_bpf__get_n_tracepoint_hit,
        .get_n_devs = scap_modern_bpf__get_n_devs,
        .get_max_buf_used = noop_get_max_buf_used,
        .get_api_version = scap_modern_bpf__get_api_version,
        .get_schema_version = scap_modern_bpf__get_schema_version,
};
