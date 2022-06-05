#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <libpman.h>

#include "modern_bpf.h"
#include "scap.h"
#include "scap-int.h"
#include "scap_procs.h"

/// TODO: Right now if we build the modern probe and there is a path in `bpf_probe`
// we match the modern probe.
bool scap_modern_bpf_match(scap_open_args* open_args)
{
	return open_args->bpf_probe && !open_args->udig;
}

static struct modern_bpf_engine* scap_modern_bpf_alloc_engine(scap_t* main_handle, char* lasterr_ptr)
{
	struct modern_bpf_engine* engine = calloc(1, sizeof(struct modern_bpf_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static void scap_modern_bpf_free_engine(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

static int32_t scap_modern_bpf_next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	if(libpman__consume_one_from_buffers((void**)pevent, pcpuid))
	{
		return SCAP_TIMEOUT;
	}
	return SCAP_SUCCESS;
}

static int32_t scap_modern_bpf_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	/* Right now this function is not supported in the new probe.
	 * We have to understand what we want to maintain.
	 */
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_start_capture(struct scap_engine_handle engine)
{
	libpman__enable_capture();
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_stop_capture(struct scap_engine_handle engine)
{
	libpman__disable_capture();
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_init(scap_t* handle, scap_open_args* open_args)
{
	int ret = 0;
	struct scap_engine_handle engine = handle->m_engine;
	/// TODO: probably it will become a parameter inside the open_args struct.
	bool libbpf_verbosity = false;

	/* Configure libbpf library used under the hood. */
	if(libpman__set_libbpf_configuration(libbpf_verbosity))
	{
		snprintf(handle->m_engine.m_handle->m_lasterr, SCAP_LASTERR_SIZE, "Unable to get configure libbpf.");
		return SCAP_FAILURE;
	}

	/* Return the number of system available CPUs, not online CPUs. */
	engine.m_handle->m_num_cpus = libpman__get_cpus_number();

	/* Load and attach */
	ret = libpman__open_probe();
	ret = ret ?: libpman__prepare_ringbuf_array_before_loading();
	ret = ret ?: libpman__prepare_maps_before_loading();
	ret = ret ?: libpman__load_probe();
	ret = ret ?: libpman__finalize_maps_after_loading();
	ret = ret ?: libpman__finalize_ringbuf_array_after_loading();
	ret = ret ?: libpman__attach_syscall_enter_dispatcher();
	ret = ret ?: libpman__attach_syscall_exit_dispatcher();
	if(ret != SCAP_SUCCESS)
	{
		return ret;
	}

	handle->m_api_version = libpman__get_probe_api_ver();
	handle->m_schema_version = libpman__get_probe_schema_ver();

	/* Here we miss the simple consumer logic. Right now
	 * all syscalls are interesting. 
	 */

	/* Here we miss the check on API compatibility */

	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_close(struct scap_engine_handle engine)
{
	libpman__detach_all_programs();
	libpman__close_probe();
	return SCAP_SUCCESS;
}

/* Should not be called in the new probe. */
static uint32_t scap_modern_bpf_get_n_devs(struct scap_engine_handle engine)
{
	return 0;
}

/* Should not be called in the new probe. */
uint64_t scap_modern_bpf_max_buf_used(struct scap_engine_handle engine)
{
	return 0;
}

int32_t scap_modern_bpf_get_stats(struct scap_engine_handle engine, OUT scap_stats* stats)
{
	if(libpman__get_scap_stats((void*)stats))
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

int32_t scap_modern_bpf_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	if(libpman__get_n_tracepoint_hit(ret))
	{
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}

struct scap_vtable scap_modern_bpf_vtable = {
	.name = "modern_bpf",
	.mode = SCAP_MODE_LIVE,

	.match = scap_modern_bpf_match,
	.alloc_handle = scap_modern_bpf_alloc_engine,
	.init = scap_modern_bpf_init,
	.free_handle = scap_modern_bpf_free_engine,
	.close = scap_modern_bpf_close,
	.next = scap_modern_bpf_next,
	.start_capture = scap_modern_bpf_start_capture,
	.stop_capture = scap_modern_bpf_stop_capture,
	.configure = scap_modern_bpf_configure,
	.get_stats = scap_modern_bpf_get_stats,
	.get_n_tracepoint_hit = scap_modern_bpf_get_n_tracepoint_hit,
	.get_n_devs = scap_modern_bpf_get_n_devs,
	.get_max_buf_used = scap_modern_bpf_max_buf_used,
};
