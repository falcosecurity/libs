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

namespace scap_gvisor {
	class engine;
}

#define SCAP_HANDLE_T scap_gvisor::engine

#include "scap.h"
#include "gvisor.h"
#include "scap-int.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include "strlcpy.h"

#ifdef __cplusplus
extern "C"{
#endif

static SCAP_HANDLE_T *gvisor_alloc_handle(scap_t* main_handle, char *lasterr_ptr)
{
	return new scap_gvisor::engine(lasterr_ptr);
}

static int32_t gvisor_init(scap_t* main_handle, scap_open_args* oargs)
{
	scap_gvisor::engine *gv = main_handle->m_engine.m_handle;
	struct scap_gvisor_engine_params *params = (struct scap_gvisor_engine_params *)oargs->engine_params;
	return gv->init(params->gvisor_config_path, params->gvisor_root_path);
}

static void gvisor_free_handle(struct scap_engine_handle engine)
{
	delete engine.m_handle;
}

static int32_t gvisor_start_capture(struct scap_engine_handle engine)
{
	return engine.m_handle->start_capture();
}

static int32_t gvisor_close(struct scap_engine_handle engine)
{
	return engine.m_handle->close();
}

static int32_t gvisor_stop_capture(struct scap_engine_handle engine)
{
	return engine.m_handle->stop_capture();
}

static int32_t gvisor_next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid)
{
	return engine.m_handle->next(pevent, pcpuid);
}

static int32_t gvisor_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	return SCAP_SUCCESS;
}

static int32_t gvisor_get_stats(struct scap_engine_handle engine, scap_stats* stats)
{
	return engine.m_handle->get_stats(stats);
}

static int32_t gvisor_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	return SCAP_NOT_SUPPORTED;
}

static uint32_t gvisor_get_n_devs(struct scap_engine_handle engine)
{
	return 0;
}

static uint64_t gvisor_get_max_buf_used(struct scap_engine_handle engine)
{
	return 0;
}

static int32_t gvisor_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr)
{
	if(*procinfo_p == NULL)
	{
		if(scap_alloc_proclist_info(procinfo_p, SCAP_DRIVER_PROCINFO_INITIAL_SIZE, lasterr) == false)
		{
			return SCAP_FAILURE;
		}
	}

	// placeholder
	(*procinfo_p)->n_entries = 0;

	return SCAP_SUCCESS;
}

static int32_t gvisor_get_threadinfos(struct scap_engine_handle engine, uint64_t *n, const scap_threadinfo **tinfos)
{
	return engine.m_handle->get_threadinfos(n, tinfos);
}

static int32_t gvisor_get_fdinfos(struct scap_engine_handle engine, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	return engine.m_handle->get_fdinfos(tinfo, n, fdinfos);
}

static int32_t gvisor_get_vxid(struct scap_engine_handle engine, uint64_t xid, int64_t *vxid)
{
	*vxid = engine.m_handle->get_vxid(xid);
	return SCAP_SUCCESS;
}

static int32_t gvisor_getpid_global(struct scap_engine_handle engine, int64_t* pid, char* error)
{
	// there is no current PID in gvisor since we run outside a sandbox
	*pid = 1000;
	return SCAP_SUCCESS;
}

#ifdef __cplusplus
}
#endif

extern const struct scap_vtable scap_gvisor_engine = {
	.name = GVISOR_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = gvisor_alloc_handle,
	.init = gvisor_init,
	.free_handle = gvisor_free_handle,
	.close = gvisor_close,
	.next = gvisor_next,
	.start_capture = gvisor_start_capture,
	.stop_capture = gvisor_stop_capture,
	.configure = gvisor_configure,
	.get_stats = gvisor_get_stats,
	.get_n_tracepoint_hit = gvisor_get_n_tracepoint_hit,
	.get_n_devs = gvisor_get_n_devs,
	.get_max_buf_used = gvisor_get_max_buf_used,
	.get_threadlist = gvisor_get_threadlist,
	.get_threadinfos = gvisor_get_threadinfos,
	.get_fdinfos = gvisor_get_fdinfos,
	.get_vpid = gvisor_get_vxid,
	.get_vtid = gvisor_get_vxid,
	.getpid_global = gvisor_getpid_global,
};
