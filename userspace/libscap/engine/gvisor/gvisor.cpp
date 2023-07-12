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
#include "gvisor_platform.h"
#include "scap-int.h"
#include "scap_proc_util.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <stdint.h>
#include <utility>

#include "strerror.h"
#include "strl.h"

#ifdef __cplusplus
extern "C"{
#endif

static int32_t scap_gvisor_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	auto gvisor_platform = reinterpret_cast<struct scap_gvisor_platform*>(platform);
	auto params = reinterpret_cast<scap_gvisor_engine_params *>(oargs->engine_params);

	gvisor_platform->m_lasterr = lasterr;
	gvisor_platform->m_platform = std::make_unique<scap_gvisor::platform>(gvisor_platform->m_lasterr,
									      params->gvisor_root_path);
	return SCAP_SUCCESS;
}

static int32_t get_fdinfos(void* ctx, const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	auto gv = reinterpret_cast<scap_gvisor::platform*>(ctx);

	return gv->get_fdinfos(tinfo, n, fdinfos);
}

static int32_t scap_gvisor_refresh_proc_table(struct scap_platform* platform, struct scap_proclist* proclist)
{
	auto gvisor_platform = reinterpret_cast<struct scap_gvisor_platform*>(platform);
	scap_gvisor::platform *gv = gvisor_platform->m_platform.get();

	if(gv == nullptr)
	{
		return scap_errprintf(gvisor_platform->m_lasterr, 0, "Platform not initialized yet");
	}

	uint64_t n;
	const scap_threadinfo* tinfos;
	int ret = gv->get_threadinfos(&n, &tinfos);

	if(ret != SCAP_SUCCESS)
	{
		return ret;
	}

	return scap_proc_scan_vtable(gvisor_platform->m_lasterr, proclist, n, tinfos, gv, get_fdinfos);
}

static int32_t scap_gvisor_close_platform(struct scap_platform* platform)
{
	return SCAP_SUCCESS;
}

static void scap_gvisor_free_platform(struct scap_platform* platform)
{
	auto gvisor_platform = reinterpret_cast<struct scap_gvisor_platform*>(platform);
	delete gvisor_platform;
}

static const struct scap_platform_vtable scap_gvisor_platform_vtable = {
	.init_platform = scap_gvisor_init_platform,
	.refresh_addr_list = NULL,
	.get_device_by_mount_id = NULL,
	.get_proc = NULL,
	.refresh_proc_table = scap_gvisor_refresh_proc_table,
	.close_platform = scap_gvisor_close_platform,
	.free_platform = scap_gvisor_free_platform,
};

struct scap_platform* scap_gvisor_alloc_platform()
{
	auto platform = new scap_gvisor_platform;
	platform->m_generic.m_vtable = &scap_gvisor_platform_vtable;

	return &platform->m_generic;
}

static SCAP_HANDLE_T *gvisor_alloc_handle(scap_t* main_handle, char *lasterr_ptr)
{
	return new scap_gvisor::engine(lasterr_ptr);
}

static int32_t gvisor_init(scap_t* main_handle, scap_open_args* oargs)
{
	scap_gvisor::engine *gv = main_handle->m_engine.m_handle;
	struct scap_gvisor_engine_params *params = (struct scap_gvisor_engine_params *)oargs->engine_params;
	return gv->init(params->gvisor_config_path, params->gvisor_root_path, params->no_events);
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

static const struct scap_stats_v2* gvisor_get_stats_v2(struct scap_engine_handle engine, uint32_t flags, uint32_t* nstats, int32_t* rc)
{
	return engine.m_handle->get_stats_v2(flags, nstats, rc);
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
	.get_stats_v2 = gvisor_get_stats_v2,
	.get_n_tracepoint_hit = gvisor_get_n_tracepoint_hit,
	.get_n_devs = gvisor_get_n_devs,
	.get_max_buf_used = gvisor_get_max_buf_used,
	.get_threadlist = gvisor_get_threadlist,
	.getpid_global = gvisor_getpid_global,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};
