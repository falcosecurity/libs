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

#include "../../../common/strlcpy.h"

#ifdef __cplusplus
extern "C"{
#endif

static SCAP_HANDLE_T *gvisor_alloc_handle(scap_t* main_handle, char *lasterr_ptr)
{
	return new scap_gvisor::engine(lasterr_ptr);
}

static int32_t gvisor_init(scap_t* main_handle, scap_open_args* open_args)
{
	scap_gvisor::engine *gv = main_handle->m_engine.m_handle;
	return gv->init(open_args->gvisor_socket);
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

static bool gvisor_match(scap_open_args* open_args)
{
	return open_args->gvisor_socket != NULL;
}

static int32_t gvisor_configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	return SCAP_SUCCESS;
}

static int32_t gvisor_get_stats(struct scap_engine_handle engine, scap_stats* stats)
{
	return SCAP_SUCCESS;
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

#ifdef __cplusplus
}
#endif

extern const struct scap_vtable scap_gvisor_engine = {
	.name = "gvisor",
	.mode = SCAP_MODE_LIVE,

	.match = gvisor_match,
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
};
