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

#include <stdlib.h>
#include <stdio.h>

#include "source_plugin.h"
#include "noop.h"

#include "scap.h"
#include "scap-int.h"
#include "../common/strlcpy.h"
#include "gettimeofday.h"

static int32_t plugin_rc_to_scap_rc(ss_plugin_rc plugin_rc)
{
	switch(plugin_rc)
	{
	case SS_PLUGIN_SUCCESS:
		return SCAP_SUCCESS;
		break;
	case SS_PLUGIN_FAILURE:
		return SCAP_FAILURE;
		break;
	case SS_PLUGIN_TIMEOUT:
		return SCAP_TIMEOUT;
		break;
	case SS_PLUGIN_EOF:
		return SCAP_EOF;
		break;
	case SS_PLUGIN_NOT_SUPPORTED:
		return SCAP_NOT_SUPPORTED;
		break;
	default:
		ASSERT(false);
		return SCAP_FAILURE;
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

static struct source_plugin_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct source_plugin_engine *engine = calloc(1, sizeof(struct source_plugin_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static int32_t init(scap_t* main_handle, scap_open_args* open_args)
{
	int32_t rc;
	struct source_plugin_engine *handle = main_handle->m_engine.m_handle;
	handle->m_input_plugin = open_args->input_plugin;

	// Set the rc to SCAP_FAILURE now, so in the unlikely event
	// that a plugin doesn't not actually set a rc, that it gets
	// treated as a failure.
	ss_plugin_rc plugin_rc = SCAP_FAILURE;

	handle->m_input_plugin->handle = handle->m_input_plugin->open(handle->m_input_plugin->state,
	                                                              open_args->input_plugin_params,
	                                                              &plugin_rc);

	rc = plugin_rc_to_scap_rc(plugin_rc);
	handle->m_input_plugin_batch_nevts = 0;
	handle->m_input_plugin_batch_evts = NULL;
	handle->m_input_plugin_batch_idx = 0;
	handle->m_input_plugin_last_batch_res = SCAP_SUCCESS;

	if(rc != SCAP_SUCCESS)
	{
		const char *errstr = handle->m_input_plugin->get_last_error(handle->m_input_plugin->state);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s", errstr);
	}

	return rc;
}

static int close_engine(struct scap_engine_handle engine)
{
	struct source_plugin_engine *handle = engine.m_handle;

	handle->m_input_plugin->close(handle->m_input_plugin->state, handle->m_input_plugin->handle);
	handle->m_input_plugin->handle = NULL;
	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	struct source_plugin_engine *handle = engine.m_handle;
	char *lasterr = engine.m_handle->m_lasterr;
	ss_plugin_event *plugin_evt;
	int32_t res = SCAP_FAILURE;

	if(handle->m_input_plugin_batch_idx >= handle->m_input_plugin_batch_nevts)
	{
		if(handle->m_input_plugin_last_batch_res != SS_PLUGIN_SUCCESS)
		{
			if(handle->m_input_plugin_last_batch_res != SCAP_TIMEOUT && handle->m_input_plugin_last_batch_res != SCAP_EOF)
			{
				const char *errstr = handle->m_input_plugin->get_last_error(handle->m_input_plugin->state);
				strlcpy(lasterr, errstr, SCAP_LASTERR_SIZE);
			}
			int32_t tres = handle->m_input_plugin_last_batch_res;
			handle->m_input_plugin_last_batch_res = SCAP_SUCCESS;
			return tres;
		}

		int32_t plugin_res = handle->m_input_plugin->next_batch(handle->m_input_plugin->state,
									handle->m_input_plugin->handle,
									&(handle->m_input_plugin_batch_nevts),
									&(handle->m_input_plugin_batch_evts));
		handle->m_input_plugin_last_batch_res = plugin_rc_to_scap_rc(plugin_res);

		if(handle->m_input_plugin_batch_nevts == 0)
		{
			if(handle->m_input_plugin_last_batch_res == SCAP_SUCCESS)
			{
				snprintf(lasterr, SCAP_LASTERR_SIZE, "unexpected 0 size event returned by plugin %s", handle->m_input_plugin->name);
				ASSERT(false);
				return SCAP_FAILURE;
			}
			else
			{
				if(handle->m_input_plugin_last_batch_res != SCAP_TIMEOUT && handle->m_input_plugin_last_batch_res != SCAP_EOF)
				{
					const char *errstr = handle->m_input_plugin->get_last_error(handle->m_input_plugin->state);
					snprintf(lasterr, SCAP_LASTERR_SIZE, "%s", errstr);
				}
				return handle->m_input_plugin_last_batch_res;
			}
		}

		handle->m_input_plugin_batch_idx = 0;
	}

	uint32_t pos = handle->m_input_plugin_batch_idx;

	plugin_evt = &(handle->m_input_plugin_batch_evts[pos]);

	handle->m_input_plugin_batch_idx++;

	res = SCAP_SUCCESS;

	/*
	 * | scap_evt | len_id (4B) | len_pl (4B) | id | payload |
	 * Note: we need to use 4B for len_id too because the PPME_PLUGINEVENT_E has
	 * EF_LARGE_PAYLOAD flag!
	 */
	uint32_t reqsize = sizeof(scap_evt) + 4 + 4 + 4 + plugin_evt->datalen;
	if(handle->m_input_plugin_evt_storage_len < reqsize)
	{
		uint8_t *tmp = (uint8_t*)realloc(handle->m_input_plugin_evt_storage, reqsize);
		if (tmp)
		{
			handle->m_input_plugin_evt_storage = tmp;
			handle->m_input_plugin_evt_storage_len = reqsize;
		}
		else
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "%s", "failed to alloc space for plugin storage");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	scap_evt* evt = (scap_evt*)handle->m_input_plugin_evt_storage;
	evt->len = reqsize;
	evt->tid = -1;
	evt->type = PPME_PLUGINEVENT_E;
	evt->nparams = 2;

	uint8_t* buf = handle->m_input_plugin_evt_storage + sizeof(scap_evt);

	const uint32_t plugin_id_size = 4;
	memcpy(buf, &plugin_id_size, sizeof(plugin_id_size));
	buf += sizeof(plugin_id_size);

	uint32_t datalen = plugin_evt->datalen;
	memcpy(buf, &(datalen), sizeof(datalen));
	buf += sizeof(datalen);

	memcpy(buf, &(handle->m_input_plugin->id), sizeof(handle->m_input_plugin->id));
	buf += sizeof(handle->m_input_plugin->id);

	memcpy(buf, plugin_evt->data, plugin_evt->datalen);

	if(plugin_evt->ts != UINT64_MAX)
	{
		evt->ts = plugin_evt->ts;
	}
	else
	{
		evt->ts = get_timestamp_ns();
	}

	*pevent = evt;
	return res;
}

const struct scap_vtable scap_source_plugin_engine = {
	.name = "source_plugin",
	.mode = SCAP_MODE_PLUGIN,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = noop_free_handle,
	.close = close_engine,
	.next = next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = noop_get_stats,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
};
