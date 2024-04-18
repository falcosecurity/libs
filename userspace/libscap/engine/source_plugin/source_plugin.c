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

#define SCAP_HANDLE_T struct source_plugin_engine

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <libscap/engine/source_plugin/source_plugin.h>
#include <libscap/engine/noop/noop.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/strl.h>
#include <libscap/scap_gettimeofday.h>

static const char * const source_plugin_counters_stats_names[] = {
	[N_EVTS] = "n_evts",
};

// We need to check that ppm_evt_hdr and ss_plugin_event are the same struct
// right at compile time. We do so by checking for their size and the offset
// of each of their subfields. This allows us to avoid divergences while at the
// same time not sharing the same headers.
#if defined __GNUC__ || __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ppm_evt_hdr) == sizeof(ss_plugin_event),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync");
_Static_assert(offsetof(struct ppm_evt_hdr, ts) == offsetof(ss_plugin_event, ts),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync (ts)");
_Static_assert(offsetof(struct ppm_evt_hdr, tid) == offsetof(ss_plugin_event, tid),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync (tid)");
_Static_assert(offsetof(struct ppm_evt_hdr, len) == offsetof(ss_plugin_event, len),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync (len)");
_Static_assert(offsetof(struct ppm_evt_hdr, type) == offsetof(ss_plugin_event, type),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync (type)");
_Static_assert(offsetof(struct ppm_evt_hdr, nparams) == offsetof(ss_plugin_event, nparams),
	"structs ppm_evt_hdr and ss_plugin_event are out of sync (nparams)");
#endif

// We need to check that ppm_param_type and ss_plugin_field_type follow
// the same enumeratives at compile-time.
#if defined __GNUC__ || __STDC_VERSION__ >= 201112L
_Static_assert((uint32_t) FTYPE_UINT64 == (uint32_t) PT_UINT64,
	"ss_plugin_field_type and ppm_param_type are out of sync (UINT64)");
_Static_assert((uint32_t) FTYPE_STRING == (uint32_t) PT_CHARBUF,
	"ss_plugin_field_type and ppm_param_type are out of sync (STRING)");
_Static_assert((uint32_t) FTYPE_RELTIME == (uint32_t) PT_RELTIME,
	"ss_plugin_field_type and ppm_param_type are out of sync (RELTIME)");
_Static_assert((uint32_t) FTYPE_ABSTIME == (uint32_t) PT_ABSTIME,
	"ss_plugin_field_type and ppm_param_type are out of sync (ABSTIME)");
_Static_assert((uint32_t) FTYPE_BOOL == (uint32_t) PT_BOOL,
	"ss_plugin_field_type and ppm_param_type are out of sync (BOOL)");
_Static_assert((uint32_t) FTYPE_IPADDR == (uint32_t) PT_IPADDR,
	"ss_plugin_field_type and ppm_param_type are out of sync (IPADDR)");
_Static_assert((uint32_t) FTYPE_IPNET == (uint32_t) PT_IPNET,
	"ss_plugin_field_type and ppm_param_type are out of sync (IPNET)");
#endif

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

static int32_t init(scap_t* main_handle, scap_open_args* oargs)
{
	int32_t rc;
	struct source_plugin_engine *handle = main_handle->m_engine.m_handle;
	struct scap_source_plugin_engine_params *params = oargs->engine_params;
	handle->m_input_plugin = params->input_plugin;

	// Set the rc to SCAP_FAILURE now, so in the unlikely event
	// that a plugin doesn't not actually set a rc, that it gets
	// treated as a failure.
	ss_plugin_rc plugin_rc = SCAP_FAILURE;

	handle->m_input_plugin->handle = handle->m_input_plugin->open(handle->m_input_plugin->state,
	                                                              params->input_plugin_params,
	                                                              &plugin_rc);

	rc = plugin_rc_to_scap_rc(plugin_rc);
	handle->m_nevts = 0;
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

	// We could arrive here without having initialized 'm_input_plugin'.
	if(handle->m_input_plugin != NULL)
	{
		handle->m_input_plugin->close(handle->m_input_plugin->state, handle->m_input_plugin->handle);
		handle->m_input_plugin->handle = NULL;
	}
	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pdevid, OUT uint32_t* pflags)
{
	struct source_plugin_engine *handle = engine.m_handle;
	char *lasterr = engine.m_handle->m_lasterr;

	/* we have to read a new batch */
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
	scap_evt* evt = (scap_evt*) handle->m_input_plugin_batch_evts[pos];

	// Sanity checks in case a plugin implements a non-syscall event source.
	// If a plugin has event sourcing capability and has a specific ID, then
	// it is allowed to produce only plugin events of its own event source.
	uint32_t* pplugin_id = (uint32_t*)((uint8_t*) evt + sizeof(scap_evt) + 4 + 4);
	uint32_t plugin_id;
	memcpy(&plugin_id, pplugin_id, sizeof(plugin_id));

	if (handle->m_input_plugin->id != 0)
	{
		/*
		* | scap_evt | len_id (4B) | len_pl (4B) | id | payload |
		* Note: we need to use 4B for len_id too because the
		* PPME_PLUGINEVENT_E has EF_LARGE_PAYLOAD flag!
		*/
		if (evt->type != PPME_PLUGINEVENT_E || evt->nparams != 2)
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "malformed plugin event produced by plugin: '%s'", handle->m_input_plugin->name);
			return SCAP_FAILURE;
		}

		// forcely setting plugin ID with the one of the open plugin
		if (plugin_id == 0)
		{
			plugin_id = handle->m_input_plugin->id;
			memcpy(pplugin_id, &plugin_id, sizeof(plugin_id));
		}
		else if (plugin_id != handle->m_input_plugin->id)
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "unexpected plugin ID in plugin event: plugin='%s', expected_id=%d, actual_id=%d", handle->m_input_plugin->name, handle->m_input_plugin->id, plugin_id);
			return SCAP_FAILURE;
		}
	}

	if (evt->type == PPME_PLUGINEVENT_E)
	{
		// a zero plugin ID is not allowed for PPME_PLUGINEVENT_E
		if (plugin_id == 0)
		{
			snprintf(lasterr, SCAP_LASTERR_SIZE, "malformed plugin event produced by plugin (no ID): '%s'", handle->m_input_plugin->name);
			return SCAP_FAILURE;
		}

		// plugin events have no thread associated
		evt->tid = (uint64_t) -1;
	}
	
	// automatically set timestamp if none was specified
	if(evt->ts == UINT64_MAX)
	{
		evt->ts = get_timestamp_ns();
	}

	*pevent = evt;
	*pdevid = 0;
	*pflags = 0;
	handle->m_nevts++;
	handle->m_input_plugin_batch_idx++;
	return SCAP_SUCCESS;
}

static int32_t get_stats(struct scap_engine_handle engine, OUT scap_stats* stats)
{
	struct source_plugin_engine *handle = engine.m_handle;
	stats->n_evts = handle->m_nevts;
	return SCAP_SUCCESS;
}

const struct metrics_v2* get_source_plugin_stats_v2(struct scap_engine_handle engine, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc)
{
	struct source_plugin_engine *handle = engine.m_handle;
	*nstats = MAX_SOURCE_PLUGIN_COUNTERS_STATS;
	metrics_v2* stats = handle->m_stats;
	if (!stats)
	{
		*nstats = 0;
		*rc = SCAP_FAILURE;
		return NULL;
	}

	/* SOURCE PLUGIN STATS COUNTERS */
	for(uint32_t stat = 0; stat < MAX_SOURCE_PLUGIN_COUNTERS_STATS; stat++)
	{
		stats[stat].type = METRIC_VALUE_TYPE_U64;
		stats[stat].value.u64 = 0;
		stats[stat].unit = METRIC_VALUE_UNIT_COUNT;
		stats[stat].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
		strlcpy(stats[stat].name, source_plugin_counters_stats_names[stat], METRIC_NAME_MAX);
	}
	stats[N_EVTS].value.u64 = handle->m_nevts;

	*rc = SCAP_SUCCESS;
	return stats;
}

const struct scap_vtable scap_source_plugin_engine = {
	.name = SOURCE_PLUGIN_ENGINE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = noop_free_handle,
	.close = close_engine,
	.next = next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = get_stats,
	.get_stats_v2 = get_source_plugin_stats_v2,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};
