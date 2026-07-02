// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HANDLE(engine) ((raw_block_engine *)(engine.m_handle))
#define MAX_EVENT_SIZE 64 * 1024

#include <libscap/engine/raw_block/raw_block.h>
#include <libscap/engine/raw_block/raw_block_public.h>
#include <libscap/engine/raw_block/raw_block_platform.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile.h>
#include <libscap/strerror.h>
#include <libscap/engine/savefile/scap_reader.h>
#include <libscap/engine/noop/noop.h>
#include <libscap/engine/savefile/converter/converter.h>

// From scap_reader_membuf.c
scap_reader_t *scap_reader_open_membuf(uint8_t **buffer_ptr, uint64_t *buffer_size_ptr);

static int32_t scap_raw_block_init_platform(struct scap_platform *platform,
                                            char *lasterr,
                                            struct scap_engine_handle engine,
                                            struct scap_open_args *oargs) {
	return SCAP_SUCCESS;
}

static int32_t scap_raw_block_close_platform(struct scap_platform *platform) {
	return SCAP_SUCCESS;
}

static void scap_raw_block_free_platform(struct scap_platform *platform) {
	free(platform);
}

static bool scap_raw_block_is_thread_alive(struct scap_platform *platform,
                                           int64_t pid,
                                           int64_t tid,
                                           const char *comm) {
	return false;
}

static const struct scap_platform_vtable scap_raw_block_platform_vtable = {
        .init_platform = scap_raw_block_init_platform,
        .is_thread_alive = scap_raw_block_is_thread_alive,
        .close_platform = scap_raw_block_close_platform,
        .free_platform = scap_raw_block_free_platform,
};

struct scap_platform *scap_raw_block_alloc_platform(scap_proc_callbacks callbacks) {
	struct scap_raw_block_platform *platform = calloc(1, sizeof(*platform));

	if(platform == NULL) {
		return NULL;
	}

	platform->m_generic.m_vtable = &scap_raw_block_platform_vtable;
	platform->m_generic.m_machine_info.num_cpus = (uint32_t)-1;

	init_proclist(&platform->m_generic.m_proclist, callbacks);

	return &platform->m_generic;
}

static void *alloc_handle(struct scap *main_handle, char *lasterr_ptr) {
	raw_block_engine *engine = calloc(1, sizeof(raw_block_engine));
	if(engine) {
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static int32_t init(struct scap *main_handle, struct scap_open_args *oargs) {
	if(oargs == NULL || oargs->engine_params == NULL) {
		return scap_errprintf(main_handle->m_lasterr, 0, "Invalid raw_block engine parameters");
	}

	int res;
	raw_block_engine *handle = main_handle->m_engine.m_handle;
	struct scap_raw_block_engine_params *params = oargs->engine_params;
	uint8_t **buffer_ptr = params->buffer_ptr;
	uint64_t *buffer_size_ptr = params->buffer_size_ptr;
	struct scap_platform *platform = params->platform;

	if(platform == NULL) {
		return scap_errprintf(main_handle->m_lasterr, 0, "Invalid raw_block engine parameters");
	}

	handle->m_platform = platform;

	if(buffer_ptr == NULL || *buffer_ptr == NULL || buffer_size_ptr == NULL ||
	   *buffer_size_ptr == 0) {
		return scap_errprintf(main_handle->m_lasterr, 0, "invalid buffer parameters");
	}

	scap_reader_t *reader = scap_reader_open_membuf(buffer_ptr, buffer_size_ptr);
	if(!reader) {
		return scap_errprintf(main_handle->m_lasterr, 0, "can't create memory buffer reader");
	}

	handle->m_use_last_block_header = false;

	// The initial buffer holds the section header and metadata blocks; the event blocks
	// arrive in subsequent buffers. Unlike the savefile engine, we don't require an event
	// block to be present here, so a metadata-only buffer is accepted.
	res = scap_savefile_read_init(handle,
	                              reader,
	                              &platform->m_machine_info,
	                              &platform->m_proclist,
	                              &platform->m_addrlist,
	                              &platform->m_userlist,
	                              main_handle->m_lasterr);

	if(res != SCAP_SUCCESS) {
		reader->close(reader);
		return res;
	}

	handle->m_reader_evt_buf = (char *)malloc(READER_BUF_SIZE);
	if(!handle->m_reader_evt_buf) {
		reader->close(reader);
		return scap_errprintf(main_handle->m_lasterr, 0, "error allocating the read buffer");
	}
	handle->m_reader_evt_buf_size = READER_BUF_SIZE;
	handle->m_reader = reader;

	if(!oargs->import_users) {
		if(platform->m_userlist != NULL) {
			scap_free_userlist(platform->m_userlist);
			platform->m_userlist = NULL;
		}
	}

	handle->m_converter_buf = scap_convert_alloc_buffer();
	if(!handle->m_converter_buf) {
		return scap_errprintf(main_handle->m_lasterr, 0, "error allocating the conversion buffer");
	}

	return SCAP_SUCCESS;
}

static void free_handle(struct scap_engine_handle engine) {
	free(engine.m_handle);
}

static int32_t scap_raw_block_close(struct scap_engine_handle engine) {
	raw_block_engine *handle = engine.m_handle;
	if(handle->m_reader) {
		handle->m_reader->close(handle->m_reader);
		handle->m_reader = NULL;
	}

	if(handle->m_reader_evt_buf) {
		free(handle->m_reader_evt_buf);
		handle->m_reader_evt_buf = NULL;
	}

	if(handle->m_new_evt) {
		free(handle->m_new_evt);
		handle->m_new_evt = NULL;
	}

	if(handle->m_to_convert_evt) {
		free(handle->m_to_convert_evt);
		handle->m_to_convert_evt = NULL;
	}

	if(handle->m_converter_buf) {
		scap_convert_free_buffer(handle->m_converter_buf);
		handle->m_converter_buf = NULL;
	}

	return SCAP_SUCCESS;
}

static int32_t next(struct scap_engine_handle engine,
                    scap_evt **pevent,
                    uint16_t *pdevid,
                    uint32_t *pflags) {
	raw_block_engine *handle = engine.m_handle;
	int32_t res = scap_savefile_next_event_from_file(handle, pevent, pdevid, pflags);
	if(res != SCAP_SUCCESS) {
		return res;
	}

	conversion_result conv_res = test_event_convertibility(*pevent, handle->m_lasterr);
	switch(conv_res) {
	case CONVERSION_PASS:
		return SCAP_SUCCESS;
	case CONVERSION_DROP:
		return SCAP_FILTERED_EVENT;
	case CONVERSION_ERROR:
		return SCAP_FAILURE;
	case CONVERSION_CONTINUE:
		break;
	default:
		scap_errprintf(handle->m_lasterr,
		               0,
		               "Bug. Unexpected conversion result '%d' while checking for event (type: %d, "
		               "nparams: %d) convertibility.",
		               conv_res,
		               (*pevent)->type,
		               (*pevent)->nparams);
		return SCAP_FAILURE;
	}

	if(!handle->m_new_evt) {
		handle->m_new_evt = calloc(1, MAX_EVENT_SIZE);
	}
	if(!handle->m_to_convert_evt) {
		handle->m_to_convert_evt = calloc(1, MAX_EVENT_SIZE);
	}

	int conv_num = 0;
	conv_res = CONVERSION_CONTINUE;
	for(conv_num = 0; conv_num < MAX_CONVERSION_BOUNDARY && conv_res == CONVERSION_CONTINUE;
	    conv_num++) {
		// The conversion staging buffers (m_to_convert_evt / m_new_evt) are MAX_EVENT_SIZE
		// bytes. Refuse to convert any event whose len would overflow them.
		if((*pevent)->len > MAX_EVENT_SIZE) {
			return scap_errprintf(handle->m_lasterr,
			                      0,
			                      "invalid event: len %u is larger than the maximum event size %u",
			                      (*pevent)->len,
			                      MAX_EVENT_SIZE);
		}
		memcpy(handle->m_to_convert_evt, *pevent, (*pevent)->len);
		conv_res = scap_convert_event(handle->m_converter_buf,
		                              (scap_evt *)handle->m_new_evt,
		                              (scap_evt *)handle->m_to_convert_evt,
		                              MAX_EVENT_SIZE,
		                              handle->m_lasterr);
		*pevent = (scap_evt *)handle->m_new_evt;
	}

	if(conv_res == CONVERSION_ERROR) {
		return SCAP_FAILURE;
	}

	if(conv_num == MAX_CONVERSION_BOUNDARY) {
		switch(conv_res) {
		case CONVERSION_PASS:
		case CONVERSION_DROP:
			return scap_errprintf(
			        handle->m_lasterr,
			        0,
			        "Reached max conversions '%d' with result '%d' for event "
			        "(type: %d, nparams: %d). Bump the conversions max limit in the code.",
			        MAX_CONVERSION_BOUNDARY,
			        conv_res,
			        (*pevent)->type,
			        (*pevent)->nparams);
		case CONVERSION_CONTINUE:
			return scap_errprintf(handle->m_lasterr,
			                      0,
			                      "Reached '%d' conversions with event (type: %d, nparams: %d) "
			                      "without reaching an end.",
			                      MAX_CONVERSION_BOUNDARY,
			                      (*pevent)->type,
			                      (*pevent)->nparams);
		default:
			return scap_errprintf(handle->m_lasterr,
			                      0,
			                      "Reached '%d' conversions with event (type: %d, nparams: %d) "
			                      "with unknown conversion result '%d'.",
			                      MAX_CONVERSION_BOUNDARY,
			                      (*pevent)->type,
			                      (*pevent)->nparams,
			                      conv_res);
		}
	}

	switch(conv_res) {
	case CONVERSION_PASS:
		return SCAP_SUCCESS;
	case CONVERSION_DROP:
		return SCAP_FILTERED_EVENT;
	case CONVERSION_CONTINUE:
		return scap_errprintf(handle->m_lasterr,
		                      0,
		                      "Bug. Conversion ended with unexpected conversion result '%d' and "
		                      "resulting event (type: %d, nparams: %d).",
		                      conv_res,
		                      (*pevent)->type,
		                      (*pevent)->nparams);
	default:
		return scap_errprintf(
		        handle->m_lasterr,
		        0,
		        "Bug. Unknown conversion result '%d' for resulting event (type: %d, nparams: %d).",
		        conv_res,
		        (*pevent)->type,
		        (*pevent)->nparams);
	}
}

static uint64_t scap_raw_block_ftell(struct scap_engine_handle engine) {
	scap_reader_t *reader = HANDLE(engine)->m_reader;
	return reader->tell(reader);
}

static void scap_raw_block_fseek(struct scap_engine_handle engine, uint64_t off) {
	scap_reader_t *reader = HANDLE(engine)->m_reader;
	reader->seek(reader, off, SEEK_SET);
}

static int32_t scap_raw_block_restart_capture(scap_t *handle) {
	raw_block_engine *engine = handle->m_engine.m_handle;
	struct scap_platform *platform = engine->m_platform;
	int32_t res;

	scap_platform_close(platform);

	// Seek the reader back to the beginning
	engine->m_reader->seek(engine->m_reader, 0, SEEK_SET);
	engine->m_use_last_block_header = false;

	if((res = scap_savefile_read_init(engine,
	                                  engine->m_reader,
	                                  &platform->m_machine_info,
	                                  &platform->m_proclist,
	                                  &platform->m_addrlist,
	                                  &platform->m_userlist,
	                                  handle->m_lasterr)) != SCAP_SUCCESS) {
		char error_copy[SCAP_LASTERR_SIZE];
		scap_errprintf(error_copy, 0, "%s", scap_getlasterr(handle));
		scap_errprintf(handle->m_lasterr, 0, "could not restart capture: %s", error_copy);
	}
	return res;
}

static int64_t get_readfile_offset(struct scap_engine_handle engine) {
	return HANDLE(engine)->m_reader->offset(HANDLE(engine)->m_reader);
}

static struct scap_savefile_vtable raw_block_savefile_ops = {
        .ftell_capture = scap_raw_block_ftell,
        .fseek_capture = scap_raw_block_fseek,

        .restart_capture = scap_raw_block_restart_capture,
        .get_readfile_offset = get_readfile_offset,
};

const struct scap_vtable scap_raw_block_engine = {
        .name = RAW_BLOCK_ENGINE,
        .savefile_ops = &raw_block_savefile_ops,

        .alloc_handle = alloc_handle,
        .init = init,
        .free_handle = free_handle,
        .close = scap_raw_block_close,
        .next = next,
        .start_capture = noop_start_capture,
        .stop_capture = noop_stop_capture,
        .configure = noop_configure,
        .get_stats = noop_get_stats,
        .get_stats_v2 = noop_get_stats_v2,
        .get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
        .get_n_devs = noop_get_n_devs,
        .get_max_buf_used = noop_get_max_buf_used,
        .get_api_version = NULL,
        .get_schema_version = NULL,
};
