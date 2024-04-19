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

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include <driver/ppm_events_public.h>
#include <scap.h>

#include "test_plugins.h"

static constexpr const char* s_evt_data = "hello world";

/**
 * Example of plugin implementing only the event sourcing capability, which:
 * - Implements a specific event source "sample"
 * - Sources plugin events containing a sample string
 */
struct plugin_state
{
    std::string lasterr;
    ss_plugin_owner_t* owner;
    ss_plugin_log_fn_t log;
};

struct instance_state
{
    uint64_t count;
    uint8_t evt_buf[2048];
    ss_plugin_event* evt;
};

static const char* plugin_get_required_api_version()
{
    return PLUGIN_API_VERSION_STR;
}

static const char* plugin_get_version()
{
    return "0.1.0";
}

static const char* plugin_get_name()
{
    return "sample_plugin_source";
}

static const char* plugin_get_description()
{
    return "some desc";
}

static const char* plugin_get_contact()
{
    return "some contact";
}

static uint32_t plugin_get_id()
{
	return 999;
}

static const char* plugin_get_event_source()
{
	return "sample";
}

static const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    plugin_state *ret = new plugin_state();

    //save logger and owner in the state
    ret->log = in->log_fn;
    ret->owner = in->owner;

    ret->log(ret->owner, NULL, "initializing plugin...", SS_PLUGIN_LOG_SEV_INFO);

    *rc = SS_PLUGIN_SUCCESS;
    return ret;
}

static void plugin_destroy(ss_plugin_t* s)
{
    plugin_state *ps = (plugin_state *) s;
    ps->log(ps->owner, NULL, "destroying plugin...", SS_PLUGIN_LOG_SEV_INFO);
    
    delete ((plugin_state *) s);
}

static ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, ss_plugin_rc* rc)
{
    instance_state *ret = new instance_state();
    ret->evt = (ss_plugin_event*) &ret->evt_buf;
    ret->count = 10000;
    auto count = atoi(params);
    if (count > 0)
    {
        ret->count = (uint64_t) count;
    }

    *rc = SS_PLUGIN_SUCCESS;
    return ret;
}

static void plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
    delete ((instance_state *) i);
}

static ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event ***evts)
{
    instance_state *istate = (instance_state *) i;

    if (istate->count == 0)
    {
        *nevts = 0;
        return SS_PLUGIN_EOF;
    }

    *nevts = 1;
    *evts = &istate->evt;

    char error[SCAP_LASTERR_SIZE];

    int32_t encode_res = scap_event_encode_params(scap_sized_buffer{istate->evt, sizeof(istate->evt_buf)},
        nullptr, error, PPME_PLUGINEVENT_E, 2,
        plugin_get_id(), scap_sized_buffer{(void*) s_evt_data, strlen(s_evt_data) + 1});

    if (encode_res == SCAP_FAILURE)
    {
        return SS_PLUGIN_FAILURE;
    }

    istate->evt->tid = -1;
    istate->evt->ts = UINT64_MAX;

    istate->count--;
    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_plugin_source(plugin_api& out)
{
    memset(&out, 0, sizeof(plugin_api));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_name = plugin_get_name;
    out.get_id = plugin_get_id;
    out.get_event_source = plugin_get_event_source;
	out.get_last_error = plugin_get_last_error;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
    out.open = plugin_open;
    out.close = plugin_close;
    out.next_batch = plugin_next_batch;
}
