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

#include "test_plugins.h"

/**
 * Example of plugin implementing only the event sourcing capability, which:
 * - Does not implement a specific event source, thus can create any syscall event
 * - Sources events of type PPME_SYSCALL_OPEN_X
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
    return "sample_syscall_source";
}

static const char* plugin_get_description()
{
    return "some desc";
}

static const char* plugin_get_contact()
{
    return "some contact";
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
    istate->evt->type = PPME_SYSCALL_OPEN_X;
    istate->evt->tid = 1;
    istate->evt->ts = UINT64_MAX;
    istate->evt->len = sizeof(ss_plugin_event);
    istate->evt->nparams = 6;

    uint8_t* parambuf = &istate->evt_buf[0] + sizeof(ss_plugin_event);

    // lenghts
    *((uint16_t*) parambuf) = sizeof(uint64_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = strlen("/tmp/the_file") + 1;
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint64_t);
    parambuf += sizeof(uint16_t);

    // params
    *((uint64_t*) parambuf) = 3;
    parambuf += sizeof(uint64_t);
    strcpy((char*) parambuf, "/tmp/the_file");
    parambuf += strlen("/tmp/the_file") + 1;
    *((uint32_t*) parambuf) = ((1 << 0) | (1 << 1));
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = 0;
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = 5;
    parambuf += sizeof(uint32_t);
    *((uint64_t*) parambuf) = 123;
    parambuf += sizeof(uint64_t);

    istate->evt->len += parambuf - (&istate->evt_buf[0] + sizeof(ss_plugin_event));
    istate->count--;
    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_syscall_source(plugin_api& out)
{
    memset(&out, 0, sizeof(plugin_api));
	out.get_required_api_version = plugin_get_required_api_version;
	out.get_version = plugin_get_version;
	out.get_description = plugin_get_description;
	out.get_contact = plugin_get_contact;
	out.get_name = plugin_get_name;
	out.get_last_error = plugin_get_last_error;
	out.init = plugin_init;
	out.destroy = plugin_destroy;
    out.open = plugin_open;
    out.close = plugin_close;
    out.next_batch = plugin_next_batch;
}
