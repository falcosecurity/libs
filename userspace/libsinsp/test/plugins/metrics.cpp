// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <iostream>

#include <driver/ppm_events_public.h>
#include "test_plugins.h"

namespace {

struct plugin_state
{
    std::string lasterr;
    ss_plugin_metric metrics[2];
    uint64_t count = 0;
};

const char* plugin_get_required_api_version()
{
    return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version()
{
    return "0.1.0";
}

const char* plugin_get_name()
{
    return "sample_metrics";
}

const char* plugin_get_description()
{
    return "some desc";
}

const char* plugin_get_contact()
{
    return "some contact";
}

const char* plugin_get_parse_event_sources()
{
    return "[\"syscall\"]";
}

uint16_t* plugin_get_parse_event_types(uint32_t* num_types, ss_plugin_t* s)
{
    static uint16_t types[] = {
        PPME_SYSCALL_OPEN_E,
        //PPME_SYSCALL_OPEN_X,
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    *rc = SS_PLUGIN_SUCCESS;
    auto ret = new plugin_state();

    ret->metrics[0].type = SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC;
    ret->metrics[0].value_type = SS_PLUGIN_METRIC_VALUE_TYPE_U64;
    ret->metrics[0].value.u64 = 1234;
    ret->metrics[0].name = "dummy_metric";

    ret->metrics[1].type = SS_PLUGIN_METRIC_TYPE_MONOTONIC;
    ret->metrics[1].value_type = SS_PLUGIN_METRIC_VALUE_TYPE_U64;
    ret->metrics[1].value.u64 = 0;
    ret->metrics[1].name = "evt_count";

    return ret;
}

void plugin_destroy(ss_plugin_t* s)
{
    delete reinterpret_cast<plugin_state*>(s);
}

const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    auto ps = reinterpret_cast<plugin_state*>(s);
    ps->count++;
    ps->metrics[1].value.u64 = ps->count;

    return SS_PLUGIN_SUCCESS;
}

ss_plugin_metric* plugin_get_metrics(ss_plugin_t *s, uint32_t *num_metrics)
{
    auto ps = reinterpret_cast<plugin_state*>(s);

    *num_metrics = sizeof(ps->metrics) / sizeof(ss_plugin_metric);

    return ps->metrics;
}

} // anonymous namespace

void get_plugin_api_sample_metrics(plugin_api& out)
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
    out.get_parse_event_sources = plugin_get_parse_event_sources;
    out.get_parse_event_types = plugin_get_parse_event_types;
    out.parse_event = plugin_parse_event;
    out.get_metrics = plugin_get_metrics;
}
