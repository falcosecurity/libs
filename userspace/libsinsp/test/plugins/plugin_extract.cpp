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

#include <ppm_events_public.h>

#include "test_plugins.h"

typedef struct plugin_state
{
    std::string lasterr;
    std::string strstorage;
    const char* strptr;
} plugin_state;

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
    return "sample_plugin_extract";
}

static const char* plugin_get_description()
{
    return "some desc";
}

static const char* plugin_get_contact()
{
    return "some contact";
}

static const char* plugin_get_fields()
{
    return
    "[" \
        "{\"type\": \"string\", \"name\": \"sample.hello\", \"desc\": \"A constant hello world string\"}" \
    "]";
}

static const char* plugin_get_extract_event_sources()
{
    return "[\"sample\"]";
}

static ss_plugin_t* plugin_init(const char* config, ss_plugin_rc* rc)
{
    plugin_state *ret = new plugin_state();
    *rc = SS_PLUGIN_SUCCESS;
    return ret;
}

static void plugin_destroy(ss_plugin_t* s)
{
    delete ((plugin_state *) s);
}

static const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

static ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event_input *in, uint32_t num_fields, ss_plugin_extract_field *fields)
{
    plugin_state *ps = (plugin_state *) s;
    for (uint32_t i = 0; i < num_fields; i++)
    {
        switch(fields[i].field_id)
        {
            case 0: // test.hello
                ps->strstorage = "hello world";
                ps->strptr = ps->strstorage.c_str();
                fields[i].res.str = &ps->strptr;
                fields[i].res_len = 1;
                break;
            default:
                fields[i].res_len = 0;
                return SS_PLUGIN_FAILURE;
        }
    }
    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_plugin_extract(plugin_api& out)
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
    out.get_fields = plugin_get_fields;
    out.get_extract_event_sources = plugin_get_extract_event_sources;
    out.extract_fields = plugin_extract_fields;
}
