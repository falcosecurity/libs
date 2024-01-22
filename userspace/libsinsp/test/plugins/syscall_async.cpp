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
#include <thread>
#include <atomic>

#include <driver/ppm_events_public.h>

#include "test_plugins.h"

/**
 * Example of plugin implementing only the async events capability, which:
 * - Is compatible with the "syscall" event source only
 * - Defines only one async event name
 * - Sends an async event periodically given the configured time period
 */
struct plugin_state
{
    std::string lasterr;
    uint64_t async_period;
    uint64_t async_maxevts;
    std::thread async_thread;
    std::atomic<bool> async_thread_run;
    uint8_t async_evt_buf[2048];
    ss_plugin_event* async_evt;
    ss_plugin_log_func log;
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
    return "sample_syscall_async";
}

static const char* plugin_get_description()
{
    return "some desc";
}

static const char* plugin_get_contact()
{
    return "some contact";
}

const char* plugin_get_async_event_sources()
{
    return "[\"syscall\"]";
}

const char* plugin_get_async_events()
{
    return "[\"sampleticker\"]";
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    *rc = SS_PLUGIN_SUCCESS;
    plugin_state *ret = new plugin_state();

    //set log function in the state
    ret->log = in->log;

    std::string msg = "Initializing plugin...";
    ret->log(msg.c_str(), SS_PLUGIN_LOG_SEV_INFO);
    
    ret->async_evt = (ss_plugin_event*) &ret->async_evt_buf;
    ret->async_thread_run = false;
    if (2 != sscanf(in->config, "%ld:%ld", &ret->async_maxevts, &ret->async_period))
    {
        ret->async_period = 1000000;
        ret->async_maxevts = 100;
    }
    return ret;
}

static void plugin_destroy(ss_plugin_t* s)
{
    plugin_state *ps = (plugin_state *) s;

    std::string msg = "Destroying plugin...";
    ps->log(msg.c_str(), SS_PLUGIN_LOG_SEV_INFO);

    // stop the async thread if it's running
    if (ps->async_thread_run)
    {
        ps->async_thread_run = false;
        if (ps->async_thread.joinable())
        {
            ps->async_thread.join();
        }
    }

    delete ps;
}

static const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

static void encode_async_event(ss_plugin_event* evt, uint64_t tid, const char* name, const char* data)
{
    // set event info
    evt->type = PPME_ASYNCEVENT_E;
    evt->tid = tid;
    evt->len = sizeof(ss_plugin_event);
    evt->nparams = 3;

    // lenghts
    uint8_t* parambuf = (uint8_t*) evt + sizeof(ss_plugin_event);
    *((uint32_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = strlen(name) + 1;
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = strlen(data) + 1;
    parambuf += sizeof(uint32_t);

    // params
    // skip plugin ID, it will be filled by the framework
    parambuf += sizeof(uint32_t);
    strcpy((char*) parambuf, name);
    parambuf += strlen(name) + 1;
    strcpy((char*) parambuf, data);
    parambuf += strlen(data) + 1;

    // update event's len
    evt->len += parambuf - ((uint8_t*) evt + sizeof(ss_plugin_event));
}

static ss_plugin_rc plugin_set_async_event_handler(ss_plugin_t* s, ss_plugin_owner_t* owner, const ss_plugin_async_event_handler_t handler)
{
    plugin_state *ps = (plugin_state *) s;

    // stop the async thread if it's running
    if (ps->async_thread_run)
    {
        ps->async_thread_run = false;
        if (ps->async_thread.joinable())
        {
            ps->async_thread.join();
        }
    }

    // launch the async thread with the handler, if one is provided
    if (handler)
    {
        ps->async_thread_run = true;
        ps->async_thread = std::thread([ps, owner, handler]()
        {
            char err[PLUGIN_MAX_ERRLEN];
            const char* name = "sampleticker";
            const char* data = "sample ticker notification";
            for (uint64_t i = 0; i < ps->async_maxevts && ps->async_thread_run; i++)
            {
                // attempt sending an event that is not in the allowed name list
                encode_async_event(ps->async_evt, 1, "unsupportedname", data);
                if (SS_PLUGIN_SUCCESS == handler(owner, ps->async_evt, err))
                {
                    printf("sample_syscall_async: unexpected success in sending unsupported asynchronous event from plugin\n");
                    exit(1);
                }

                // send an event in the allowed name list
                // note: we set a tid=1 to test that async events can have
                // either an empty (-1) or a non-empty tid value
                encode_async_event(ps->async_evt, 1, name, data);
                if (SS_PLUGIN_SUCCESS != handler(owner, ps->async_evt, err))
                {
                    printf("sample_syscall_async: unexpected failure in sending asynchronous event from plugin: %s\n", err);
                    exit(1);
                }

				// sleep for a period
				if(i < 2)
				{
					// sleep for 1ms
					std::this_thread::sleep_for(std::chrono::nanoseconds(ps->async_period));
				}
				else
				{
					// sleep for 1s
					std::this_thread::sleep_for(std::chrono::nanoseconds(ps->async_period*1000));
				}

            }
        });
    }

    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_syscall_async(plugin_api& out)
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
    out.get_async_event_sources = plugin_get_async_event_sources;
    out.get_async_events = plugin_get_async_events;
    out.set_async_event_handler = plugin_set_async_event_handler;
}
