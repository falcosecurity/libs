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
#include "sample_table.h"
#include "test_plugins.h"

/**
 * Example of plugin implementing only the event parsing capability, which:
 * - Is compatible with the "syscall" event source only
 * - Parses only events of the "open" family
 * - Defines a new field in the libsinsp's thread table representing
 *   a counter of all events of the "open" family for each thread
 * - Owns and defines a new table that has one entry for each event type,
 *   with a field representing a counter for all events of that type across all threads.
 */
struct plugin_state
{
    std::string lasterr;
    ss_plugin_table_t* thread_table;
    ss_plugin_table_field_t* thread_opencount_field;
    sample_table::ptr_t event_count_table;
    ss_plugin_table_field_t* event_count_table_count_field;
    ss_plugin_log_fn_t log;
};

static inline bool evt_type_is_open(uint16_t type)
{
    return type == PPME_SYSCALL_OPEN_E
        || type == PPME_SYSCALL_OPEN_X
        || type == PPME_SYSCALL_OPENAT_E
        || type == PPME_SYSCALL_OPENAT_X
        || type == PPME_SYSCALL_OPENAT_2_E
        || type == PPME_SYSCALL_OPENAT_2_X
        || type == PPME_SYSCALL_OPENAT2_E
        || type == PPME_SYSCALL_OPENAT2_X
        || type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_E
        || type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X
    ;
}

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
    return "sample_syscall_parse";
}

static const char* plugin_get_description()
{
    return "some desc";
}

static const char* plugin_get_contact()
{
    return "some contact";
}

static const char* plugin_get_parse_event_sources()
{
    return "[\"syscall\"]";
}

static uint16_t* plugin_get_parse_event_types(uint32_t* num_types, ss_plugin_t* s)
{
    static uint16_t types[] = {
        PPME_SYSCALL_OPEN_E,
        PPME_SYSCALL_OPEN_X,
        PPME_SYSCALL_OPENAT_E,
        PPME_SYSCALL_OPENAT_X,
        PPME_SYSCALL_OPENAT_2_E,
        PPME_SYSCALL_OPENAT_2_X,
        PPME_SYSCALL_OPENAT2_E,
        PPME_SYSCALL_OPENAT2_X,
        PPME_SYSCALL_OPEN_BY_HANDLE_AT_E,
        PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    *rc = SS_PLUGIN_SUCCESS;
    plugin_state *ret = new plugin_state();

    //set log function in the state
    ret->log = in->log_fn;

    std::string msg = "Initializing plugin...";
    std::string component = "some component";
    ret->log(component.c_str(), msg.c_str(), SS_PLUGIN_LOG_SEV_INFO);

    if (!in || !in->tables)
    {
        *rc = SS_PLUGIN_FAILURE;
        ret->lasterr = "invalid config input";
        return ret;
    }

    // get accessor for thread table
    ret->thread_table = in->tables->get_table(
        in->owner, "threads", ss_plugin_state_type::SS_PLUGIN_ST_INT64);
    if (!ret->thread_table)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        ret->lasterr = err ? err : "can't access thread table";
        return ret;
    }

    // define a new field in thread table entries
    ret->thread_opencount_field = in->tables->fields.add_table_field(
        ret->thread_table, "open_evt_count", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
    if (!ret->thread_opencount_field)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        ret->lasterr = err ? err : "can't add open counter in thread table";
        return ret;
    }

    // define a new table that keeps a counter for all events. The table's key
    // is the event code as for the libscap specific
    ret->event_count_table = sample_table::create("event_counters", ret->lasterr);
    ret->event_count_table_count_field = ret->event_count_table->fields.add_table_field(
            ret->event_count_table->table, "count",
            ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
    if (!ret->event_count_table_count_field)
    {
        *rc = SS_PLUGIN_FAILURE;
        ret->lasterr = "can't define event counter fields (count)";
        return ret;
    }

    if (SS_PLUGIN_SUCCESS != in->tables->add_table(in->owner, ret->event_count_table.get()))
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        ret->lasterr = err ? err : "can't add event counter table";
        return ret;
    }
    return ret;
}

static void plugin_destroy(ss_plugin_t* s)
{
    plugin_state *ps = (plugin_state *) s;
    std::string msg = "Destroying plugin...";
    std::string component = "some component";
    ps->log(component.c_str(), msg.c_str(), SS_PLUGIN_LOG_SEV_INFO);

    delete ((plugin_state *) s);
}

static const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

// parses events and keeps a count for each thread about the syscalls of the open family
static ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    ss_plugin_state_data tmp;
    plugin_state *ps = (plugin_state *) s;

    // update event counters
    tmp.u64 = ev->evt->type;
    auto evtcounter = ps->event_count_table->reader.get_table_entry(ps->event_count_table->table, &tmp);
    if (!evtcounter)
    {
        auto newentry = ps->event_count_table->writer.create_table_entry(ps->event_count_table->table);
        tmp.u64 = ev->evt->type;
        evtcounter = ps->event_count_table->writer.add_table_entry(ps->event_count_table->table, &tmp, newentry);
        if (!evtcounter)
        {
            ps->lasterr = "can't allocate event counter in table";
            return SS_PLUGIN_FAILURE;
        }
    }
    if (SS_PLUGIN_SUCCESS != ps->event_count_table->reader.read_entry_field(
            ps->event_count_table->table, evtcounter, ps->event_count_table_count_field, &tmp))
    {
        ps->lasterr = "can't read event counter in table";
        ps->event_count_table->reader_ext->release_table_entry(ps->event_count_table->table, evtcounter);
        return SS_PLUGIN_FAILURE;
    }
    tmp.u64++;
    if (SS_PLUGIN_SUCCESS != ps->event_count_table->writer.write_entry_field(
            ps->event_count_table->table, evtcounter, ps->event_count_table_count_field, &tmp))
    {
        ps->lasterr = "can't write event counter in table";
        ps->event_count_table->reader_ext->release_table_entry(ps->event_count_table->table, evtcounter);
        return SS_PLUGIN_FAILURE;
    }
    ps->event_count_table->reader_ext->release_table_entry(ps->event_count_table->table, evtcounter);

    // update counter for current thread
    if (evt_type_is_open(ev->evt->type))
    {
        tmp.s64 = ev->evt->tid;
        auto thread = in->table_reader.get_table_entry(ps->thread_table, &tmp);
        if (!thread)
        {
            auto err = in->get_owner_last_error(in->owner);
            ps->lasterr = err ? err : ("can't get thread with tid=" + std::to_string(ev->evt->tid));
            return SS_PLUGIN_FAILURE;
        }

        if (SS_PLUGIN_SUCCESS != in->table_reader.read_entry_field(ps->thread_table, thread, ps->thread_opencount_field, &tmp))
        {
            auto err = in->get_owner_last_error(in->owner);
            ps->lasterr = err ? err : ("can't read open counter from thread with tid=" + std::to_string(ev->evt->tid));
            in->table_reader_ext->release_table_entry(ps->thread_table, thread);
            return SS_PLUGIN_FAILURE;
        }

        // increase counter and write it back in the current thread's info
        tmp.u64++;
        if (SS_PLUGIN_SUCCESS != in->table_writer.write_entry_field(ps->thread_table, thread, ps->thread_opencount_field, &tmp))
        {
            auto err = in->get_owner_last_error(in->owner);
            ps->lasterr = err ? err : ("can't write open counter to thread with tid=" + std::to_string(ev->evt->tid));
            in->table_reader_ext->release_table_entry(ps->thread_table, thread);
            return SS_PLUGIN_FAILURE;
        }
        in->table_reader_ext->release_table_entry(ps->thread_table, thread);
    }

    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_syscall_parse(plugin_api& out)
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
}
