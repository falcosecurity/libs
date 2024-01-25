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
 * Example of plugin implementing only the field extraction capability, which:
 * - Is compatible with the "syscall" event source only
 * - Extracts only from events of the "open" family, plus another one for test purposes
 * - Uses the libsinsp's thread table and accesses the threads' "comm" field
 * - Optionally accesses a field defined at runtime by another plugin on the thread table
 * - Optionally accesses a table defined at runtime by another plugin
 */
struct plugin_state
{
    std::string lasterr;
    uint64_t u64storage;
    std::string strstorage;
    const char* strptrstorage;
    ss_plugin_table_t* thread_table;
    ss_plugin_table_field_t* thread_comm_field;
    ss_plugin_table_field_t* thread_opencount_field;
    ss_plugin_table_t* evtcount_table;
    ss_plugin_table_field_t* evtcount_count_field;
    ss_plugin_owner_t* owner;
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

static inline const char* get_async_event_name(const ss_plugin_event* e)
{
    return (const char*) ((uint8_t*) e + sizeof(ss_plugin_event) + 4+4+4+4);
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
    return "sample_syscall_extract";
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
	return R"(
[
	{
		"type": "uint64",
		"name": "sample.is_open",
		"desc": "Value is 1 if event is of open family"
	},
	{
		"type": "uint64",
		"name": "sample.open_count",
		"desc": "Counter for all the events of open family in a given thread"
	},
	{
		"type": "uint64",
		"name": "sample.evt_count",
		"desc": "Counter of events of the same type of the current one, counting all threads"
	},
	{
		"type": "string",
		"name": "sample.proc_name",
		"desc": "Alias for proc.name, but implemented from a plugin"
	},
	{
		"type": "string",
		"name": "sample.tick",
		"desc": "'true' if the current event is a ticker notification"
	}
])";
}

static const char* plugin_get_extract_event_sources()
{
    return "[\"syscall\"]";
}

static uint16_t* plugin_get_extract_event_types(uint32_t* num_types, ss_plugin_t* s)
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
        // note: filtered for testing purposes
        // PPME_SYSCALL_OPEN_BY_HANDLE_AT_E,
        // PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
        // note: non-filtered for testing purposes
        PPME_SYSCALL_INOTIFY_INIT1_E,
        PPME_SYSCALL_INOTIFY_INIT1_X,
        PPME_ASYNCEVENT_E, // used for catching async events
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    *rc = SS_PLUGIN_SUCCESS;
    plugin_state *ret = new plugin_state();

    //save logger and owner in the state
    ret->log = in->log_fn;
    ret->owner = in->owner;

    ret->log(ret->owner, NULL, "initializing plugin...", SS_PLUGIN_LOG_SEV_INFO);

	// we have the extraction capability so the `in->tables` field should be != NULL
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

    // get accessor for proc name in thread table entries
    ret->thread_comm_field = in->tables->fields.get_table_field(
        ret->thread_table, "comm", ss_plugin_state_type::SS_PLUGIN_ST_STRING);
    if (!ret->thread_comm_field)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        ret->lasterr = err ? err : "can't access proc name in thread table";
        return ret;
    }

    // get a field defined from another plugin (sample_syscall_parse) in the sinsp thread table.
    // we don't check for errors: if the field is not available, we'll simply
    // extract the related field as NULL.
    ret->thread_opencount_field = in->tables->fields.get_table_field(
        ret->thread_table, "open_evt_count", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
    /* The result will depend on how the plugin is used in the test */
	if (!ret->thread_opencount_field)
    {
        printf("OK(syscall_extract) - as expected field 'open_evt_count' is not available in the thread table. The plugin field 'sample.open_count' will not be available\n");
    }
	else
	{
        printf("OK(syscall_extract) - as expected field 'open_evt_count' is available in the thread table. The plugin field 'sample.open_count' will be available\n");
	}

    // we try to access a table (and one of its fields) defined and owned by
    // another plugin
    ret->evtcount_table = in->tables->get_table(
        in->owner, "event_counters", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
    /* The result will depend on how the plugin is used in the test */
    if (ret->evtcount_table)
    {
        ret->evtcount_count_field = in->tables->fields.get_table_field(
            ret->evtcount_table, "count", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
    }

    if (!ret->evtcount_table || !ret->evtcount_count_field)
    {
        printf("OK(syscall_extract) - as expected 'event_counters' table is not available. The plugin field 'sample.evt_count' will not be available\n");
    }
	else
	{
        printf("OK(syscall_extract) - as expected 'event_counters' table is available. The plugin field 'sample.evt_count' will be available\n");
	}
    return ret;
}

static void plugin_destroy(ss_plugin_t* s)
{
    plugin_state *ps = (plugin_state *) s;
    ps->log(ps->owner, NULL, "destroying plugin...", SS_PLUGIN_LOG_SEV_INFO);

    delete ((plugin_state *) s);
}

static const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

static ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_field_extract_input* in)
{
    ss_plugin_rc rc;
    ss_plugin_state_data tmp;
    ss_plugin_table_entry_t* thread = NULL;
    ss_plugin_table_entry_t* evtcount = NULL;
    plugin_state *ps = (plugin_state *) s;
    for (uint32_t i = 0; i < in->num_fields; i++)
    {
        switch(in->fields[i].field_id)
        {
            case 0: // sample.is_open
                ps->u64storage = evt_type_is_open(ev->evt->type);
                in->fields[i].res.u64 = &ps->u64storage;
                in->fields[i].res_len = 1;
                break;
            case 1: // sample.open_count
				/* This is a new field defined in the sinsp thread table */
                if (!ps->thread_opencount_field)
                {
                    in->fields[i].res_len = 0;
                    return SS_PLUGIN_FAILURE;
                }
                tmp.s64 = ev->evt->tid;
                thread = in->table_reader.get_table_entry(ps->thread_table, &tmp);
                if (!thread)
                {
                    auto err = in->get_owner_last_error(in->owner);
                    ps->lasterr = err ? err : ("can't get thread with tid=" + std::to_string(ev->evt->tid));
                    return SS_PLUGIN_FAILURE;
                }
                rc = in->table_reader.read_entry_field(ps->thread_table, thread, ps->thread_opencount_field, &tmp);
                if (rc != SS_PLUGIN_SUCCESS)
                {
                    auto err = in->get_owner_last_error(in->owner);
                    ps->lasterr = err ? err : ("can't read ope counter from thread with tid=" + std::to_string(ev->evt->tid));
                    in->table_reader_ext->release_table_entry(ps->thread_table, thread);
                    return SS_PLUGIN_FAILURE;
                }
                ps->u64storage = tmp.u64;
                in->fields[i].res.u64 = &ps->u64storage;
                in->fields[i].res_len = 1;
                in->table_reader_ext->release_table_entry(ps->thread_table, thread);
                break;
            case 2: // sample.evt_count
                if (!ps->evtcount_table || !ps->evtcount_count_field)
                {
                    in->fields[i].res_len = 0;
                    return SS_PLUGIN_FAILURE;
                }

                // testing that error reporting works as expected
                tmp.s64 = 9999;
                evtcount = in->table_reader.get_table_entry(ps->evtcount_table, &tmp);
                if (evtcount)
                {
                    printf("sample_syscall_extract: unexpected success in getting unknown table entry from another plugin\n");
                    exit(1);
                }
                else
                {
                    auto err = in->get_owner_last_error(in->owner);
                    if (err == NULL || strlen(err) == 0)
                    {
                        printf("sample_syscall_extract: unexpected empty error in getting unknown table entry from another plugin\n");
                        exit(1);
                    }
                }

                tmp.s64 = ev->evt->type;
                evtcount = in->table_reader.get_table_entry(ps->evtcount_table, &tmp);
                if (!evtcount)
                {
                    // stubbing the counter to 0 if no entry exists
                    ps->u64storage = 0;
                    in->fields[i].res.u64 = &ps->u64storage;
                    in->fields[i].res_len = 1;
                    return SS_PLUGIN_SUCCESS;
                }
                rc = in->table_reader.read_entry_field(ps->evtcount_table, evtcount, ps->evtcount_count_field, &tmp);
                if (rc != SS_PLUGIN_SUCCESS)
                {
                    auto err = in->get_owner_last_error(in->owner);
                    ps->lasterr = err ? err : ("can't read event counter for type=" + std::to_string(ev->evt->type));
                    in->table_reader_ext->release_table_entry(ps->evtcount_table, evtcount);
                    return SS_PLUGIN_FAILURE;
                }
                ps->u64storage = tmp.u64;
                in->fields[i].res.u64 = &ps->u64storage;
                in->fields[i].res_len = 1;
                in->table_reader_ext->release_table_entry(ps->evtcount_table, evtcount);
                break;
            case 3: // sample.proc_name
                tmp.s64 = ev->evt->tid;
                thread = in->table_reader.get_table_entry(ps->thread_table, &tmp);
                if (!thread)
                {
                    auto err = in->get_owner_last_error(in->owner);
                    ps->lasterr = err ? err : ("can't get thread with tid=" + std::to_string(ev->evt->tid));
                    return SS_PLUGIN_FAILURE;
                }
                rc = in->table_reader.read_entry_field(ps->thread_table, thread, ps->thread_comm_field, &tmp);
                if (rc != SS_PLUGIN_SUCCESS)
                {
                    auto err = in->get_owner_last_error(in->owner);
                    ps->lasterr = err ? err : ("can't read proc name from thread with tid=" + std::to_string(ev->evt->tid));
                    in->table_reader_ext->release_table_entry(ps->thread_table, thread);
                    return SS_PLUGIN_FAILURE;
                }
                ps->strstorage = std::string(tmp.str);
                ps->strptrstorage = ps->strstorage.c_str();
                in->fields[i].res.str = &ps->strptrstorage;
                in->fields[i].res_len = 1;
                in->table_reader_ext->release_table_entry(ps->thread_table, thread);
                break;
            case 4: // sample.tick
                if (ev->evt->type == PPME_ASYNCEVENT_E
                    && strcmp("sampleticker", get_async_event_name(ev->evt)) == 0)
                {
                    ps->strstorage = "true";
                }
                else
                {
                    ps->strstorage = "false";
                }
                ps->strptrstorage = ps->strstorage.c_str();
                in->fields[i].res.str = &ps->strptrstorage;
                in->fields[i].res_len = 1;
                break;
            default:
                in->fields[i].res_len = 0;
                return SS_PLUGIN_FAILURE;
        }
    }
    return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_syscall_extract(plugin_api& out)
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
    out.get_extract_event_types = plugin_get_extract_event_types;
    out.extract_fields = plugin_extract_fields;
}
