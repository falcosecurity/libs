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
 * Example of plugin that accesses the thread table and that exposes its own
 * sta table. The goal is to test all the methods of the table API.
 */
struct plugin_state
{
	std::string lasterr;
	ss_plugin_table_t* thread_table;
	ss_plugin_table_field_t* thread_static_field;
	ss_plugin_table_field_t* thread_dynamic_field;
	ss_plugin_table_field_t* thread_dynamic_field_str;
	sample_table::ptr_t internal_table;
	ss_plugin_table_field_t* internal_dynamic_field;
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
	return "sample_tables";
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
	static uint16_t *types = {};
	*num_types = 0;
	return types;
}

static ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
	*rc = SS_PLUGIN_SUCCESS;
	plugin_state *ret = new plugin_state();

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

	// get an existing field from thread table entries
	// todo(jasondellaluce): add tests for fields of other types as well
	ret->thread_static_field = in->tables->fields.get_table_field(
		ret->thread_table, "comm", ss_plugin_state_type::SS_PLUGIN_ST_STRING);
	if (!ret->thread_static_field)
	{
		*rc = SS_PLUGIN_FAILURE;
		auto err = in->get_owner_last_error(in->owner);
		ret->lasterr = err ? err : "can't get static field in thread table";
		return ret;
	}

	// define a new field in thread table entries
	// todo(jasondellaluce): add tests for fields of other types as well
	ret->thread_dynamic_field = in->tables->fields.add_table_field(
		ret->thread_table, "some_new_dynamic_field", ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
	if (!ret->thread_dynamic_field)
	{
		*rc = SS_PLUGIN_FAILURE;
		auto err = in->get_owner_last_error(in->owner);
		ret->lasterr = err ? err : "can't add dynamic field in thread table";
		return ret;
	}
	ret->thread_dynamic_field_str = in->tables->fields.add_table_field(
		ret->thread_table, "some_new_dynamic_field_str", ss_plugin_state_type::SS_PLUGIN_ST_STRING);
	if (!ret->thread_dynamic_field_str)
	{
		*rc = SS_PLUGIN_FAILURE;
		auto err = in->get_owner_last_error(in->owner);
		ret->lasterr = err ? err : "can't add dynamic field in thread table";
		return ret;
	}

	// define a new table that keeps a counter for all events.
	// todo(jasondellaluce): add tests for fields of other types as well
	ret->internal_table = sample_table::create("plugin_sample", ret->lasterr);
	ret->internal_dynamic_field = ret->internal_table->fields.add_table_field(
			ret->internal_table->table, "u64_val",
			ss_plugin_state_type::SS_PLUGIN_ST_UINT64);
	if (!ret->internal_dynamic_field)
	{
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't define internal table field";
		return ret;
	}

	if (SS_PLUGIN_SUCCESS != in->tables->add_table(in->owner, ret->internal_table.get()))
	{
		*rc = SS_PLUGIN_FAILURE;
		auto err = in->get_owner_last_error(in->owner);
		ret->lasterr = err ? err : "can't add internal table";
		return ret;
	}
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

// parses events and keeps a count for each thread about the syscalls of the open family
static ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
	static int64_t s_new_thread_tid = 999999;
	int step = 0;
	ss_plugin_state_data tmp;
	ss_plugin_table_entry_t* thread;
	plugin_state *ps = (plugin_state *) s;

	// get table name
	step++;
	{
		if (strcmp("threads", in->table_reader_ext->get_table_name(ps->thread_table)))
		{
			fprintf(stderr, "table_reader.get_table_name (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
	}

	// check that the table contains only the init thread
	step++;
	{
		auto size = in->table_reader_ext->get_table_size(ps->thread_table);
		if (size != 1)
		{
			fprintf(stderr, "table_reader.get_table_size (%d) failure: (%lu) %s\n", step, size, in->get_owner_last_error(in->owner));
			exit(1);
		}
	}

	// get the init thread and read its comm
	step++;
	{
		tmp.s64 = 1;
		thread = in->table_reader_ext->get_table_entry(ps->thread_table, &tmp);
		if (!thread)
		{
			fprintf(stderr, "table_reader.get_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_static_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (strcmp("init", tmp.str))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// read-write dynamic field from existing thread
	step++;
	{
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (tmp.u64 != 0)
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
		tmp.u64 = 5;
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (tmp.u64 != 5)
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// read-write dynamic field (str) from existing thread
	step++;
	{
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field_str, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (strcmp("", tmp.str))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
		tmp.str = "hello";
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_dynamic_field_str, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field_str, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (strcmp("hello", tmp.str))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// get non-existing thread
	step++;
	{
		tmp.s64 = s_new_thread_tid;
		thread = in->table_reader_ext->get_table_entry(ps->thread_table, &tmp);
		if (thread)
		{
			fprintf(stderr, "table_reader.get_table_entry (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// creating a destroying a thread without adding it to the table
	step++;
	{
		thread = in->table_writer_ext->create_table_entry(ps->thread_table);
		if (!thread)
		{
			fprintf(stderr, "table_reader.create_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		in->table_writer_ext->destroy_table_entry(ps->thread_table, thread);
	}

	// creating and adding a thread to the table
	step++;
	{
		thread = in->table_writer_ext->create_table_entry(ps->thread_table);
		if (!thread)
		{
			fprintf(stderr, "table_reader.create_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		tmp.s64 = s_new_thread_tid;
		thread = in->table_writer_ext->add_table_entry(ps->thread_table, &tmp, thread);
		if (!thread)
		{
			fprintf(stderr, "table_reader.add_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		auto size = in->table_reader_ext->get_table_size(ps->thread_table);
		if (size != 2)
		{
			fprintf(stderr, "table_reader.get_table_size (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		tmp.s64 = s_new_thread_tid;
		in->table_reader_ext->release_table_entry(ps->thread_table, &tmp);
	}

	// get newly-created thread
	step++;
	{
		tmp.s64 = s_new_thread_tid;
		thread = in->table_reader_ext->get_table_entry(ps->thread_table, &tmp);
		if (!thread)
		{
			fprintf(stderr, "table_reader.get_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
	}

	// read and write from newly-created thread (static field)
	step++;
	{
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_static_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (strcmp("", tmp.str))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
		tmp.str = "hello";
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_static_field, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_static_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (strcmp("hello", tmp.str))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// read and write from newly-created thread (dynamic field)
	step++;
	{
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (tmp.u64 != 0)
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}
		tmp.u64 = 5;
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (SS_PLUGIN_SUCCESS != in->table_reader_ext->read_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		if (tmp.u64 != 5)
		{
			fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", step);
			exit(1);
		}

		tmp.s64 = s_new_thread_tid;
		in->table_reader_ext->release_table_entry(ps->thread_table, &tmp);
	}

	// erasing an unknown thread
	step++;
	{
		tmp.s64 = 10;
		if (SS_PLUGIN_SUCCESS == in->table_writer_ext->erase_table_entry(ps->thread_table, &tmp))
		{
			fprintf(stderr, "table_reader.erase_table_entry (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// loop over all threads, we expect to only find two (init, and our new one)
	step++;
	{
		struct iterate_entries_state
		{
			int* step = nullptr;
			uint64_t count = 0;
			const ss_plugin_event_parse_input *in = nullptr;
			plugin_state* ps = nullptr;
		};

		// successful iteration
		iterate_entries_state its1;
		its1.in = in;
		its1.ps = ps;
		its1.step = &step;
		auto it1 = [](ss_plugin_table_iterator_state_t* s, ss_plugin_table_entry_t* e) -> ss_plugin_bool
		{
			auto st = (iterate_entries_state*) s;
			st->count++;

			ss_plugin_state_data val;
			if (SS_PLUGIN_SUCCESS != st->in->table_reader_ext->read_entry_field(st->ps->thread_table, e, st->ps->thread_static_field, &val))
			{
				fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", (*st->step), st->in->get_owner_last_error(st->in->owner));
				exit(1);
			}
			if (strcmp(val.str, "init") == 0 || strcmp(val.str, "hello") == 0)
			{
				if (SS_PLUGIN_SUCCESS != st->in->table_reader_ext->read_entry_field(st->ps->thread_table, e, st->ps->thread_dynamic_field, &val))
				{
					fprintf(stderr, "table_reader.read_entry_field (%d) failure: %s\n", (*st->step), st->in->get_owner_last_error(st->in->owner));
					exit(1);
				}
				if (val.u64 != 5)
				{
					fprintf(stderr, "table_reader.read_entry_field (%d) inconsistency\n", (*st->step));
					exit(1);
				}
			}
			else
			{
				fprintf(stderr, "table_reader.read_entry_field (%d) unexpected value: %s\n", (*st->step), val.str);
				exit(1);
			}

			return 1;
		};
		if (in->table_reader_ext->iterate_entries(ps->thread_table, it1, (ss_plugin_table_iterator_state_t*) &its1) != 1)
		{
			fprintf(stderr, "table_reader.iterate_entries (%d) unexpected break-out\n", step);
			exit(1);
		}
		if (its1.count != 2)
		{
			fprintf(stderr, "table_reader.iterate_entries (%d) unexpected count result\n", step);
			exit(1);
		}

		// iteration with break-out
		auto it2 = [](ss_plugin_table_iterator_state_t* s, ss_plugin_table_entry_t* e) -> ss_plugin_bool
		{
			return false;
		};
		if (in->table_reader_ext->iterate_entries(ps->thread_table, it2, (ss_plugin_table_iterator_state_t*) &its1) != 0)
		{
			fprintf(stderr, "table_reader.iterate_entries (%d) break-out was expected\n", step);
			exit(1);
		}
	}

	// erase newly-created thread
	step++;
	{
		tmp.s64 = s_new_thread_tid;
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->erase_table_entry(ps->thread_table, &tmp))
		{
			fprintf(stderr, "table_reader.erase_table_entry (%d) inconsistency\n", step);
			exit(1);
		}
	}

	// revert edits made to existing thread
	step++;
	{
		tmp.s64 = 1;
		thread = in->table_reader_ext->get_table_entry(ps->thread_table, &tmp);
		if (!thread)
		{
			fprintf(stderr, "table_reader.get_table_entry (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		tmp.u64 = 0;
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_dynamic_field, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		tmp.str = "";
		if (SS_PLUGIN_SUCCESS != in->table_writer_ext->write_entry_field(ps->thread_table, thread, ps->thread_dynamic_field_str, &tmp))
		{
			fprintf(stderr, "table_reader.write_entry_field (%d) failure: %s\n", step, in->get_owner_last_error(in->owner));
			exit(1);
		}
		tmp.s64 = 1;
		in->table_reader_ext->release_table_entry(ps->thread_table, &tmp);
	}

	return SS_PLUGIN_SUCCESS;
}

void get_plugin_api_sample_tables(plugin_api& out)
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
