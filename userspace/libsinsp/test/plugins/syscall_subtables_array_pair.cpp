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

struct plugin_state {
	std::string lasterr;
	ss_plugin_table_t* thread_table;

	ss_plugin_table_field_t* table_field_cgroupstable;
	ss_plugin_table_field_t* table_field_cgroupstable_first;
	ss_plugin_table_field_t* table_field_cgroupstable_second;

	uint8_t step = 0;
};

const char* plugin_get_required_api_version() {
	return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version() {
	return "0.1.0";
}

const char* plugin_get_name() {
	return "sample_subtables_array_pair";
}

const char* plugin_get_description() {
	return "some desc";
}

const char* plugin_get_contact() {
	return "some contact";
}

const char* plugin_get_parse_event_sources() {
	return "[\"syscall\"]";
}

uint16_t* plugin_get_parse_event_types(uint32_t* num_types, ss_plugin_t* s) {
	static uint16_t types[] = {PPME_SYSCALL_OPEN_E};
	*num_types = sizeof(types) / sizeof(uint16_t);
	return &types[0];
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc) {
	*rc = SS_PLUGIN_SUCCESS;
	auto ret = new plugin_state();

	if(!in || !in->tables) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "invalid config input";
		return ret;
	}

	// get an accessor to the threads table
	ret->thread_table =
	        in->tables->get_table(in->owner, "threads", ss_plugin_state_type::SS_PLUGIN_ST_INT64);
	if(!ret->thread_table) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't access thread table";
		return ret;
	}

	// get an accessor to the file descriptor tables owned by each thread info
	ret->table_field_cgroupstable =
	        in->tables->fields.get_table_field(ret->thread_table,
	                                           "cgroups",
	                                           ss_plugin_state_type::SS_PLUGIN_ST_TABLE);
	if(!ret->table_field_cgroupstable) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't get cgroupstable field in thread table";
		return ret;
	}

	// create a new thread info -- the purpose is just to access its file
	// descriptor table and obtain accessors for fields of that sub-table
	auto entry = in->tables->writer_ext->create_table_entry(ret->thread_table);
	if(!entry) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't create subtable entry (init-time)";
		return ret;
	}

	// read pointer to file descriptor table owned by the new thread info
	ss_plugin_state_data data;
	*rc = in->tables->reader_ext->read_entry_field(ret->thread_table,
	                                               entry,
	                                               ret->table_field_cgroupstable,
	                                               &data);
	if(*rc != SS_PLUGIN_SUCCESS) {
		ret->lasterr = "can't read sub-table table entry field (init-time)";
		return ret;
	}
	auto cgroupstable = data.table;

	// obtain accessor to one of the fields of file descriptor tables (name)
	ret->table_field_cgroupstable_first =
	        in->tables->fields_ext->get_table_field(cgroupstable,
	                                                "first",
	                                                ss_plugin_state_type::SS_PLUGIN_ST_STRING);
	if(!ret->table_field_cgroupstable_first) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't get sub-table 'first' field";
		return ret;
	}

	ret->table_field_cgroupstable_second =
	        in->tables->fields_ext->get_table_field(cgroupstable,
	                                                "second",
	                                                ss_plugin_state_type::SS_PLUGIN_ST_STRING);
	if(!ret->table_field_cgroupstable_second) {
		*rc = SS_PLUGIN_FAILURE;
		ret->lasterr = "can't get sub-table 'second' field";
		return ret;
	}

	// once we're done, destroy the temporarily-created thread info
	in->tables->writer_ext->destroy_table_entry(ret->thread_table, entry);

	return ret;
}

void plugin_destroy(ss_plugin_t* s) {
	delete reinterpret_cast<plugin_state*>(s);
}

const char* plugin_get_last_error(ss_plugin_t* s) {
	return ((plugin_state*)s)->lasterr.c_str();
}

ss_plugin_rc plugin_parse_event(ss_plugin_t* s,
                                const ss_plugin_event_input* ev,
                                const ss_plugin_event_parse_input* in) {
	auto ps = reinterpret_cast<plugin_state*>(s);
	ss_plugin_state_data key;
	ss_plugin_state_data out;
	ss_plugin_state_data data;

	key.s64 = ev->evt->tid;
	ss_plugin_table_entry_t* tinfo = in->table_reader_ext->get_table_entry(ps->thread_table, &key);
	if(!tinfo) {
		ps->lasterr = "can't get table entry";
		return SS_PLUGIN_FAILURE;
	}

	auto res = in->table_reader_ext->read_entry_field(ps->thread_table,
	                                                  tinfo,
	                                                  ps->table_field_cgroupstable,
	                                                  &out);
	if(res != SS_PLUGIN_SUCCESS) {
		ps->lasterr = "can't read table entry field";
		return SS_PLUGIN_FAILURE;
	}

	ss_plugin_table_t* cgroupstable = out.table;

	// add entries to the cgroupstable
	if(ps->step == 0) {
		int max_iterations = 10;
		for(int i = 0; i < max_iterations; i++) {
			auto nentry = in->table_writer_ext->create_table_entry(cgroupstable);
			if(!nentry) {
				ps->lasterr = "can't create subtable entry";
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}
			key.s64 = i;
			nentry = in->table_writer_ext->add_table_entry(cgroupstable, &key, nentry);
			if(!nentry) {
				ps->lasterr = "can't add subtable entry";
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}

			data.str = "hello";
			res = in->table_reader_ext->read_entry_field(cgroupstable,
			                                             nentry,
			                                             ps->table_field_cgroupstable_first,
			                                             &data);
			if(res != SS_PLUGIN_SUCCESS) {
				ps->lasterr = "can't read subtable entry first field: " +
				              std::string(in->get_owner_last_error(in->owner));
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}
			if(strcmp(data.str, "") != 0) {
				ps->lasterr = "wrong string read from subtable entry first field: " +
				              std::string(data.str);
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}

			data.str = "hello";
			res = in->table_reader_ext->read_entry_field(cgroupstable,
			                                             nentry,
			                                             ps->table_field_cgroupstable_second,
			                                             &data);
			if(res != SS_PLUGIN_SUCCESS) {
				ps->lasterr = "can't read subtable entry second field: " +
				              std::string(in->get_owner_last_error(in->owner));
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}
			if(strcmp(data.str, "") != 0) {
				ps->lasterr = "wrong string read from subtable entry second field: " +
				              std::string(data.str);
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}

			data.str = "hello";
			res = in->table_writer_ext->write_entry_field(cgroupstable,
			                                              nentry,
			                                              ps->table_field_cgroupstable_first,
			                                              &data);
			if(res != SS_PLUGIN_SUCCESS) {
				ps->lasterr = "can't write subtable entry first field: " +
				              std::string(in->get_owner_last_error(in->owner));
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}

			data.str = "world";
			res = in->table_writer_ext->write_entry_field(cgroupstable,
			                                              nentry,
			                                              ps->table_field_cgroupstable_second,
			                                              &data);
			if(res != SS_PLUGIN_SUCCESS) {
				ps->lasterr = "can't write subtable entry second field: " +
				              std::string(in->get_owner_last_error(in->owner));
				printf("ERR %s\n", ps->lasterr.c_str());
				return SS_PLUGIN_FAILURE;
			}

			in->table_reader_ext->release_table_entry(cgroupstable, nentry);
		}

		ps->step++;
		in->table_reader_ext->release_table_entry(ps->thread_table, tinfo);
		return SS_PLUGIN_SUCCESS;
	}

	// remove one entry from the cgroupstable
	if(ps->step == 1) {
		key.s64 = 0;
		res = in->table_writer_ext->erase_table_entry(cgroupstable, &key);
		if(res != SS_PLUGIN_SUCCESS) {
			ps->lasterr = "can't erase subtable entry";
			printf("ERR %s\n", ps->lasterr.c_str());
			return SS_PLUGIN_FAILURE;
		}

		ps->step++;
		in->table_reader_ext->release_table_entry(ps->thread_table, tinfo);
		return SS_PLUGIN_SUCCESS;
	}

	// clear the cgroupstable
	if(ps->step == 2) {
		res = in->table_writer_ext->clear_table(cgroupstable);
		if(res != SS_PLUGIN_SUCCESS) {
			ps->lasterr = "can't clear subtable";
			printf("ERR %s\n", ps->lasterr.c_str());
			return SS_PLUGIN_FAILURE;
		}

		ps->step++;
		in->table_reader_ext->release_table_entry(ps->thread_table, tinfo);
		return SS_PLUGIN_SUCCESS;
	}

	return SS_PLUGIN_SUCCESS;
}

}  // namespace

void get_plugin_api_sample_syscall_subtables_array_pair(plugin_api& out) {
	memset(&out, 0, sizeof(plugin_api));
	out.static_plugin_abi_version = PLUGIN_ABI_VERSION;
	out.static_plugin_api_size = sizeof(plugin_api);
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
