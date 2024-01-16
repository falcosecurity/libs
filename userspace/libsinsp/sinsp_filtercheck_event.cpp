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

#include <math.h>

#include <libsinsp/sinsp_filtercheck_event.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_manager.h>
#include <libsinsp/value_parser.h>

using namespace std;

extern sinsp_evttables g_infotables;

#define UESTORAGE_INITIAL_BUFSIZE 256

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

#define RETURN_EXTRACT_PTR(x) do {  \
        *len = sizeof(*(x));        \
        return (uint8_t*) (x);      \
} while(0)

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

#define RETURN_EXTRACT_CSTR(x) do {             \
        if((x))                                 \
        {                                       \
                *len = strlen((char *) ((x)));  \
        }                                       \
        return (uint8_t*) ((x));                \
} while(0)

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

const filtercheck_field_info sinsp_filter_check_event_fields[] =
{
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency", "Latency", "delta between an exit event and the correspondent enter event, in nanoseconds."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency.s", "Latency (s)", "integer part of the event latency delta."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.latency.ns", "Latency (ns)", "fractional part of the event latency delta."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.latency.quantized", "Quantized Latency", "10-base log of the delta between an exit event and the correspondent enter event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.latency.human", "Human-Readable Latency", "delta between an exit event and the correspondent enter event, as a human readable string (e.g. 10.3ms)."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.deltatime", "Delta", "delta between this event and the previous event, in nanoseconds."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.deltatime.s", "Delta (s)", "integer part of the delta between this event and the previous event."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.deltatime.ns", "Delta (ns)", "fractional part of the delta between this event and the previous event."},
	{PT_CHARBUF, EPF_PRINT_ONLY, PF_NA, "evt.outputtime", "Output Time", "this depends on -t param, default is %evt.time ('h')."},
	{PT_CHARBUF, EPF_NONE, PF_DIR, "evt.dir", "Direction", "event direction can be either '>' for enter events or '<' for exit events."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.type", "Type", "The name of the event (e.g. 'open')."},
	{PT_UINT32, EPF_ARG_REQUIRED, PF_NA, "evt.type.is", "Type Is", "allows one to specify an event type, and returns 1 for events that are of that type. For example, evt.type.is.open returns 1 for open events, 0 for any other event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "syscall.type", "Syscall Type", "For system call events, the name of the system call (e.g. 'open'). Unset for other events (e.g. switch or internal events). Use this field instead of evt.type if you need to make sure that the filtered/printed value is actually a system call."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.category", "Category", "The event category. Example values are 'file' (for file operations like open and close), 'net' (for network operations like socket and bind), memory (for things like brk or mmap), and so on."},
	{PT_INT16, EPF_NONE, PF_ID, "evt.cpu", "CPU Number", "number of the CPU where this event happened."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.args", "Arguments", "all the event arguments, aggregated into a single string."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "evt.arg", "Argument", "one of the event arguments specified by name or by number. Some events (e.g. return codes or FDs) will be converted into a text representation when possible. E.g. 'evt.arg.fd' or 'evt.arg[0]'."},
	{PT_DYN, EPF_ARG_REQUIRED, PF_NA, "evt.rawarg", "Raw Argument", "one of the event arguments specified by name. E.g. 'evt.rawarg.fd'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.info", "Information", "for most events, this field returns the same value as evt.args. However, for some events (like writes to /dev/log) it provides higher level information coming from decoding the arguments."},
	{PT_BYTEBUF, EPF_NONE, PF_NA, "evt.buffer", "Buffer", "the binary data buffer for events that have one, like read(), recvfrom(), etc. Use this field in filters with 'contains' to search into I/O data buffers."},
	{PT_UINT64, EPF_NONE, PF_DEC, "evt.buflen", "Buffer Length", "the length of the binary data buffer for events that have one, like read(), recvfrom(), etc."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "evt.res", "Return Value", "event return value, as a string. If the event failed, the result is an error code string (e.g. 'ENOENT'), otherwise the result is the string 'SUCCESS'."},
	{PT_INT64, EPF_NONE, PF_DEC, "evt.rawres", "Raw Return Value", "event return value, as a number (e.g. -2). Useful for range comparisons."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.failed", "Failed", "'true' for events that returned an error status."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io", "Is I/O", "'true' for events that read or write to FDs, like read(), send, recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_read", "Is Read", "'true' for events that read from FDs, like read(), recv(), recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_write", "Is Write", "'true' for events that write to FDs, like write(), send(), etc."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.io_dir", "I/O Direction", "'r' for events that read from FDs, like read(); 'w' for events that write to FDs, like write()."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_wait", "Is Wait", "'true' for events that make the thread wait, e.g. sleep(), select(), poll()."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.wait_latency", "Wait Latency", "for events that make the thread wait (e.g. sleep(), select(), poll()), this is the time spent waiting for the event to return, in nanoseconds."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_syslog", "Is Syslog", "'true' for events that are writes to /dev/log."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count", "Count", "This filter field always returns 1 and can be used to count events from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.error", "Error Count", "This filter field returns 1 for events that returned with an error, and can be used to count event failures from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.error.file", "File Error Count", "This filter field returns 1 for events that returned with an error and are related to file I/O, and can be used to count event failures from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.error.net", "Network Error Count", "This filter field returns 1 for events that returned with an error and are related to network I/O, and can be used to count event failures from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.error.memory", "Memory Error Count", "This filter field returns 1 for events that returned with an error and are related to memory allocation, and can be used to count event failures from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.error.other", "Other Error Count", "This filter field returns 1 for events that returned with an error and are related to none of the previous categories, and can be used to count event failures from inside chisels."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count.exit", "Exit Count", "This filter field returns 1 for exit events, and can be used to count single events from inside chisels."},
	{PT_UINT32, EPF_TABLE_ONLY, PF_DEC, "evt.count.procinfo", "Procinfo Count", "This filter field returns 1 for procinfo events generated by process main threads, and can be used to count processes from inside views."},
	{PT_UINT32, EPF_TABLE_ONLY, PF_DEC, "evt.count.threadinfo", "Thread Info Count", "This filter field returns 1 for procinfo events, and can be used to count processes from inside views."},
	{PT_UINT64, (filtercheck_field_flags) (EPF_FILTER_ONLY | EPF_ARG_REQUIRED), PF_DEC, "evt.around", "Around Interval", "Accepts the event if it's around the specified time interval. The syntax is evt.around[T]=D, where T is the value returned by %evt.rawtime for the event and D is a delta in milliseconds. For example, evt.around[1404996934793590564]=1000 will return the events with timestamp with one second before the timestamp and one second after it, for a total of two seconds of capture."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "evt.abspath", "Absolute Path", "Absolute path calculated from dirfd and name during syscalls like renameat and symlinkat. Use 'evt.abspath.src' or 'evt.abspath.dst' for syscalls that support multiple paths."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.in", "Input Buffer Length", "the length of the binary data buffer, but only for input I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.out", "Output Buffer Length", "the length of the binary data buffer, but only for output I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.file", "File Buffer Length", "the length of the binary data buffer, but only for file I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.file.in", "File Input Buffer Length", "the length of the binary data buffer, but only for input file I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.file.out", "File Output Buffer Length", "the length of the binary data buffer, but only for output file I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.net", "Network Buffer Length", "the length of the binary data buffer, but only for network I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.net.in", "Network Input Buffer Length", "the length of the binary data buffer, but only for input network I/O events."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "evt.buflen.net.out", "Network Output Buffer Length", "the length of the binary data buffer, but only for output network I/O events."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_open_read", "Is Opened For Reading", "'true' for open/openat/openat2/open_by_handle_at events where the path was opened for reading"},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_open_write", "Is Opened For Writing", "'true' for open/openat/openat2/open_by_handle_at events where the path was opened for writing"},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "evt.infra.docker.name", "Docker Name", "for docker infrastructure events, the name of the event."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "evt.infra.docker.container.id", "Docker ID", "for docker infrastructure events, the id of the impacted container."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "evt.infra.docker.container.name", "Container Name", "for docker infrastructure events, the name of the impacted container."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "evt.infra.docker.container.image", "Container Image", "for docker infrastructure events, the image name of the impacted container."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_open_exec", "Is Created With Execute Permissions", "'true' for open/openat/openat2/open_by_handle_at or creat events where a file is created with execute permissions"},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_open_create", "Is Created", "'true' for for open/openat/openat2/open_by_handle_at events where a file is created."},
};

sinsp_filter_check_event::sinsp_filter_check_event()
{
	m_is_compare = false;
	m_info.m_name = "evt";
	m_info.m_shortdesc = "Syscall events only";
	m_info.m_desc = "Event fields applicable to syscall events. Note that for most events you can access the individual arguments/parameters of each syscall via evt.arg, e.g. evt.arg.filename.";
	m_info.m_fields = sinsp_filter_check_event_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_event_fields) / sizeof(sinsp_filter_check_event_fields[0]);
	m_u64val = 0;
	m_converter = new sinsp_filter_check_reference();

	m_storage_size = UESTORAGE_INITIAL_BUFSIZE;
	m_storage = (char*)malloc(m_storage_size);
	if(m_storage == NULL)
	{
		throw sinsp_exception("memory allocation error in sinsp_filter_check_appevt::sinsp_filter_check_event");
	}

	m_cargname = NULL;
}

sinsp_filter_check_event::~sinsp_filter_check_event()
{
	if(m_storage != NULL)
	{
		free(m_storage);
	}

	if(m_converter != NULL)
	{
		delete m_converter;
	}
}

sinsp_filter_check* sinsp_filter_check_event::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_event();
}

int32_t sinsp_filter_check_event::extract_arg(string fldname, string val, OUT const ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		if(parinfo != NULL)
		{
			throw sinsp_exception("evt.arg fields must be expressed explicitly");
		}

		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);

		if(m_field_id == TYPE_AROUND)
		{
			m_u64val = sinsp_numparser::parseu64(numstr);
		}
		else
		{
			m_argid = sinsp_numparser::parsed32(numstr);
		}

		parsed_len++;
	}
	else if(val[fldname.size()] == '.')
	{
		if(m_field_id == TYPE_AROUND)
		{
			throw sinsp_exception("wrong syntax for evt.around");
		}

		const ppm_param_info* pi =
			sinsp_utils::find_longest_matching_evt_param(val.substr(fldname.size() + 1));

		if(pi == NULL)
		{
			throw sinsp_exception("unknown event argument " + val.substr(fldname.size() + 1));
		}

		m_argname = pi->name;
		parsed_len = (uint32_t)(fldname.size() + strlen(pi->name) + 1);
		m_argid = -1;

		if(parinfo != NULL)
		{
			*parinfo = pi;
		}
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len;
}

int32_t sinsp_filter_check_event::extract_type(string fldname, string val, OUT const ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	if(val[fldname.size()] == '.')
	{
		string itype = val.substr(fldname.size() + 1);

		if(sinsp_numparser::tryparseu32(itype, &m_evtid))
		{
			m_evtid1 = PPM_EVENT_MAX;
			parsed_len = (uint32_t)(fldname.size() + itype.size() + 1);
			return parsed_len;
		}

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			const ppm_event_info* ei = &g_infotables.m_event_info[j];

			if(itype == ei->name)
			{
				m_evtid = j;
				m_evtid1 = j + 1;
				parsed_len = (uint32_t)(fldname.size() + strlen(ei->name) + 1);
				break;
			}
		}
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len;
}

int32_t sinsp_filter_check_event::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);
	int32_t res = 0;

	//
	// A couple of fields are handled in a custom way
	//
	if(STR_MATCH("evt.arg")  && !STR_MATCH("evt.args"))
	{
		m_field_id = TYPE_ARGSTR;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evt.arg", val, NULL);
	}
	else if(STR_MATCH("evt.rawarg"))
	{
		m_field_id = TYPE_ARGRAW;
		m_customfield = m_info.m_fields[m_field_id];
		m_field = &m_customfield;

		res = extract_arg("evt.rawarg", val, &m_arginfo);

		m_customfield.m_type = m_arginfo->type;
		m_customfield.m_print_format = m_arginfo->fmt;
	}
	else if(STR_MATCH("evt.around"))
	{
		m_field_id = TYPE_AROUND;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("evt.around", val, NULL);
	}
	else if(STR_MATCH("evt.latency") ||
		STR_MATCH("evt.latency.s") ||
		STR_MATCH("evt.latency.ns") ||
		STR_MATCH("evt.latency.quantized") ||
		STR_MATCH("evt.latency.human"))
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
	else if(STR_MATCH("evt.abspath"))
	{
		m_field_id = TYPE_ABSPATH;
		m_field = &m_info.m_fields[m_field_id];

		if(STR_MATCH("evt.abspath.src"))
		{
			m_argid = 1;
			res = sizeof("evt.abspath.src") - 1;
		}
		else if(STR_MATCH("evt.abspath.dst"))
		{
			m_argid = 2;
			res = sizeof("evt.abspath.dst") - 1;
		}
		else
		{
			m_argid = 0;
			res = sizeof("evt.abspath") - 1;
		}
	}
	else if(STR_MATCH("evt.type.is"))
	{
		m_field_id = TYPE_TYPE_IS;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_type("evt.type.is", val, NULL);
	}
	else
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}

	return res;
}

size_t sinsp_filter_check_event::parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len)
{
	size_t parsed_len;
	if(m_field_id == sinsp_filter_check_event::TYPE_ARGRAW)
	{
		ASSERT(m_arginfo != NULL);
		parsed_len = sinsp_filter_value_parser::string_to_rawval(str, len, filter_value_p(), filter_value()->size(), m_arginfo->type);
	}
	else
	{
		parsed_len = sinsp_filter_check::parse_filter_value(str, len, storage, storage_len);
	}

	validate_filter_value(str, parsed_len);

	return parsed_len;
}



void sinsp_filter_check_event::validate_filter_value(const char* str, uint32_t len)
{
	if(m_field_id == TYPE_TYPE)
	{
		sinsp_evttables* einfo = m_inspector->get_event_info_tables();
		const ppm_event_info* etable = einfo->m_event_info;
		string stype(str, len);

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			if(stype == etable[j].name)
			{
				return;
			}
		}

		for(uint16_t j = 0; j < PPM_SC_MAX; j++)
		{
			if(stype == scap_get_ppm_sc_name((ppm_sc_code)j))
			{
				return;
			}
		}

		// note: plugins can potentially define meta-events with a certain
		// name, which will be extracted as valid values for evt.type
		// we loop over all plugins and check if at least one defines a
		// meta-event with the given name
		for (auto& p : m_inspector->get_plugin_manager()->plugins())
		{
			if (p->caps() & CAP_ASYNC)
			{
				const auto& names = p->async_event_names();
				if (names.find(stype) != names.end())
				{
					return;
				}
			}
		}

		throw sinsp_exception("unknown event type " + stype);
	}
	else if(m_field_id == TYPE_AROUND)
	{
		if(m_cmpop != CO_EQ)
		{
			throw sinsp_exception("evt.around supports only '=' comparison operator");
		}

		m_tsdelta = sinsp_numparser::parseu64(str) * 1000000;

		return;
	}
}

const filtercheck_field_info* sinsp_filter_check_event::get_field_info() const
{
	if(m_field_id == TYPE_ARGRAW)
	{
		return &m_customfield;
	}
	else
	{
		return &m_info.m_fields[m_field_id];
	}
}

uint8_t* extract_argraw(sinsp_evt *evt, OUT uint32_t* len, const char *argname)
{
	const sinsp_evt_param* pi = evt->get_param_by_name(argname);

	if(pi != NULL)
	{
		*len = pi->m_len;
		return (uint8_t*)pi->m_val;
	}
	else
	{
		return NULL;
	}
}

uint8_t *sinsp_filter_check_event::extract_abspath(sinsp_evt *evt, OUT uint32_t *len)
{
	std::string spath;

	if(evt->m_tinfo == NULL)
	{
		return NULL;
	}

	uint16_t etype = evt->get_type();

	const char *dirfdarg = NULL, *patharg = NULL;
	if(etype == PPME_SYSCALL_RENAMEAT_X || etype == PPME_SYSCALL_RENAMEAT2_X)
	{
		if(m_argid == 0 || m_argid == 1)
		{
			dirfdarg = "olddirfd";
			patharg = "oldpath";
		}
		else if(m_argid == 2)
		{
			dirfdarg = "newdirfd";
			patharg = "newpath";
		}
	}
	else if(etype == PPME_SYSCALL_SYMLINKAT_X)
	{
		dirfdarg = "linkdirfd";
		patharg = "linkpath";
	}
	else if(etype == PPME_SYSCALL_OPENAT_E || etype == PPME_SYSCALL_OPENAT_2_X || etype == PPME_SYSCALL_OPENAT2_X)
	{
		dirfdarg = "dirfd";
		patharg = "name";
	}
	else if(etype == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X)
	{
		int fd = 0;
		std::string fullname;

		//
		// We can extract the file path only in case of a successful file opening (fd>0).
		//
		fd = evt->get_param(0)->as<int64_t>();

		if(fd>0)
		{
			//
			// Get the file path directly from the ring buffer.
			// concatenate_paths takes care of resolving the path
			//
			m_strstorage = sinsp_utils::concatenate_paths("", evt->get_param(3)->as<std::string_view>());

			RETURN_EXTRACT_STRING(m_strstorage);
		}
	}
	else if(etype == PPME_SYSCALL_LINKAT_E || etype == PPME_SYSCALL_LINKAT_2_X)
	{
		if(m_argid == 0 || m_argid == 1)
		{
			dirfdarg = "olddir";
			patharg = "oldpath";
		}
		else if(m_argid == 2)
		{
			dirfdarg = "newdir";
			patharg = "newpath";
		}
	}
	else if(etype == PPME_SYSCALL_UNLINKAT_E || etype == PPME_SYSCALL_UNLINKAT_2_X)
	{
		dirfdarg = "dirfd";
		patharg = "name";
	}
	else if(etype == PPME_SYSCALL_MKDIRAT_X)
	{
		dirfdarg = "dirfd";
		patharg = "path";
	}
	else if(etype == PPME_SYSCALL_FCHMODAT_X)
	{
		dirfdarg = "dirfd";
		patharg = "filename";
	}
	else if(etype == PPME_SYSCALL_FCHOWNAT_X)
	{
		dirfdarg = "dirfd";
		patharg = "pathname";
	}

	if(!dirfdarg || !patharg)
	{
		return 0;
	}

	int dirfdargidx = -1, pathargidx = -1, idx = 0;
	while (((dirfdargidx < 0) || (pathargidx < 0)) && (idx < (int) evt->get_num_params()))
	{
		const char *name = evt->get_param_name(idx);
		if((dirfdargidx < 0) && (strcmp(name, dirfdarg) == 0))
		{
			dirfdargidx = idx;
		}
		if((pathargidx < 0) && (strcmp(name, patharg) == 0))
		{
			pathargidx = idx;
		}
		idx++;
	}

	if((dirfdargidx < 0) || (pathargidx < 0))
	{
		return 0;
	}

	int64_t dirfd = evt->get_param(dirfdargidx)->as<int64_t>();

	std::string_view path = evt->get_param(pathargidx)->as<std::string_view>();

	string sdir;

	bool is_absolute = (path[0] == '/');
	if(is_absolute)
	{
		//
		// The path is absolute.
		// Some processes (e.g. irqbalance) actually do this: they pass an invalid fd and
		// and absolute path, and openat succeeds.
		//
		sdir = ".";
	}
	else if(dirfd == PPM_AT_FDCWD)
	{
		sdir = evt->m_tinfo->get_cwd();
	}
	else
	{
		evt->m_fdinfo = evt->m_tinfo->get_fd(dirfd);

		if(evt->m_fdinfo == NULL)
		{
			ASSERT(false);
			sdir = "<UNKNOWN>/";
		}
		else
		{
			if(evt->m_fdinfo->m_name[evt->m_fdinfo->m_name.length()] == '/')
			{
				sdir = evt->m_fdinfo->m_name;
			}
			else
			{
				sdir = evt->m_fdinfo->m_name + '/';
			}
		}
	}

	m_strstorage = sinsp_utils::concatenate_paths(sdir, path);

	RETURN_EXTRACT_STRING(m_strstorage);
}

inline uint8_t* sinsp_filter_check_event::extract_buflen(sinsp_evt *evt, OUT uint32_t* len)
{
	if(evt->get_direction() == SCAP_ED_OUT)
	{
		//
		// Extract the return value
		//
		m_s64val = evt->get_param(0)->as<int64_t>();

		if(m_s64val >= 0)
		{
			RETURN_EXTRACT_VAR(m_s64val);
		}
	}

	return NULL;
}

Json::Value sinsp_filter_check_event::extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
{
	switch(m_field_id)
	{
	case TYPE_RUNTIME_TIME_OUTPUT_FORMAT:
		return (Json::Value::Int64)evt->get_ts();

	case TYPE_LATENCY:
	case TYPE_LATENCY_S:
	case TYPE_LATENCY_NS:
	case TYPE_DELTA:
	case TYPE_DELTA_S:
	case TYPE_DELTA_NS:
		return (Json::Value::Int64)*(uint64_t*)extract(evt, len);
	case TYPE_COUNT:
		m_u32val = 1;
		return m_u32val;

	default:
		return Json::nullValue;
	}

	return Json::nullValue;
}

uint8_t* sinsp_filter_check_event::extract_error_count(sinsp_evt *evt, OUT uint32_t* len)
{
	const sinsp_evt_param* pi = evt->get_param_by_name("res");

	if(pi != NULL)
	{
		ASSERT(pi->m_len == sizeof(uint64_t));

		int64_t res = *(int64_t*)pi->m_val;
		if(res < 0)
		{
			m_u32val = 1;
			RETURN_EXTRACT_VAR(m_u32val);
		}
		else
		{
			return NULL;
		}
	}

	if((evt->get_info_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
	{
		pi = evt->get_param_by_name("fd");

		if(pi != NULL)
		{
			ASSERT(pi->m_len == sizeof(uint64_t));

			int64_t res = *(int64_t*)pi->m_val;
			if(res < 0)
			{
				m_u32val = 1;
				RETURN_EXTRACT_VAR(m_u32val);
			}
		}
	}

	return NULL;
}

uint8_t* sinsp_filter_check_event::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	switch(m_field_id)
	{
	case TYPE_LATENCY:
		{
			m_u64val = 0;

			if(evt->m_tinfo != NULL)
			{
				ppm_event_category ecat = evt->get_category();
				if(ecat & EC_INTERNAL)
				{
					return NULL;
				}

				m_u64val = evt->m_tinfo->m_latency;
			}

			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_LATENCY_HUMAN:
		{
			m_u64val = 0;

			if(evt->m_tinfo != NULL)
			{
				ppm_event_category ecat = evt->get_category();
				if(ecat & EC_INTERNAL)
				{
					return NULL;
				}

				m_converter->set_val(PT_RELTIME,
					EPF_NONE,
					(uint8_t*)&evt->m_tinfo->m_latency,
					8,
					0,
					ppm_print_format::PF_DEC);

				m_strstorage = m_converter->tostring_nice(NULL, 0, 1000000000);
			}

			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_LATENCY_S:
	case TYPE_LATENCY_NS:
		{
			m_u64val = 0;

			if(evt->m_tinfo != NULL)
			{
				ppm_event_category ecat = evt->get_category();
				if(ecat & EC_INTERNAL)
				{
					return NULL;
				}

				uint64_t lat = evt->m_tinfo->m_latency;

				if(m_field_id == TYPE_LATENCY_S)
				{
					m_u64val = lat / 1000000000;
				}
				else
				{
					m_u64val = lat % 1000000000;
				}
			}

			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_LATENCY_QUANTIZED:
		{
			if(evt->m_tinfo != NULL)
			{
				ppm_event_category ecat = evt->get_category();
				if(ecat & EC_INTERNAL)
				{
					return NULL;
				}

				uint64_t lat = evt->m_tinfo->m_latency;
				if(lat != 0)
				{
					double llatency = log10((double)lat);

					if(llatency > 11)
					{
						llatency = 11;
					}

					m_u64val = (uint64_t)(llatency * m_inspector->get_quantization_interval() / 11) + 1;

					RETURN_EXTRACT_VAR(m_u64val);
				}
			}

			return NULL;
		}
	case TYPE_DELTA:
	case TYPE_DELTA_S:
	case TYPE_DELTA_NS:
		{
			if(m_u64val == 0)
			{
				m_u64val = evt->get_ts();
				m_tsdelta = 0;
			}
			else
			{
				uint64_t tts = evt->get_ts();

				if(m_field_id == TYPE_DELTA)
				{
					m_tsdelta = tts - m_u64val;
				}
				else if(m_field_id == TYPE_DELTA_S)
				{
					m_tsdelta = (tts - m_u64val) / ONE_SECOND_IN_NS;
				}
				else if(m_field_id == TYPE_DELTA_NS)
				{
					m_tsdelta = (tts - m_u64val) % ONE_SECOND_IN_NS;
				}

				m_u64val = tts;
			}

			RETURN_EXTRACT_VAR(m_tsdelta);
		}
	case TYPE_RUNTIME_TIME_OUTPUT_FORMAT:
		{
			char timebuffer[100];
			m_strstorage = "";
			switch(m_inspector->m_output_time_flag)
			{
				case 'h':
					sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, true);
					RETURN_EXTRACT_STRING(m_strstorage);

				case 'a':
					m_strstorage += to_string(evt->get_ts() / ONE_SECOND_IN_NS);
					m_strstorage += ".";
					m_strstorage += to_string(evt->get_ts() % ONE_SECOND_IN_NS);
					RETURN_EXTRACT_STRING(m_strstorage);

				case 'r':
					m_strstorage += to_string((evt->get_ts() - m_inspector->m_firstevent_ts) / ONE_SECOND_IN_NS);
					m_strstorage += ".";
					snprintf(timebuffer, sizeof(timebuffer), "%09llu", (evt->get_ts() - m_inspector->m_firstevent_ts) % ONE_SECOND_IN_NS);
					m_strstorage += string(timebuffer);
					RETURN_EXTRACT_STRING(m_strstorage);

				case 'd':
				{
					if(evt->m_tinfo != NULL)
					{
						long long unsigned lat = evt->m_tinfo->m_latency;

						m_strstorage += to_string(lat / 1000000000);
						m_strstorage += ".";
						snprintf(timebuffer, sizeof(timebuffer), "%09llu", lat % 1000000000);
						m_strstorage += string(timebuffer);
					}
					else
					{
						m_strstorage = "0.000000000";
					}

					RETURN_EXTRACT_STRING(m_strstorage);
				}

				case 'D':
					if(m_u64val == 0)
					{
						m_u64val = evt->get_ts();
						m_tsdelta = 0;
					}
					uint64_t tts = evt->get_ts();

					m_strstorage += to_string((tts - m_u64val) / ONE_SECOND_IN_NS);
					m_tsdelta = (tts - m_u64val) / ONE_SECOND_IN_NS;
					m_strstorage += ".";
					snprintf(timebuffer, sizeof(timebuffer), "%09llu", (tts - m_u64val) % ONE_SECOND_IN_NS);
					m_strstorage += string(timebuffer);
					m_tsdelta = (tts - m_u64val) % ONE_SECOND_IN_NS;

					m_u64val = tts;
					RETURN_EXTRACT_STRING(m_strstorage);
			}
		}
	case TYPE_DIR:
		if(PPME_IS_ENTER(evt->get_type()))
		{
			RETURN_EXTRACT_CSTR(">");
		}
		else
		{
			RETURN_EXTRACT_CSTR("<");
		}
	case TYPE_TYPE:
		{
			uint8_t* evname;
			uint16_t etype = evt->m_pevt->type;

			if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
			{
				uint16_t ppm_sc = evt->get_param(0)->as<uint16_t>();

				// Only generic enter event has the nativeID as second param
				if(m_inspector && m_inspector->is_capture() && ppm_sc == PPM_SC_UNKNOWN && etype == PPME_GENERIC_E)
				{
					// try to enforce a forward compatibility for syscalls added
					// after a scap file was generated,
					// by looking up using nativeID.
					// Of course, this will only reliably work for
					// same architecture scap capture->replay.
					uint16_t nativeid = evt->get_param(1)->as<uint16_t>();
					ppm_sc = scap_native_id_to_ppm_sc(nativeid);
				}
				evname = (uint8_t*)scap_get_ppm_sc_name((ppm_sc_code)ppm_sc);
			}
			else
			{
				// note: for async events, the event name is encoded
				// inside the event itself. In this case libsinsp's evt.type
				// field acts as an alias of evt.asynctype.
				if (etype == PPME_ASYNCEVENT_E)
				{
					evname = (uint8_t*) evt->get_param(1)->m_val;
				}
				else
				{
					evname = (uint8_t*)evt->get_name();
				}
			}

			RETURN_EXTRACT_CSTR(evname);
		}
		break;
	case TYPE_TYPE_IS:
		{
			uint16_t etype = evt->m_pevt->type;

			if(etype == m_evtid || etype == m_evtid1)
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}
		break;
	case TYPE_SYSCALL_TYPE:
		{
			uint8_t* evname;
			ppm_event_code etype = (ppm_event_code)evt->m_pevt->type;
			if(!libsinsp::events::is_syscall_event(etype))
			{
				return NULL;
			}

			if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
			{
				uint16_t ppm_sc = evt->get_param(0)->as<uint16_t>();

				// Only generic enter event has the nativeID as second param
				if (m_inspector && m_inspector->is_capture() && ppm_sc == PPM_SC_UNKNOWN && etype == PPME_GENERIC_E)
				{
					// try to enforce a forward compatibility for syscalls added
					// after a scap file was generated,
					// by looking up using nativeID.
					// Of course, this will only reliably work for
					// same architecture scap capture->replay.
					uint16_t nativeid = evt->get_param(1)->as<uint16_t>();
					ppm_sc = scap_native_id_to_ppm_sc(nativeid);
				}
				evname = (uint8_t*)scap_get_ppm_sc_name((ppm_sc_code)ppm_sc);
			}
			else
			{
				evname = (uint8_t*)evt->get_name();
			}

			RETURN_EXTRACT_CSTR(evname);
		}
		break;
	case TYPE_CATEGORY:
		sinsp_evt::category cat;
		evt->get_category(&cat);

		switch(cat.m_category)
		{
		case EC_UNKNOWN:
			m_strstorage = "unknown";
			break;
		case EC_OTHER:
			m_strstorage = "other";
			break;
		case EC_FILE:
			m_strstorage = "file";
			break;
		case EC_NET:
			m_strstorage = "net";
			break;
		case EC_IPC:
			m_strstorage = "IPC";
			break;
		case EC_MEMORY:
			m_strstorage = "memory";
			break;
		case EC_PROCESS:
			m_strstorage = "process";
			break;
		case EC_SLEEP:
			m_strstorage = "sleep";
			break;
		case EC_SYSTEM:
			m_strstorage = "system";
			break;
		case EC_SIGNAL:
			m_strstorage = "signal";
			break;
		case EC_USER:
			m_strstorage = "user";
			break;
		case EC_TIME:
			m_strstorage = "time";
			break;
		case EC_PROCESSING:
			m_strstorage = "processing";
			break;
		case EC_IO_READ:
		case EC_IO_WRITE:
		case EC_IO_OTHER:
		{
			switch(cat.m_subcategory)
			{
			case sinsp_evt::SC_FILE:
				m_strstorage = "file";
				break;
			case sinsp_evt::SC_NET:
				m_strstorage = "net";
				break;
			case sinsp_evt::SC_IPC:
				m_strstorage = "ipc";
				break;
			case sinsp_evt::SC_NONE:
			case sinsp_evt::SC_UNKNOWN:
			case sinsp_evt::SC_OTHER:
				m_strstorage = "unknown";
				break;
			default:
				ASSERT(false);
				m_strstorage = "unknown";
				break;
			}
		}
		break;
		case EC_WAIT:
			m_strstorage = "wait";
			break;
		case EC_SCHEDULER:
			m_strstorage = "scheduler";
			break;
		case EC_INTERNAL:
			m_strstorage = "internal";
			break;
		case EC_SYSCALL:
			m_strstorage = "syscall";
			break;
		case EC_TRACEPOINT:
			m_strstorage = "tracepoint";
			break;
		case EC_PLUGIN:
			m_strstorage = "plugin";
			break;
		case EC_METAEVENT:
			m_strstorage = "meta";
			break;
		default:
			m_strstorage = "unknown";
			break;
		}

		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_CPU:
		RETURN_EXTRACT_VAR(evt->m_cpuid);
	case TYPE_ARGRAW:
		return extract_argraw(evt, len, m_arginfo->name);
		break;
	case TYPE_ARGSTR:
		{
			const char* resolved_argstr;
			const char* argstr;

			ASSERT(m_inspector != NULL);

			if(m_argid != -1)
			{
				if(m_argid >= (int32_t)evt->get_num_params())
				{
					return NULL;
				}

				argstr = evt->get_param_as_str(m_argid, &resolved_argstr, m_inspector->get_buffer_format());
			}
			else
			{
				argstr = evt->get_param_value_str(m_argname.c_str(), &resolved_argstr, m_inspector->get_buffer_format());
			}

			if(resolved_argstr != NULL && resolved_argstr[0] != 0)
			{
				RETURN_EXTRACT_CSTR(resolved_argstr);
			}
			else
			{
				RETURN_EXTRACT_CSTR(argstr);
			}
		}
		break;
	case TYPE_INFO:
		{
			if(m_inspector->m_parser->get_syslog_decoder().is_data_valid())
			{
				// syslog is actually the only info line we support up until now
				m_strstorage = m_inspector->m_parser->get_syslog_decoder().get_info_line();
				RETURN_EXTRACT_STRING(m_strstorage);
			}
		}
		//
		// NOTE: this falls through to TYPE_ARGSTR, and that's what we want!
		//       Please don't add anything here!
		//
	case TYPE_ARGS:
		{
			if(evt->get_type() == PPME_GENERIC_E || evt->get_type() == PPME_GENERIC_X)
			{
				//
				// Don't print the arguments for generic events: they have only internal use
				//
				RETURN_EXTRACT_CSTR("");
			}

			const char* resolved_argstr = NULL;
			const char* argstr = NULL;
			uint32_t nargs = evt->get_num_params();
			m_strstorage.clear();

			for(uint32_t j = 0; j < nargs; j++)
			{
				ASSERT(m_inspector != NULL);

				argstr = evt->get_param_as_str(j, &resolved_argstr, m_inspector->get_buffer_format());

				if(resolved_argstr[0] == 0)
				{
					m_strstorage += evt->get_param_name(j);
					m_strstorage += '=';
					m_strstorage += argstr;
					m_strstorage += " ";
				}
				else
				{
					m_strstorage += evt->get_param_name(j);
					m_strstorage += '=';
					m_strstorage += argstr;
					m_strstorage += string("(") + resolved_argstr + ") ";
				}
			}

			RETURN_EXTRACT_STRING(m_strstorage);
		}
		break;
	case TYPE_BUFFER:
		{
			if(m_is_compare)
			{
				return extract_argraw(evt, len, "data");
			}

			const char* resolved_argstr;
			const char* argstr;
			argstr = evt->get_param_value_str("data", &resolved_argstr, m_inspector->get_buffer_format());
			*len = evt->m_rawbuf_str_len;

			return (uint8_t*)argstr;
		}
	case TYPE_BUFLEN:
		if(evt->m_fdinfo && evt->get_category() & EC_IO_BASE)
		{
			return extract_buflen(evt, len);
		}
		break;
	case TYPE_RESRAW:
		{
			const sinsp_evt_param* pi = evt->get_param_by_name("res");

			if(pi != NULL)
			{
				*len = pi->m_len;
				return (uint8_t*)pi->m_val;
			}

			if((evt->get_info_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
			{
				pi = evt->get_param_by_name("fd");

				if(pi != NULL)
				{
					*len = pi->m_len;
					return (uint8_t*)pi->m_val;
				}
			}

			return NULL;
		}
		break;
	case TYPE_RESSTR:
		{
			const char* resolved_argstr;
			const char* argstr;

			const sinsp_evt_param* pi = evt->get_param_by_name("res");

			if(pi != NULL)
			{
				ASSERT(pi->m_len == sizeof(int64_t));

				int64_t res = *(int64_t*)pi->m_val;

				if(res >= 0)
				{
					RETURN_EXTRACT_CSTR("SUCCESS");
				}
				else
				{
					argstr = evt->get_param_value_str("res", &resolved_argstr);
					ASSERT(resolved_argstr != NULL && resolved_argstr[0] != 0);

					if(resolved_argstr != NULL && resolved_argstr[0] != 0)
					{
						RETURN_EXTRACT_CSTR(resolved_argstr);
					}
					else if(argstr != NULL)
					{
						RETURN_EXTRACT_CSTR(argstr);
					}
				}
			}
			else
			{
				if((evt->get_info_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
				{
					pi = evt->get_param_by_name("fd");
					if (pi)
					{
						int64_t res = *(int64_t*)pi->m_val;

						if(res >= 0)
						{
							RETURN_EXTRACT_CSTR("SUCCESS");
						}
						else
						{
							argstr = evt->get_param_value_str("fd", &resolved_argstr);
							ASSERT(resolved_argstr != NULL && resolved_argstr[0] != 0);

							if(resolved_argstr != NULL && resolved_argstr[0] != 0)
							{
								RETURN_EXTRACT_CSTR(resolved_argstr);
							}
							else if(argstr != NULL)
							{
								RETURN_EXTRACT_CSTR(argstr);
							}
						}
					}
				}
			}

			return NULL;
		}
		break;
	case TYPE_FAILED:
		{
			m_u32val = 0;
			const sinsp_evt_param* pi = evt->get_param_by_name("res");

			if(pi != NULL)
			{
				ASSERT(pi->m_len == sizeof(int64_t));
				if(*(int64_t*)pi->m_val < 0)
				{
					m_u32val = 1;
				}
			}
			else if((evt->get_info_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
			{
				pi = evt->get_param_by_name("fd");

				if(pi != NULL)
				{
					ASSERT(pi->m_len == sizeof(int64_t));
					if(*(int64_t*)pi->m_val < 0)
					{
						m_u32val = 1;
					}
				}
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}
		break;
	case TYPE_ISIO:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & (EF_READS_FROM_FD | EF_WRITES_TO_FD))
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}
		}

		RETURN_EXTRACT_VAR(m_u32val);
	case TYPE_ISIO_READ:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & EF_READS_FROM_FD)
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}
	case TYPE_ISIO_WRITE:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}
	case TYPE_IODIR:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				m_strstorage = "write";
			}
			else if(eflags & EF_READS_FROM_FD)
			{
				m_strstorage = "read";
			}
			else
			{
				return NULL;
			}

			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_ISWAIT:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & (EF_WAITS))
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}
		}

		RETURN_EXTRACT_VAR(m_u32val);
	case TYPE_WAIT_LATENCY:
		{
			ppm_event_flags eflags = evt->get_info_flags();
			uint16_t etype = evt->m_pevt->type;

			if(eflags & (EF_WAITS) && PPME_IS_EXIT(etype))
			{
				if(evt->m_tinfo != NULL)
				{
					m_u64val = evt->m_tinfo->m_latency;
				}
				else
				{
					m_u64val = 0;
				}

				RETURN_EXTRACT_VAR(m_u64val);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_ISSYSLOG:
		{
			m_u32val = 0;

			ppm_event_flags eflags = evt->get_info_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				sinsp_fdinfo* fdinfo = evt->m_fdinfo;

				if(fdinfo != NULL && fdinfo->is_syslog())
				{
					m_u32val = 1;
				}
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}
	case TYPE_COUNT:
		m_u32val = 1;
		RETURN_EXTRACT_VAR(m_u32val);
	case TYPE_COUNT_ERROR:
		return extract_error_count(evt, len);
	case TYPE_COUNT_ERROR_FILE:
		{
			sinsp_fdinfo* fdinfo = evt->m_fdinfo;

			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_FILE ||
					fdinfo->m_type == SCAP_FD_FILE_V2 ||
					fdinfo->m_type == SCAP_FD_DIRECTORY)
				{
					return extract_error_count(evt, len);
				}
			}
			else
			{
				uint16_t etype = evt->get_type();

				if(etype == PPME_SYSCALL_OPEN_X ||
					etype == PPME_SYSCALL_CREAT_X ||
					etype == PPME_SYSCALL_OPENAT_X ||
					etype == PPME_SYSCALL_OPENAT_2_X ||
					etype == PPME_SYSCALL_OPENAT2_X ||
					etype == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X)
				{
					return extract_error_count(evt, len);
				}
			}

			return NULL;
		}
	case TYPE_COUNT_ERROR_NET:
		{
			sinsp_fdinfo* fdinfo = evt->m_fdinfo;

			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK ||
					fdinfo->m_type == SCAP_FD_UNIX_SOCK)
				{
					return extract_error_count(evt, len);
				}
			}
			else
			{
				uint16_t etype = evt->get_type();

				if(etype == PPME_SOCKET_ACCEPT_X ||
					etype == PPME_SOCKET_ACCEPT_5_X ||
					etype == PPME_SOCKET_ACCEPT4_X ||
					etype == PPME_SOCKET_ACCEPT4_5_X ||
				        etype == PPME_SOCKET_ACCEPT4_6_X ||
					etype == PPME_SOCKET_CONNECT_X)
				{
					return extract_error_count(evt, len);
				}
			}

			return NULL;
		}
	case TYPE_COUNT_ERROR_MEMORY:
		{
			if(evt->get_category() == EC_MEMORY)
			{
				return extract_error_count(evt, len);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_COUNT_ERROR_OTHER:
		{
			sinsp_fdinfo* fdinfo = evt->m_fdinfo;

			if(fdinfo != NULL)
			{
				if(!(fdinfo->m_type == SCAP_FD_FILE ||
					fdinfo->m_type == SCAP_FD_FILE_V2 ||
					fdinfo->m_type == SCAP_FD_DIRECTORY ||
					fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK ||
					fdinfo->m_type == SCAP_FD_UNIX_SOCK))
				{
					return extract_error_count(evt, len);
				}
			}
			else
			{
				uint16_t etype = evt->get_type();

				if(!(etype == PPME_SYSCALL_OPEN_X ||
					etype == PPME_SYSCALL_CREAT_X ||
					etype == PPME_SYSCALL_OPENAT_X ||
					etype == PPME_SYSCALL_OPENAT_2_X ||
					etype == PPME_SYSCALL_OPENAT2_X ||
					etype == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X ||
					etype == PPME_SOCKET_ACCEPT_X ||
					etype == PPME_SOCKET_ACCEPT_5_X ||
					etype == PPME_SOCKET_ACCEPT4_X ||
					etype == PPME_SOCKET_ACCEPT4_5_X ||
				        etype == PPME_SOCKET_ACCEPT4_6_X ||
					etype == PPME_SOCKET_CONNECT_X ||
					evt->get_category() == EC_MEMORY))
				{
					return extract_error_count(evt, len);
				}
			}

			return NULL;
		}
	case TYPE_COUNT_EXIT:
		if(PPME_IS_EXIT(evt->get_type()))
		{
			m_u32val = 1;
			RETURN_EXTRACT_VAR(m_u32val);
		}
		else
		{
			return NULL;
		}
	case TYPE_COUNT_PROCINFO:
		{
			uint16_t etype = evt->get_type();

			if(etype == PPME_PROCINFO_E)
			{
				sinsp_threadinfo* tinfo = evt->get_thread_info();

				if(tinfo != NULL && tinfo->is_main_thread())
				{
					m_u32val = 1;
					RETURN_EXTRACT_VAR(m_u32val);
				}
			}
		}

		break;
	case TYPE_COUNT_THREADINFO:
		{
			uint16_t etype = evt->get_type();

			if(etype == PPME_PROCINFO_E)
			{
				m_u32val = 1;
				RETURN_EXTRACT_VAR(m_u32val);
			}
		}

		break;
	case TYPE_ABSPATH:
		return extract_abspath(evt, len);
	case TYPE_BUFLEN_IN:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_READ)
		{
			return extract_buflen(evt, len);
		}

		break;
	case TYPE_BUFLEN_OUT:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_WRITE)
		{
			return extract_buflen(evt, len);
		}

		break;
	case TYPE_BUFLEN_FILE:
		if(evt->m_fdinfo && evt->get_category() & EC_IO_BASE)
		{
			if(evt->m_fdinfo->m_type == SCAP_FD_FILE || evt->m_fdinfo->m_type == SCAP_FD_FILE_V2)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_BUFLEN_FILE_IN:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_READ)
		{
			if(evt->m_fdinfo->m_type == SCAP_FD_FILE || evt->m_fdinfo->m_type == SCAP_FD_FILE_V2)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_BUFLEN_FILE_OUT:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_WRITE)
		{
			if(evt->m_fdinfo->m_type == SCAP_FD_FILE || evt->m_fdinfo->m_type == SCAP_FD_FILE_V2)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_BUFLEN_NET:
		if(evt->m_fdinfo && evt->get_category() & EC_IO_BASE)
		{
			scap_fd_type etype = evt->m_fdinfo->m_type;

			if(etype >= SCAP_FD_IPV4_SOCK && etype <= SCAP_FD_IPV6_SERVSOCK)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_BUFLEN_NET_IN:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_READ)
		{
			scap_fd_type etype = evt->m_fdinfo->m_type;

			if(etype >= SCAP_FD_IPV4_SOCK && etype <= SCAP_FD_IPV6_SERVSOCK)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_BUFLEN_NET_OUT:
		if(evt->m_fdinfo && evt->get_category() == EC_IO_WRITE)
		{
			scap_fd_type etype = evt->m_fdinfo->m_type;

			if(etype >= SCAP_FD_IPV4_SOCK && etype <= SCAP_FD_IPV6_SERVSOCK)
			{
				return extract_buflen(evt, len);
			}
		}

		break;
	case TYPE_ISOPEN_READ:
	case TYPE_ISOPEN_WRITE:
	case TYPE_ISOPEN_EXEC:
	case TYPE_ISOPEN_CREATE:
		{
			uint16_t etype = evt->get_type();

			m_u32val = 0;
			// If any of the exec bits is on, we consider this an open+exec
			uint32_t is_exec_mask = (PPM_S_IXUSR | PPM_S_IXGRP | PPM_S_IXOTH);

			if(etype == PPME_SYSCALL_OPEN_X ||
			   etype == PPME_SYSCALL_OPENAT_E ||
			   etype == PPME_SYSCALL_OPENAT_2_X ||
			   etype == PPME_SYSCALL_OPENAT2_X ||
			   etype == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X)
			{
				bool is_new_version = etype == PPME_SYSCALL_OPENAT_2_X || etype == PPME_SYSCALL_OPENAT2_X;
				// For both OPEN_X and OPENAT_E,
				// flags is the 3rd argument.
				uint32_t flags = evt->get_param(is_new_version ? 3 : 2)->as<uint32_t>();

				// PPM open flags use 0x11 for
				// PPM_O_RDWR, so there's no need to
				// check that value explicitly.
				if(m_field_id == TYPE_ISOPEN_READ &&
				   flags & PPM_O_RDONLY)
				{
					m_u32val = 1;
				}

				if(m_field_id == TYPE_ISOPEN_WRITE &&
				   flags & PPM_O_WRONLY)
				{
					m_u32val = 1;
				}

				if(m_field_id == TYPE_ISOPEN_CREATE)
				{
					// If PPM_O_F_CREATED is set the file is created
					if(flags & PPM_O_F_CREATED)
					{
						m_u32val = 1;
					}

					// If PPM_O_TMPFILE is set and syscall is successful the file is created
					if(flags & PPM_O_TMPFILE)
					{
						int64_t retval = evt->get_param(0)->as<int64_t>();

						if(retval >= 0)
						{
							m_u32val = 1;
						}
					}
				}

				/* `open_by_handle_at` exit event has no `mode` parameter. */
				if(m_field_id == TYPE_ISOPEN_EXEC && (flags & (PPM_O_TMPFILE | PPM_O_CREAT) && etype != PPME_SYSCALL_OPEN_BY_HANDLE_AT_X))
				{
					uint32_t mode_bits = evt->get_param(is_new_version ? 4 : 3)->as<uint32_t>();
					m_u32val = (mode_bits & is_exec_mask)? 1 : 0;
				}
			}
			else if ((m_field_id == TYPE_ISOPEN_EXEC) && (etype == PPME_SYSCALL_CREAT_X))
			{
				uint32_t mode_bits = evt->get_param(2)->as<uint32_t>();
				m_u32val = (mode_bits & is_exec_mask)? 1 : 0;
			}

			RETURN_EXTRACT_VAR(m_u32val);
		}

		break;
	case TYPE_INFRA_DOCKER_NAME:
	case TYPE_INFRA_DOCKER_CONTAINER_ID:
	case TYPE_INFRA_DOCKER_CONTAINER_NAME:
	case TYPE_INFRA_DOCKER_CONTAINER_IMAGE:
		{
			uint16_t etype = evt->m_pevt->type;

			if(etype == PPME_INFRASTRUCTURE_EVENT_E)
			{
				std::string descstr{evt->get_param(2)->as<std::string_view>()};
				vector<string> elements = sinsp_split(descstr, ';');
				for(string ute : elements)
				{
					string e = trim(ute);

					if(m_field_id == TYPE_INFRA_DOCKER_NAME)
					{
						if(e.substr(0, sizeof("Event") - 1) == "Event")
						{
							vector<string> subelements = sinsp_split(e, ':');
							ASSERT(subelements.size() == 2);
							m_strstorage = trim(subelements[1]);
							RETURN_EXTRACT_STRING(m_strstorage);
						}
					}
					else if(m_field_id == TYPE_INFRA_DOCKER_CONTAINER_ID)
					{
						if(e.substr(0, sizeof("ID") - 1) == "ID")
						{
							vector<string> subelements = sinsp_split(e, ':');
							ASSERT(subelements.size() == 2);
							m_strstorage = trim(subelements[1]);
							if(m_strstorage.length() > 12)
							{
								m_strstorage = m_strstorage.substr(0, 12);
							}
							RETURN_EXTRACT_STRING(m_strstorage);
						}
					}
					else if(m_field_id == TYPE_INFRA_DOCKER_CONTAINER_NAME)
					{
						if(e.substr(0, sizeof("name") - 1) == "name")
						{
							vector<string> subelements = sinsp_split(e, ':');
							ASSERT(subelements.size() == 2);
							m_strstorage = trim(subelements[1]);
							RETURN_EXTRACT_STRING(m_strstorage);
						}
					}
					else if(m_field_id == TYPE_INFRA_DOCKER_CONTAINER_IMAGE)
					{
						if(e.substr(0, sizeof("Image") - 1) == "Image")
						{
							vector<string> subelements = sinsp_split(e, ':');
							ASSERT(subelements.size() == 2);
							m_strstorage = subelements[1];

							if(m_strstorage.find("@") != string::npos)
							{
								m_strstorage = m_strstorage.substr(0, m_strstorage.find("@"));
							}
							else if(m_strstorage.find("sha256") != string::npos)
							{
								m_strstorage = e.substr(e.find(":") + 1);
							}
							m_strstorage = trim(m_strstorage);
							RETURN_EXTRACT_STRING(m_strstorage);
						}
					}
				}
			}
		}
		break;
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}

bool sinsp_filter_check_event::compare(sinsp_evt *evt)
{
	bool res;

	m_is_compare = true;

	if(m_field_id == TYPE_ARGRAW)
	{
		uint32_t len;
		bool sanitize_strings = false;
		// note: this uses the single-value extract because this filtercheck
		// class does not support multi-valued extraction
		uint8_t* extracted_val = extract(evt, &len, sanitize_strings);

		if(extracted_val == NULL)
		{
			return false;
		}

		ASSERT(m_arginfo != NULL);

		res = flt_compare(m_cmpop,
			m_arginfo->type,
			extracted_val);
	}
	else if(m_field_id == TYPE_AROUND)
	{
		uint64_t ts = evt->get_ts();
		uint64_t t1 = ts - m_tsdelta;
		uint64_t t2 = ts + m_tsdelta;

		bool res1 = ::flt_compare(CO_GE,
			PT_UINT64,
			&m_u64val,
			&t1);

		bool res2 = ::flt_compare(CO_LE,
			PT_UINT64,
			&m_u64val,
			&t2);

		return res1 && res2;
	}
	else
	{
		res = sinsp_filter_check::compare(evt);
	}

	m_is_compare = false;

	return res;
}
