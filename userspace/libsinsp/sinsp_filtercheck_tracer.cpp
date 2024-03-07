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

#include <libsinsp/sinsp_filtercheck_tracer.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/strl.h>

using namespace std;

#define TEXT_ARG_ID -1000000

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_tracer_fields[] =
{
	{PT_INT64, EPF_NONE|EPF_DEPRECATED, PF_ID, "span.id", "Span ID", "ID of the span. This is a unique identifier that is used to match the enter and exit tracer events for this span. It can also be used to match different spans belonging to a trace."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "span.time", "Time", "time of the span's enter tracer as a human readable string that includes the nanosecond part."},
	{PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "span.ntags", "Tag Count", "number of tags that this span has."},
	{PT_UINT32, EPF_NONE|EPF_DEPRECATED, PF_DEC, "span.nargs", "Argument Count", "number of arguments that this span has."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "span.tags", "Tags", "dot-separated list of all of the span's tags."},
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "span.tag", "Tag", "one of the span's tags, specified by 0-based offset, e.g. 'span.tag[1]'. You can use a negative offset to pick elements from the end of the tag list. For example, 'span.tag[-1]' returns the last tag."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "span.args", "Arguments", "comma-separated list of the span's arguments." },
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "span.arg", "Argument", "one of the span arguments, specified by name or by 0-based offset. E.g. 'span.arg.xxx' or 'span.arg[1]'. You can use a negative offset to pick elements from the end of the tag list. For example, 'span.arg[-1]' returns the last argument." },
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "span.enterargs", "Enter Arguments", "comma-separated list of the span's enter tracer event arguments. For enter tracers, this is the same as evt.args. For exit tracers, this is the evt.args of the corresponding enter tracer." },
	{PT_CHARBUF, EPF_ARG_REQUIRED|EPF_DEPRECATED, PF_NA, "span.enterarg", "Enter Argument", "one of the span's enter arguments, specified by name or by 0-based offset. For enter tracer events, this is the same as evt.arg. For exit tracer events, this is the evt.arg of the corresponding enter event." },
	{PT_RELTIME, EPF_NONE|EPF_DEPRECATED, PF_DEC, "span.duration", "Duration", "delta between this span's exit tracer event and the enter tracer event."},
	{PT_UINT64, EPF_TABLE_ONLY|EPF_DEPRECATED, PF_DEC, "span.duration.quantized", "Quantized Duration", "10-base log of the delta between an exit tracer event and the correspondent enter event."},
	{PT_CHARBUF, EPF_NONE|EPF_DEPRECATED, PF_NA, "span.duration.human", "Human-Readable Duration", "delta between this span's exit tracer event and the enter event, as a human readable string (e.g. 10.3ms)."},
	{PT_RELTIME, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED | EPF_DEPRECATED), PF_DEC, "span.duration.fortag", "Duration For Tag", "duration of the span if the number of tags matches the field argument, otherwise 0. For example, span.duration.fortag[1] returns the duration of all the spans with 1 tag, and zero for all the other ones."},
	{PT_UINT64, EPF_TABLE_ONLY|EPF_DEPRECATED, PF_DEC, "span.count", "Span Count", "1 for span exit events."},
	{PT_UINT64, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED | EPF_DEPRECATED), PF_DEC, "span.count.fortag", "Count For Tag", "1 if the span's number of tags matches the field argument, and zero for all the other ones."},
	{PT_UINT64, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED | EPF_DEPRECATED), PF_DEC, "span.childcount.fortag", "Child Count For Tag", "1 if the span's number of tags is greater than the field argument, and zero for all the other ones."},
	{PT_CHARBUF, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED | EPF_DEPRECATED), PF_NA, "span.idtag", "List View ID", "id used by the span list view."},
	{PT_CHARBUF, EPF_TABLE_ONLY|EPF_DEPRECATED, PF_NA, "span.rawtime", "List View Time", "id used by the span list view."},
	{PT_CHARBUF, EPF_TABLE_ONLY|EPF_DEPRECATED, PF_NA, "span.rawparenttime", "List View Parent Time", "id used by the span list view."},
};

sinsp_filter_check_tracer::sinsp_filter_check_tracer()
{
	m_info.m_flags = filter_check_info::FL_HIDDEN;
	m_info.m_name = "span";
	m_info.m_desc = "Fields used if information about distributed tracing is available.";
	m_info.m_fields = sinsp_filter_check_tracer_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_tracer_fields) / sizeof(sinsp_filter_check_tracer_fields[0]);
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_tracer::allocate_new()
{
	return std::make_unique<sinsp_filter_check_tracer>();
}

int32_t sinsp_filter_check_tracer::extract_arg(string fldname, string val, OUT const ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		if(parinfo != NULL)
		{
			throw sinsp_exception("tracer field must be expressed explicitly");
		}

		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);
		m_argid = sinsp_numparser::parsed32(numstr);
		parsed_len++;
	}
	else if(val[fldname.size()] == '.')
	{
		if(fldname == "span.tag")
		{
			throw sinsp_exception("invalid syntax for span.tag");
		}
		else if(fldname == "span.idtag")
		{
			throw sinsp_exception("invalid syntax for span.idtag");
		}

		m_argname = val.substr(fldname.size() + 1);
		parsed_len = (uint32_t)(fldname.size() + m_argname.size() + 1);
		m_argid = TEXT_ARG_ID;
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len;
}

int32_t sinsp_filter_check_tracer::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t res;
	string val(str);

	//
	// A couple of fields are handled in a custom way
	//
	if(STR_MATCH("span.tag") &&
		!STR_MATCH("span.tags"))
	{
		m_field_id = TYPE_TAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.tag", val, NULL);
	}
	else if(STR_MATCH("span.arg") &&
		!STR_MATCH("span.args"))
	{
		m_field_id = TYPE_ARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.arg", val, NULL);
	}
	else if(STR_MATCH("span.enterarg") &&
		!STR_MATCH("span.enterargs"))
	{
		m_field_id = TYPE_ENTERARG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.enterarg", val, NULL);
	}
	else if(STR_MATCH("span.duration.fortag"))
	{
		m_field_id = TYPE_TAGDURATION;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.duration.fortag", val, NULL);
	}
	else if(STR_MATCH("span.count.fortag"))
	{
		m_field_id = TYPE_TAGCOUNT;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.count.fortag", val, NULL);
	}
	else if(STR_MATCH("span.childcount.fortag"))
	{
		m_field_id = TYPE_TAGCHILDSCOUNT;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.childcount.fortag", val, NULL);
	}
	else if(STR_MATCH("span.idtag"))
	{
		m_field_id = TYPE_IDTAG;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg("span.idtag", val, NULL);
	}
	else
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}

	return res;
}

uint8_t* sinsp_filter_check_tracer::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	// do nothing: support to tracers has been dropped
	*len = 0;
	return NULL;
}
