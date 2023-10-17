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

#include "sinsp_filtercheck_tracer.h"
#include "sinsp_filtercheck_reference.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "tracers.h"
#include "strl.h"

using namespace std;

static int32_t g_screen_w = -1;

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

static const filtercheck_field_info sinsp_filter_check_tracer_fields[] =
{
	{PT_INT64, EPF_NONE, PF_ID, "span.id", "Span ID", "ID of the span. This is a unique identifier that is used to match the enter and exit tracer events for this span. It can also be used to match different spans belonging to a trace."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "span.time", "Time", "time of the span's enter tracer as a human readable string that includes the nanosecond part."},
	{PT_UINT32, EPF_NONE, PF_DEC, "span.ntags", "Tag Count", "number of tags that this span has."},
	{PT_UINT32, EPF_NONE, PF_DEC, "span.nargs", "Argument Count", "number of arguments that this span has."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "span.tags", "Tags", "dot-separated list of all of the span's tags."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "span.tag", "Tag", "one of the span's tags, specified by 0-based offset, e.g. 'span.tag[1]'. You can use a negative offset to pick elements from the end of the tag list. For example, 'span.tag[-1]' returns the last tag."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "span.args", "Arguments", "comma-separated list of the span's arguments." },
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "span.arg", "Argument", "one of the span arguments, specified by name or by 0-based offset. E.g. 'span.arg.xxx' or 'span.arg[1]'. You can use a negative offset to pick elements from the end of the tag list. For example, 'span.arg[-1]' returns the last argument." },
	{PT_CHARBUF, EPF_NONE, PF_NA, "span.enterargs", "Enter Arguments", "comma-separated list of the span's enter tracer event arguments. For enter tracers, this is the same as evt.args. For exit tracers, this is the evt.args of the corresponding enter tracer." },
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "span.enterarg", "Enter Argument", "one of the span's enter arguments, specified by name or by 0-based offset. For enter tracer events, this is the same as evt.arg. For exit tracer events, this is the evt.arg of the corresponding enter event." },
	{PT_RELTIME, EPF_NONE, PF_DEC, "span.duration", "Duration", "delta between this span's exit tracer event and the enter tracer event."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "span.duration.quantized", "Quantized Duration", "10-base log of the delta between an exit tracer event and the correspondent enter event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "span.duration.human", "Human-Readable Duration", "delta between this span's exit tracer event and the enter event, as a human readable string (e.g. 10.3ms)."},
	{PT_RELTIME, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED), PF_DEC, "span.duration.fortag", "Duration For Tag", "duration of the span if the number of tags matches the field argument, otherwise 0. For example, span.duration.fortag[1] returns the duration of all the spans with 1 tag, and zero for all the other ones."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "span.count", "Span Count", "1 for span exit events."},
	{PT_UINT64, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED), PF_DEC, "span.count.fortag", "Count For Tag", "1 if the span's number of tags matches the field argument, and zero for all the other ones."},
	{PT_UINT64, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED), PF_DEC, "span.childcount.fortag", "Child Count For Tag", "1 if the span's number of tags is greater than the field argument, and zero for all the other ones."},
	{PT_CHARBUF, (filtercheck_field_flags) (EPF_TABLE_ONLY | EPF_ARG_REQUIRED), PF_NA, "span.idtag", "List View ID", "id used by the span list view."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "span.rawtime", "List View Time", "id used by the span list view."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "span.rawparenttime", "List View Parent Time", "id used by the span list view."},
};

sinsp_filter_check_tracer::sinsp_filter_check_tracer()
{
	m_storage = NULL;
	m_info.m_name = "span";
	m_info.m_desc = "Fields used if information about distributed tracing is available.";
	m_info.m_fields = sinsp_filter_check_tracer_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_tracer_fields) / sizeof(sinsp_filter_check_tracer_fields[0]);
	m_converter = new sinsp_filter_check_reference();

	m_storage_size = UESTORAGE_INITIAL_BUFSIZE;
	m_storage = (char*)malloc(m_storage_size);
	if(m_storage == NULL)
	{
		throw sinsp_exception("memory allocation error in sinsp_filter_check_tracer::sinsp_filter_check_tracer");
	}

	m_cargname = NULL;
}

sinsp_filter_check_tracer::~sinsp_filter_check_tracer()
{
	if(m_converter != NULL)
	{
		delete m_converter;
	}

	if(m_storage != NULL)
	{
		free(m_storage);
	}
}

sinsp_filter_check* sinsp_filter_check_tracer::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_tracer();
}

int32_t sinsp_filter_check_tracer::extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo)
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
		m_cargname = m_argname.c_str();
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

	if(m_field_id == TYPE_DURATION ||
		m_field_id == TYPE_DURATION_QUANTIZED ||
		m_field_id == TYPE_DURATION_HUMAN ||
		m_field_id == TYPE_TAGDURATION ||
		m_field_id == TYPE_ARG ||
		m_field_id == TYPE_ARGS ||
		m_field_id == TYPE_ENTERARG ||
		m_field_id == TYPE_ENTERARGS ||
		m_field_id == TYPE_IDTAG ||
		m_field_id == TYPE_TIME ||
		m_field_id == TYPE_RAWTIME ||
		m_field_id == TYPE_RAWPARENTTIME
		)
	{
		m_inspector->request_tracer_state_tracking();
		m_needs_state_tracking = true;
	}

	return res;
}

uint8_t* sinsp_filter_check_tracer::extract_duration(uint16_t etype, sinsp_tracerparser* eparser, OUT uint32_t* len)
{
	if(etype == PPME_TRACER_X)
	{
		sinsp_partial_tracer* pae = eparser->m_enter_pae;
		if(pae == NULL)
		{
			return NULL;
		}

		m_s64val = eparser->m_exit_pae.m_time - pae->m_time;
		if(m_s64val < 0)
		{
			ASSERT(false);
			m_s64val = 0;
		}

		RETURN_EXTRACT_VAR(m_s64val);
	}
	else
	{
		return NULL;
	}
}

uint8_t* sinsp_filter_check_tracer::extract_args(sinsp_partial_tracer* pae, OUT uint32_t* len)
{
	if(pae == NULL)
	{
		return NULL;
	}

	vector<char*>::iterator nameit;
	vector<char*>::iterator valit;
	vector<uint32_t>::iterator namesit;
	vector<uint32_t>::iterator valsit;

	uint32_t nargs = (uint32_t)pae->m_argnames.size();
	uint32_t encoded_args_len = pae->m_argnames_len + pae->m_argvals_len +
	nargs + nargs + 2;

	if(m_storage_size < encoded_args_len)
	{
		char *new_storage = (char*)realloc(m_storage, encoded_args_len);
		if(new_storage == NULL)
		{
			return NULL;
		}
		m_storage = new_storage;
		m_storage_size = encoded_args_len;
	}

	char* p = m_storage;
	size_t storage_len = 0;

	for(nameit = pae->m_argnames.begin(), valit = pae->m_argvals.begin(),
		namesit = pae->m_argnamelens.begin(), valsit = pae->m_argvallens.begin();
		nameit != pae->m_argnames.end();
		++nameit, ++namesit, ++valit, ++valsit)
	{
		strlcpy(p + storage_len, *nameit, m_storage_size - storage_len);
		storage_len += (*namesit);
		m_storage[storage_len] = '=';
		storage_len++;

		memcpy(p + storage_len, *valit, (*valsit));
		storage_len += (*valsit);
		m_storage[storage_len] = ',';
		storage_len++;
	}

	if (storage_len == 0)
	{
		m_storage[0] = '\0';
	}
	else
	{
		m_storage[storage_len - 1] = '\0';
	}

	RETURN_EXTRACT_CSTR(m_storage);
}

uint8_t* sinsp_filter_check_tracer::extract_arg(sinsp_partial_tracer* pae, OUT uint32_t* len)
{
	char* res = NULL;

	if(pae == NULL)
	{
		return NULL;
	}

	if(m_argid == TEXT_ARG_ID)
	{
		//
		// Argument expressed as name, e.g. span.arg.name.
		// Scan the argname list and find the match.
		//
		uint32_t j;

		for(j = 0; j < pae->m_nargs; j++)
		{
			if(strcmp(m_cargname, pae->m_argnames[j]) == 0)
			{
				res = pae->m_argvals[j];
				break;
			}
		}
	}
	else
	{
		//
		// Argument expressed as id, e.g. span.arg[1].
		// Pick the corresponding value.
		//
		if(m_argid >= 0)
		{
			if(m_argid < (int32_t)pae->m_nargs)
			{
				res = pae->m_argvals[m_argid];
			}
		}
		else
		{
			int32_t id = (int32_t)pae->m_nargs + m_argid;

			if(id >= 0)
			{
				res = pae->m_argvals[id];
			}
		}
	}

	if (res)
	{
		*len = strlen(res);
	}
	return (uint8_t*)res;
}

uint8_t* sinsp_filter_check_tracer::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_tracerparser* eparser;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	uint16_t etype = evt->get_type();

	if(etype != PPME_TRACER_E && etype != PPME_TRACER_X)
	{
		return NULL;
	}

	if(tinfo == NULL)
	{
		return NULL;
	}

	eparser = tinfo->m_tracer_parser;
	if(eparser == NULL)
	{
		return NULL;
	}
	else
	{
		if(m_needs_state_tracking && eparser->m_enter_pae == NULL)
		{
			return NULL;
		}
	}

	switch(m_field_id)
	{
	case TYPE_ID:
		RETURN_EXTRACT_VAR(eparser->m_id);
	case TYPE_TIME:
		{
			sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, true);
			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_NTAGS:
		m_u32val = (uint32_t)eparser->m_tags.size();
		RETURN_EXTRACT_VAR(m_u32val);
	case TYPE_NARGS:
		{
			sinsp_partial_tracer* pae = eparser->m_enter_pae;
			if(pae == NULL)
			{
				return NULL;
			}

			m_u32val = (uint32_t)pae->m_argvals.size();
			RETURN_EXTRACT_VAR(m_u32val);
		}
	case TYPE_TAGS:
		{
			vector<char*>::iterator it;
			vector<uint32_t>::iterator sit;

			uint32_t ntags = (uint32_t)eparser->m_tags.size();
			uint32_t encoded_tags_len = eparser->m_tot_taglens + ntags + 1;

			if(m_storage_size < encoded_tags_len)
			{
				char *new_storage = (char*)realloc(m_storage, encoded_tags_len);
				if(new_storage == NULL)
				{
					return NULL;
				}
				m_storage = new_storage;
				m_storage_size = encoded_tags_len;
			}

			char* p = m_storage;

			for(it = eparser->m_tags.begin(), sit = eparser->m_taglens.begin();
				it != eparser->m_tags.end(); ++it, ++sit)
			{
				memcpy(p, *it, (*sit));
				p += (*sit);
				*p++ = '.';
			}

			if(p != m_storage)
			{
				*--p = 0;
			}
			else
			{
				*p = 0;
			}

			RETURN_EXTRACT_CSTR(m_storage);
		}
	case TYPE_TAG:
		{
			char* res = NULL;

			if(m_argid >= 0)
			{
				if(m_argid < (int32_t)eparser->m_tags.size())
				{
					res = eparser->m_tags[m_argid];
				}
			}
			else
			{
				int32_t id = (int32_t)eparser->m_tags.size() + m_argid;

				if(id >= 0)
				{
					res = eparser->m_tags[id];
				}
			}

			RETURN_EXTRACT_CSTR(res);
		}
	case TYPE_IDTAG:
		{
			m_strstorage = to_string(eparser->m_id);

			if(m_argid >= 0)
			{
				if(m_argid < (int32_t)eparser->m_tags.size())
				{
					m_strstorage += eparser->m_tags[m_argid];
				}
			}
			else
			{
				int32_t id = (int32_t)eparser->m_tags.size() + m_argid;

				if(id >= 0)
				{
					m_strstorage += eparser->m_tags[id];
				}
			}

			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_ARGS:
		if(PPME_IS_ENTER(etype))
		{
			return extract_args(eparser->m_enter_pae, len);
		}
		else
		{
			return extract_args(&eparser->m_exit_pae, len);
		}
	case TYPE_ARG:
		if(PPME_IS_ENTER(etype))
		{
			return extract_arg(eparser->m_enter_pae, len);
		}
		else
		{
			return extract_arg(&eparser->m_exit_pae, len);
		}
	case TYPE_ENTERARGS:
		return extract_args(eparser->m_enter_pae, len);
	case TYPE_ENTERARG:
		return extract_arg(eparser->m_enter_pae, len);
	case TYPE_DURATION:
		return (uint8_t*)extract_duration(etype, eparser, len);
	case TYPE_DURATION_HUMAN:
		{
			if(extract_duration(etype, eparser, len) == NULL)
			{
				return NULL;
			}
			else
			{
				m_converter->set_val(PT_RELTIME,
					EPF_NONE,
					(uint8_t*)&m_s64val,
					8,
					0,
					ppm_print_format::PF_DEC);

				m_strstorage = m_converter->tostring_nice(NULL, 0, 1000000000);
			}

			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_DURATION_QUANTIZED:
		{
			if(extract_duration(etype, eparser, len) == NULL)
			{
				return NULL;
			}
			else
			{
				uint64_t lat = m_s64val;
				if(lat != 0)
				{
					double lduration = log10((double)lat);

					if(lduration > 11)
					{
						lduration = 11;
					}

					m_s64val = (uint64_t)(lduration * g_screen_w / 11) + 1;

					RETURN_EXTRACT_VAR(m_s64val);
				}
			}

			return NULL;
		}
	case TYPE_TAGDURATION:
		if((int32_t)eparser->m_tags.size() - 1 == m_argid)
		{
			return (uint8_t*)extract_duration(etype, eparser, len);
		}
		else
		{
			return NULL;
		}
	case TYPE_COUNT:
		if(evt->get_type() == PPME_TRACER_X)
		{
			m_s64val = 1;
		}
		else
		{
			m_s64val = 0;
		}

		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_TAGCOUNT:
		if(PPME_IS_EXIT(evt->get_type()) && (int32_t)eparser->m_tags.size() - 1 == m_argid)
		{
			m_s64val = 1;
		}
		else
		{
			m_s64val = 0;
		}

		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_TAGCHILDSCOUNT:
		if(PPME_IS_EXIT(evt->get_type()) && (int32_t)eparser->m_tags.size() > m_argid + 1)
		{
			m_s64val = 1;
		}
		else
		{
			m_s64val = 0;
		}

		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_RAWTIME:
		{
			m_strstorage = to_string(eparser->m_enter_pae->m_time);
			RETURN_EXTRACT_STRING(m_strstorage);
		}
	case TYPE_RAWPARENTTIME:
		{
			sinsp_partial_tracer* pepae = eparser->find_parent_enter_pae();

			if(pepae == NULL)
			{
				return NULL;
			}

			m_strstorage = to_string(pepae->m_time);
			RETURN_EXTRACT_STRING(m_strstorage);
		}
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
