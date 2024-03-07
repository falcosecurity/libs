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

#include <libsinsp/sinsp_filtercheck_gen_event.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_manager.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
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

static const filtercheck_field_info sinsp_filter_check_gen_event_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_ID, "evt.num", "Event Number", "event number."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time", "Time", "event timestamp as a time string that includes the nanosecond part."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.s", "Time (s)", "event timestamp as a time string with no nanoseconds."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.iso8601", "ISO 8601 Time", "event timestamp in ISO 8601 format, including nanoseconds and time zone offset (in UTC)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime", "Datetime", "event timestamp as a time string that includes the date."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime.s", "Datetime (s)", "event timestamp as a datetime string with no nanoseconds."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime", "Absolute Time", "absolute event timestamp, i.e. nanoseconds from epoch."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime.s", "Absolute Time (s)", "integer part of the event timestamp (e.g. seconds since epoch)."},
	{PT_ABSTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.rawtime.ns", "Absolute Time (ns)", "fractional part of the absolute event timestamp."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime", "Relative Time", "number of nanoseconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.reltime.s", "Relative Time (s)", "number of seconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime.ns", "Relative Time (ns)", "fractional part (in ns) of the time from the beginning of the capture."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.pluginname", "Plugin Name", "if the event comes from a plugin-defined event source, the name of the plugin that generated it. The plugin must be currently loaded."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.plugininfo", "Plugin Info", "if the event comes from a plugin-defined event source, a summary of the event as formatted by the plugin. The plugin must be currently loaded."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.source", "Event Source", "the name of the source that produced the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_async", "Async Event", "'true' for asynchronous events, 'false' otherwise."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.asynctype", "Async-Event Type", "If the event is asynchronous, the type of the event (e.g. 'container')."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.hostname", "Hostname", "The hostname of the underlying host can be customized by setting an environment variable (e.g. FALCO_HOSTNAME for the Falco agent). This is valuable in Kubernetes setups, where the hostname can match the pod name particularly in DaemonSet deployments. To achieve this, assign Kubernetes' spec.nodeName to the environment variable. Notably, spec.nodeName generally includes the cluster name."},
	/* Note for libs adopters: libs exposes a customizable env variable for hostname which defaults to `set(SCAP_HOSTNAME_ENV_VAR "SCAP_HOSTNAME")`, and Falco client adopts "FALCO_HOSTNAME". */
};

sinsp_filter_check_gen_event::sinsp_filter_check_gen_event()
{
	m_info.m_name = "evt";
	m_info.m_shortdesc = "All event types";
	m_info.m_desc = "These fields can be used for all event types";
	m_info.m_fields = sinsp_filter_check_gen_event_fields;
	m_info.m_flags = filter_check_info::FL_NONE;
	m_info.m_nfields = sizeof(sinsp_filter_check_gen_event_fields) / sizeof(sinsp_filter_check_gen_event_fields[0]);
	m_u64val = 0;
}

std::unique_ptr<sinsp_filter_check> sinsp_filter_check_gen_event::allocate_new()
{
	return std::make_unique<sinsp_filter_check_gen_event>();
}

Json::Value sinsp_filter_check_gen_event::extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
{
	switch(m_field_id)
	{
	case TYPE_TIME:
	case TYPE_TIME_S:
	case TYPE_TIME_ISO8601:
	case TYPE_DATETIME:
	case TYPE_DATETIME_S:
		return (Json::Value::Int64)evt->get_ts();

	case TYPE_RAWTS:
	case TYPE_RAWTS_S:
	case TYPE_RAWTS_NS:
	case TYPE_RELTS:
	case TYPE_RELTS_S:
	case TYPE_RELTS_NS:
		return (Json::Value::Int64)*(uint64_t*)extract(evt, len);
	default:
		return Json::nullValue;
	}

	return Json::nullValue;
}

uint8_t* sinsp_filter_check_gen_event::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{

	std::shared_ptr<sinsp_plugin> plugin;
	const scap_machine_info* minfo;

	*len = 0;
	switch(m_field_id)
	{
	case TYPE_TIME:
		if(false)
		{
			m_strstorage = to_string(evt->get_ts());
		}
		else
		{
			sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, true);
		}
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_TIME_S:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, false);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_TIME_ISO8601:
		sinsp_utils::ts_to_iso_8601(evt->get_ts(), &m_strstorage);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_DATETIME:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, true, true);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_DATETIME_S:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, true, false);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_RAWTS:
		m_u64val = evt->get_ts();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RAWTS_S:
		m_u64val = evt->get_ts() / ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RAWTS_NS:
		m_u64val = evt->get_ts() % ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS:
		m_u64val = evt->get_ts() - m_inspector->m_firstevent_ts;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS_S:
		m_u64val = (evt->get_ts() - m_inspector->m_firstevent_ts) / ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS_NS:
		m_u64val = (evt->get_ts() - m_inspector->m_firstevent_ts) % ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_NUMBER:
		m_u64val = evt->get_num();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PLUGINNAME:
	case TYPE_PLUGININFO:
		plugin = m_inspector->get_plugin_manager()->plugin_by_evt(evt);
		if (plugin == nullptr)
		{
			return NULL;
		}

		if(m_field_id == TYPE_PLUGINNAME)
		{
			m_strstorage = plugin->name();
		}
		else
		{
			m_strstorage = plugin->event_to_string(evt);
		}

		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_SOURCE:
		if (evt->get_source_idx() == sinsp_no_event_source_idx
			|| evt->get_source_name() == sinsp_no_event_source_name)
		{
			return NULL;
		}
		RETURN_EXTRACT_CSTR(evt->get_source_name());
	case TYPE_ISASYNC:
		if (libsinsp::events::is_metaevent((ppm_event_code) evt->get_type()))
		{
			m_u32val = 1;
		}
		else
		{
			m_u32val = 0;
		}
		RETURN_EXTRACT_VAR(m_u32val);
	case TYPE_ASYNCTYPE:
		if (!libsinsp::events::is_metaevent((ppm_event_code) evt->get_type()))
		{
			return NULL;
		}
		if (evt->get_type() == PPME_ASYNCEVENT_E)
		{
			RETURN_EXTRACT_CSTR(evt->get_param(1)->m_val);
		}
		RETURN_EXTRACT_CSTR(evt->get_name());
	case TYPE_HOSTNAME:
		minfo = m_inspector->get_machine_info();
		if (!minfo)
		{
			return NULL;
		}
		RETURN_EXTRACT_CSTR(minfo->hostname);
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}
