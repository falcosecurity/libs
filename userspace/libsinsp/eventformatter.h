/*
Copyright (C) 2021 The Falco Authors.

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

#pragma once
#include <map>
#include <utility>
#include <string>
#include <json/json.h>

#include "filter_check_list.h"
#include "gen_filter.h"

class sinsp_filter_check;

/** @defgroup event Event manipulation
 *  @{
 */

/*!
  \brief Event to string converter class.
  This class can be used to format an event into a string, based on an arbitrary
  format.
*/
class SINSP_PUBLIC sinsp_evt_formatter : public gen_event_formatter
{
public:
	/*!
	  \brief Constructs a formatter.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be formatter.
	  \param fmt The printf-like format to use. The accepted format is the same
	   as the one of the output in Falco rules, so refer to the Falco
	   documentation for details.
	*/
	sinsp_evt_formatter(sinsp* inspector, filter_check_list &available_checks = g_filterlist);

	sinsp_evt_formatter(sinsp* inspector, const std::string& fmt, filter_check_list &available_checks = g_filterlist);

	void set_format(gen_event_formatter::output_format of, const std::string& fmt) override;

	~sinsp_evt_formatter();

	/*!
	  \brief Resolve all the formatted tokens and return them in a key/value
	  map.

	  \param evt Pointer to the event to be converted into string.
	  \param res Reference to the map that will be filled with the result.

	  \return true if all the tokens can be retrieved successfully, false
	  otherwise.
	*/
	bool resolve_tokens(sinsp_evt *evt, std::map<std::string,std::string>& values);

	// For compatibility with gen_event_filter_factory
	// interface. It just calls resolve_tokens().
	bool get_field_values(gen_event *evt, std::map<std::string, std::string> &fields) override;

	void get_field_names(std::vector<std::string> &fields) override;

	gen_event_formatter::output_format get_output_format() override;

	/*!
	  \brief Fills res with the string rendering of the event.

	  \param evt Pointer to the event to be converted into string.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if the string should be shown (based on the initial *),
	   false otherwise.
	*/
	bool tostring(sinsp_evt* evt, OUT std::string* res);

	// For compatibility with gen_event_formatter
	bool tostring(gen_event* evt, std::string &output) override;

	bool tostring_withformat(gen_event* evt, std::string &output, gen_event_formatter::output_format of) override;

	/*!
	  \brief Fills res with end of capture string rendering of the event.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if there is a string to show (based on the format),
	   false otherwise.
	*/
	bool on_capture_end(OUT std::string* res);

private:
	gen_event_formatter::output_format m_output_format;

	// vector of (full string of the token, filtercheck) pairs
	// e.g. ("proc.aname[2], ptr to sinsp_filter_check_thread)
	std::vector<std::pair<std::string, sinsp_filter_check*>> m_tokens;
	std::vector<uint32_t> m_tokenlens;
	sinsp* m_inspector;
	filter_check_list &m_available_checks;
	bool m_require_all_values;
	std::vector<sinsp_filter_check*> m_chks_to_free;

	Json::Value m_root;
	Json::FastWriter m_writer;
};

/*!
  \brief Caching version of sinsp_evt_formatter
  This class is a wrapper around sinsp_evt_formatter, maintaining a
  cache of previously seen formatters. It avoids the overhead of
  recreating sinsp_evt_formatter objects for each event.
*/
class SINSP_PUBLIC sinsp_evt_formatter_cache
{
public:
	sinsp_evt_formatter_cache(sinsp *inspector);
	virtual ~sinsp_evt_formatter_cache();

	// Resolve the tokens inside format and return them as a key/value map.
	// Creates a new sinsp_evt_formatter object if necessary.
	bool resolve_tokens(sinsp_evt *evt, std::string &format, std::map<std::string,std::string>& values);

	// Fills in res with the event formatted according to
	// format. Creates a new sinsp_evt_formatter object if
	// necessary.
	bool tostring(sinsp_evt *evt, std::string &format, OUT std::string *res);

private:

	// Get the formatter for this format string. Creates a new
	// sinsp_evt_formatter object if necessary.
	std::shared_ptr<sinsp_evt_formatter>& get_cached_formatter(std::string &format);

	std::map<std::string,std::shared_ptr<sinsp_evt_formatter>> m_formatter_cache;
	sinsp *m_inspector;
};
/*@}*/

class sinsp_evt_formatter_factory : public gen_event_formatter_factory
{
public:
	sinsp_evt_formatter_factory(sinsp *inspector, filter_check_list &available_checks=g_filterlist);
	virtual ~sinsp_evt_formatter_factory();

	void set_output_format(gen_event_formatter::output_format of) override;

	std::shared_ptr<gen_event_formatter> create_formatter(const std::string &format) override;

protected:

	// Maps from output string to formatter
	std::map<std::string, std::shared_ptr<gen_event_formatter>> m_formatters;

	sinsp *m_inspector;
	filter_check_list &m_available_checks;
	gen_event_formatter::output_format m_output_format;
};
