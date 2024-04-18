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

#pragma once
#include <map>
#include <utility>
#include <string>
#include <memory>
#include <json/json.h>

#include <libsinsp/filter_check_list.h>
#include <libsinsp/filter.h>

/** @defgroup event Event manipulation
 *  @{
 */

/*!
  \brief Event to string converter class.
  This class can be used to format an event into a string, based on an arbitrary
  format.
*/
class SINSP_PUBLIC sinsp_evt_formatter
{
public:
	enum output_format {
		OF_NORMAL = 0,
		OF_JSON   = 1
	};

	/*!
	  \brief Constructs a formatter.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be formatter.
	  \param fmt The printf-like format to use. The accepted format is the same
	   as the one of the output in Falco rules, so refer to the Falco
	   documentation for details.
	*/
	sinsp_evt_formatter(sinsp* inspector, filter_check_list &available_checks);

	sinsp_evt_formatter(sinsp* inspector, const std::string& fmt, filter_check_list &available_checks);

	virtual ~sinsp_evt_formatter() = default;

	/*!
	  \brief Resolve all the formatted tokens and return them in a key/value
	  map.

	  \param evt Pointer to the event to be converted into string.
	  \param res Reference to the map that will be filled with the result.

	  \return true if all the tokens can be retrieved successfully, false
	  otherwise.
	*/
	bool resolve_tokens(sinsp_evt *evt, std::map<std::string,std::string>& values);

	virtual void set_format(output_format of, const std::string& fmt);

	// For compatibility with sinsp_filter_factory
	// interface. It just calls resolve_tokens().
	virtual bool get_field_values(sinsp_evt *evt, std::map<std::string, std::string> &fields);

	virtual void get_field_names(std::vector<std::string> &fields);

	virtual output_format get_output_format();

	/*!
	  \brief Fills res with the string rendering of the event.

	  \param evt Pointer to the event to be converted into string.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if the string should be shown (based on the initial *),
	   false otherwise.
	*/
	inline bool tostring(sinsp_evt* evt, OUT std::string* res)
	{
		if (!res)
		{
			return false;
		}
		return tostring(evt, *res);
	}
	virtual bool tostring(sinsp_evt* evt, std::string &output);

	virtual bool tostring_withformat(sinsp_evt* evt, std::string &output, output_format of);

	/*!
	  \brief Fills res with end of capture string rendering of the event.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if there is a string to show (based on the format),
	   false otherwise.
	*/
	bool on_capture_end(OUT std::string* res);

private:
	output_format m_output_format;

	// vector of (full string of the token, filtercheck) pairs
	// e.g. ("proc.aname[2], ptr to sinsp_filter_check_thread)
	std::vector<std::pair<std::string, sinsp_filter_check*>> m_tokens;
	std::vector<uint32_t> m_tokenlens;
	sinsp* m_inspector;
	filter_check_list &m_available_checks;
	bool m_require_all_values;
	std::vector<std::unique_ptr<sinsp_filter_check>> m_checks;

	Json::Value m_root;
	Json::FastWriter m_writer;
};

class sinsp_evt_formatter_factory
{
public:
	sinsp_evt_formatter_factory(sinsp *inspector, filter_check_list &available_checks);
	virtual ~sinsp_evt_formatter_factory() = default;

	virtual void set_output_format(sinsp_evt_formatter::output_format of);

	virtual std::shared_ptr<sinsp_evt_formatter> create_formatter(const std::string &format);

protected:

	// Maps from output string to formatter
	std::map<std::string, std::shared_ptr<sinsp_evt_formatter>> m_formatters;

	sinsp *m_inspector;
	filter_check_list &m_available_checks;
	sinsp_evt_formatter::output_format m_output_format;
};
