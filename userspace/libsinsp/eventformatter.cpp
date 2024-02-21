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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/filter.h>
#include <libsinsp/filterchecks.h>
#include <libsinsp/eventformatter.h>

///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector,
					 filter_check_list &available_checks)
	: m_inspector(inspector),
	  m_available_checks(available_checks)
{
}

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector,
					 const std::string& fmt,
					 filter_check_list &available_checks)
	: m_inspector(inspector),
	  m_available_checks(available_checks)
{
	output_format of = sinsp_evt_formatter::OF_NORMAL;

	if(m_inspector->get_buffer_format() == sinsp_evt::PF_JSON
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONEOLS
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEX
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEXASCII
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONBASE64)
	{
		of = sinsp_evt_formatter::OF_JSON;
	}

	set_format(of, fmt);
}

void sinsp_evt_formatter::set_format(output_format of, const std::string& fmt)
{
	uint32_t j;
	uint32_t last_nontoken_str_start = 0;
	std::string lfmt(fmt);

	m_output_format = of;

	if(lfmt == "")
	{
		throw sinsp_exception("empty formatting token");
	}

	//
	// If the string starts with a *, it means that we are ok with printing
	// the string even when not all the values it specifies are set.
	//
	if(lfmt[0] == '*')
	{
		m_require_all_values = false;
		lfmt.erase(0, 1);
	}
	else
	{
		m_require_all_values = true;
	}

	//
	// Parse the string and extract the tokens
	//
	const char* cfmt = lfmt.c_str();

	m_tokens.clear();
	uint32_t lfmtlen = (uint32_t)lfmt.length();

	for(j = 0; j < lfmtlen; j++)
	{
		if(cfmt[j] == '%')
		{
			int toklen = 0;

			if(last_nontoken_str_start != j)
			{
				auto newtkn = std::make_unique<rawstring_check>(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
				m_tokens.emplace_back(std::make_pair("", newtkn.get()));
				m_tokenlens.push_back(0);
				m_checks.push_back(std::move(newtkn));
			}

			if(j == lfmtlen - 1)
			{
				throw sinsp_exception("invalid formatting syntax: formatting cannot end with a %");
			}

			//
			// If the field specifier starts with a number, it means that we have a length modifier
			//
			if(isdigit(cfmt[j + 1]))
			{
				//
				// Parse the token length
				//
				sscanf(cfmt+ j + 1, "%d", &toklen);

				//
				// Advance until the beginning of the field name
				//
				while(true)
				{
					if(j == lfmtlen - 1)
					{
						throw sinsp_exception("invalid formatting syntax: formatting cannot end with a number");
					}
					else if(isdigit(cfmt[j + 1]))
					{
						j++;
						continue;
					}
					else
					{
						break;
					}
				}
			}

			auto chk = m_available_checks.new_filter_check_from_fldname(std::string(cfmt + j + 1),
				m_inspector,
				false);

			if(chk == nullptr)
			{
				throw sinsp_exception("invalid formatting token " + std::string(cfmt + j + 1));
			}

			const char * fstart = cfmt + j + 1;
			uint32_t fsize = chk->parse_field_name(fstart, true, false);

			j += fsize;
			ASSERT(j <= lfmt.length());

			m_tokens.emplace_back(std::make_pair(std::string(fstart, fsize), chk.get()));
			m_tokenlens.push_back(toklen);

			m_checks.push_back(std::move(chk));

			last_nontoken_str_start = j + 1;
		}
	}

	if(last_nontoken_str_start != j)
	{
		auto chk = std::make_unique<rawstring_check>(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
		m_tokens.emplace_back(std::make_pair("", chk.get()));
		m_checks.emplace_back(std::move(chk));
		m_tokenlens.push_back(0);
	}
}

bool sinsp_evt_formatter::on_capture_end(OUT std::string* res)
{
	res->clear();
	return res->size() > 0;
}

bool sinsp_evt_formatter::resolve_tokens(sinsp_evt *evt, std::map<std::string,std::string>& values)
{
	bool retval = true;
	const filtercheck_field_info* fi;
	uint32_t j = 0;

	ASSERT(m_tokenlens.size() == m_tokens.size());

	for(j = 0; j < m_tokens.size(); j++)
	{
		char* str = m_tokens[j].second->tostring(evt);

		if(str == NULL)
		{
			if(m_require_all_values)
			{
				retval = false;
				break;
			}
			else
			{
				str = (char*)"<NA>";
			}
		}

		fi = m_tokens[j].second->get_field_info();
		if(fi)
		{
			values[m_tokens[j].first] = std::string(str);
		}
	}

	return retval;
}

bool sinsp_evt_formatter::get_field_values(sinsp_evt *evt, std::map<std::string, std::string> &fields)
{
	return resolve_tokens(evt, fields);
}

void sinsp_evt_formatter::get_field_names(std::vector<std::string> &fields)
{
	for(size_t i = 0; i < m_tokens.size(); i++)
	{
		if(m_tokens[i].first == "")
		{
			continue;
		}

		fields.emplace_back(m_tokens[i].first);
	}
}

sinsp_evt_formatter::output_format sinsp_evt_formatter::get_output_format()
{
	return m_output_format;
}

bool sinsp_evt_formatter::tostring_withformat(sinsp_evt* evt, std::string &output, output_format of)
{
	bool retval = true;
	const filtercheck_field_info* fi;

	uint32_t j = 0;
	output.clear();

	ASSERT(m_tokenlens.size() == m_tokens.size());

	for(j = 0; j < m_tokens.size(); j++)
	{
		if(of == OF_JSON)
		{
			Json::Value json_value = m_tokens[j].second->tojson(evt);

			if(retval == false)
			{
				continue;
			}

			if(json_value == Json::nullValue && m_require_all_values)
			{
				retval = false;
				continue;
			}

			fi = m_tokens[j].second->get_field_info();

			if(fi)
			{
				m_root[m_tokens[j].first] = m_tokens[j].second->tojson(evt);
			}
		}
		else
		{
			char* str = m_tokens[j].second->tostring(evt);

			if(retval == false)
			{
				continue;
			}

			if(str == NULL)
			{
				if(m_require_all_values)
				{
					retval = false;
					continue;
				}
				else
				{
					str = (char*)"<NA>";
				}
			}

			uint32_t tks = m_tokenlens[j];

			if(tks != 0)
			{
				std::string sstr(str);
				sstr.resize(tks, ' ');
				output += sstr;
			}
			else
			{
				output += str;
			}
		}
	}

	if(of == OF_JSON)
	{
		output = m_writer.write(m_root);
		output = output.substr(0, output.size() - 1);
	}

	return retval;
}

bool sinsp_evt_formatter::tostring(sinsp_evt* evt, std::string& res)
{
	return tostring_withformat(evt, res, m_output_format);
}

sinsp_evt_formatter_factory::sinsp_evt_formatter_factory(sinsp *inspector, filter_check_list &available_checks)
	: m_inspector(inspector),
	  m_available_checks(available_checks),
	  m_output_format(sinsp_evt_formatter::OF_NORMAL)
{
}

void sinsp_evt_formatter_factory::set_output_format(sinsp_evt_formatter::output_format of)
{
	m_formatters.clear();

	m_output_format = of;
}

std::shared_ptr<sinsp_evt_formatter> sinsp_evt_formatter_factory::create_formatter(const std::string &format)
{
	auto it = m_formatters.find(format);

	if (it != m_formatters.end())
	{
		return it->second;
	}

	std::shared_ptr<sinsp_evt_formatter> ret;

	ret.reset(new sinsp_evt_formatter(m_inspector, m_available_checks));

	ret->set_format(m_output_format, format);
	m_formatters[format] = ret;

	return ret;
}
