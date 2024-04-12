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
#include <libsinsp/filterchecks.h>
#include <libsinsp/eventformatter.h>
#include <libsinsp/filter/parser.h>

static constexpr const char* s_not_available_str = "<NA>";

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
	if(fmt.empty())
	{
		throw sinsp_exception("empty formatting token");
	}

	m_output_tokens.clear();
	m_output_format = of;

	//
	// If the string starts with a *, it means that we are ok with printing
	// the string even when not all the values it specifies are set.
	//
	std::string lfmt(fmt);
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
	std::shared_ptr<sinsp_filter_check> chk;
	uint32_t lfmtlen = (uint32_t)lfmt.length();
	uint32_t last_nontoken_str_start = 0;
	uint32_t j = 0;
	for(j = 0; j < lfmtlen; j++)
	{
		if(cfmt[j] == '%')
		{
			int toklen = 0;

			if(last_nontoken_str_start != j)
			{
				auto newtkn = std::make_shared<rawstring_check>(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
				m_output_tokens.emplace_back(newtkn);
				m_output_tokenlens.push_back(0);
			}

			if(j == lfmtlen - 1)
			{
				throw sinsp_exception("invalid formatting syntax: formatting cannot end with a %");
			}

			//
			// If the field specifier starts with a number, it means that we have a length transformer
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

			// start parsing the token, which at this point must be a valid
			// field or a valid field transformer
			int msize = 0;
			const char* tstart = cfmt + j + 1;
			std::vector<filter_transformer_type> transformers;
			while(true)
			{
				auto prev_size = msize;
				for (const auto& tr : libsinsp::filter::parser::supported_field_transformers())
				{
					if ((j + 1 + tr.size() + 1) < lfmtlen
						&& tstart[msize + tr.size()] == '('
						&& !strncmp(tstart + msize, tr.c_str(), tr.size()))
					{
						transformers.emplace_back(filter_transformer_from_str(tr));
						msize += tr.size() + 1; // count '('
						j += tr.size() + 1;
					}
				}
				// note: no whitespace is allowed between transformers
				if (prev_size == msize)
				{
					break;
				}
			}

			// read field token and make sure it's a valid one
			const char* fstart = cfmt + j + 1;
			chk = m_available_checks.new_filter_check_from_fldname(
				std::string_view(fstart), m_inspector, false);
			if(chk == nullptr)
			{
				throw sinsp_exception("invalid formatting token " + std::string(fstart));
			}
			uint32_t fsize = chk->parse_field_name(fstart, true, false);
			j += fsize;
			ASSERT(j <= lfmtlen);

			// we always add the field with no transformers for key->value resolution
			m_resolution_tokens.emplace_back(std::string(fstart, fsize), chk, false);

			// if we have transformers, create a copy of the field and use it
			// both for output substitution and for key->value resolution
			if (!transformers.empty())
			{
				chk = m_available_checks.new_filter_check_from_fldname(
					fstart, m_inspector, false);
				if(chk == nullptr)
				{
					throw sinsp_exception("invalid formatting token " + std::string(fstart));
				}
				chk->parse_field_name(fstart, true, false);

				// apply all transformers and pop back their ')' enclosing token
				// note: we apply transformers in reserve order to preserve their semantics
				for (auto rit = transformers.rbegin(); rit != transformers.rend(); ++rit) 
				{
					chk->add_transformer(*rit);

					// note: no whitespace is allowed between transformer enclosing
					if (j + 1 >= lfmtlen || cfmt[j + 1] != ')')
					{
						throw sinsp_exception("missing closing transformer parenthesis: " + std::string(cfmt + j));
					}
					j++;
					msize++; // count ')'
				}
				
				// when requested to do so, we'll resolve the field with transformers
				// in addition to the non-transformed version
				m_resolution_tokens.emplace_back(std::string(tstart, fsize + msize), chk, true);
			}

			// add field for output substitution
			m_output_tokens.emplace_back(chk);
			m_output_tokenlens.push_back(toklen);

			last_nontoken_str_start = j + 1;
		}
	}

	if(last_nontoken_str_start != j)
	{
		auto chk = std::make_shared<rawstring_check>(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
		m_output_tokens.emplace_back(chk);
		m_output_tokenlens.push_back(0);
	}
}

bool sinsp_evt_formatter::resolve_tokens(sinsp_evt *evt, std::map<std::string,std::string>& values)
{
	for(const auto& t : m_resolution_tokens)
	{
		if (t.has_transformers && !m_resolve_transformed_fields)
		{
			continue;
		}

		const char* str = t.token->tostring(evt);
		if(str == NULL)
		{
			if(m_require_all_values)
			{
				return false;
			}

			str = s_not_available_str;
		}
		values[t.name] = str;
	}
	return true;
}

bool sinsp_evt_formatter::get_field_values(sinsp_evt *evt, std::map<std::string, std::string> &fields)
{
	return resolve_tokens(evt, fields);
}

void sinsp_evt_formatter::get_field_names(std::vector<std::string> &fields)
{
	for(const auto& t : m_resolution_tokens)
	{
		fields.emplace_back(t.name);
	}
}

sinsp_evt_formatter::output_format sinsp_evt_formatter::get_output_format()
{
	return m_output_format;
}

bool sinsp_evt_formatter::tostring_withformat(sinsp_evt* evt, std::string &output, output_format of)
{
	output.clear();

	if(of == OF_JSON)
	{
		bool retval = true;
		for (const auto& t : m_resolution_tokens)
		{
			if (t.has_transformers && !m_resolve_transformed_fields)
			{
				// always skip keys with transformers here
				// todo!: is this the desired behavior?
				continue;
			}
			Json::Value json_value = t.token->tojson(evt);
			if(json_value == Json::nullValue && m_require_all_values)
			{
				retval = false;
				break;
			}
			m_root[t.name] = t.token->tojson(evt);
		}
		output = m_writer.write(m_root);
		output = output.substr(0, output.size() - 1);
		return retval;
	}

	ASSERT(m_output_tokenlens.size() == m_output_tokens.size());
	for(size_t j = 0; j < m_output_tokens.size(); j++)
	{
		const char* str = m_output_tokens[j]->tostring(evt);
		if(str == NULL)
		{
			if(m_require_all_values)
			{
				return false;
			}
			else
			{
				str = s_not_available_str;
			}
		}

		uint32_t tks = m_output_tokenlens[j];
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

	return true;
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

	auto ret = std::make_shared<sinsp_evt_formatter>(m_inspector, m_available_checks);

	ret->set_format(m_output_format, format);
	m_formatters[format] = ret;

	return ret;
}
