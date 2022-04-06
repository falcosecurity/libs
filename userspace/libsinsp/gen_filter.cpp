/*
Copyright (C) 2021 The Falco Authors.

Falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

Falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstddef>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include "stdint.h"
#include "gen_filter.h"
#include "sinsp.h"
#include "sinsp_int.h"

gen_event::gen_event()
{
}

gen_event::~gen_event()
{
}

void gen_event::set_check_id(int32_t id)
{
	if (id) {
		m_check_id = id;
	}
}

int32_t gen_event::get_check_id() const
{
	return m_check_id;
}

gen_event_filter_check::gen_event_filter_check()
{
}

gen_event_filter_check::~gen_event_filter_check()
{
}

void gen_event_filter_check::set_check_id(int32_t id)
{
	m_check_id = id;
}

int32_t gen_event_filter_check::get_check_id()
{
	return m_check_id;
}

///////////////////////////////////////////////////////////////////////////////
// gen_event_filter_expression implementation
///////////////////////////////////////////////////////////////////////////////
gen_event_filter_expression::gen_event_filter_expression()
{
	m_parent = NULL;
}

gen_event_filter_expression::~gen_event_filter_expression()
{
	uint32_t j;

	for(j = 0; j < m_checks.size(); j++)
	{
		delete m_checks[j];
	}
}

void gen_event_filter_expression::add_check(gen_event_filter_check* chk)
{
	m_checks.push_back(chk);
}

bool gen_event_filter_expression::compare(gen_event *evt)
{
	uint32_t j;
	uint32_t size = (uint32_t)m_checks.size();
	bool res = true;
	gen_event_filter_check* chk = NULL;

	for(j = 0; j < size; j++)
	{
		chk = m_checks[j];
		ASSERT(chk != NULL);

		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_NOT:
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				if(res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_AND:
				if(!res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ORNOT:
				if(res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ANDNOT:
				if(!res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}
 done:

	return res;
}

bool gen_event_filter_expression::extract(gen_event *evt, vector<extract_value_t>& values, bool sanitize_strings)
{
	return false;
}

int32_t gen_event_filter_expression::get_expr_boolop()
{
	std::vector<gen_event_filter_check*>* cks = &(m_checks);

	if(cks->size() <= 1)
	{
		return m_boolop;
	}

	// Reset bit 0 to remove irrelevant not
	boolop b0 = (boolop)((uint32_t)(cks->at(1)->m_boolop) & (uint32_t)~1);

	if(cks->size() <= 2)
	{
		return b0;
	}

	for(uint32_t l = 2; l < cks->size(); l++)
	{
		if((boolop)((uint32_t)(cks->at(l)->m_boolop) & (uint32_t)~1) != b0)
		{
			return -1;
		}
	}

	return b0;
}


///////////////////////////////////////////////////////////////////////////////
// sinsp_filter implementation
///////////////////////////////////////////////////////////////////////////////
gen_event_filter::gen_event_filter()
{
	m_filter = new gen_event_filter_expression();
	m_curexpr = m_filter;

}

gen_event_filter::~gen_event_filter()
{
	if(m_filter)
	{
		delete m_filter;
	}
}

void gen_event_filter::push_expression(boolop op)
{
	gen_event_filter_expression* newexpr = new gen_event_filter_expression();
	newexpr->m_boolop = op;
	newexpr->m_parent = m_curexpr;

	add_check((gen_event_filter_check*)newexpr);
	m_curexpr = newexpr;
}

void gen_event_filter::pop_expression()
{
	ASSERT(m_curexpr->m_parent != NULL);

	if(m_curexpr->get_expr_boolop() == -1)
	{
		throw sinsp_exception("expression mixes 'and' and 'or' in an ambiguous way. Please use brackets.");
	}

	m_curexpr = m_curexpr->m_parent;
}

bool gen_event_filter::run(gen_event *evt)
{
	return m_filter->compare(evt);
}

void gen_event_filter::add_check(gen_event_filter_check* chk)
{
	m_curexpr->add_check((gen_event_filter_check *) chk);
}

bool gen_event_filter_factory::filter_field_info::is_skippable()
{
	// Skip fields with the EPF_TABLE_ONLY flag.
	return (tags.find("EPF_TABLE_ONLY") != tags.end());
}

uint32_t gen_event_filter_factory::filter_fieldclass_info::s_rightblock_start = 30;
uint32_t gen_event_filter_factory::filter_fieldclass_info::s_width = 120;

void gen_event_filter_factory::filter_fieldclass_info::wrapstring(const std::string &in, std::ostringstream &os)
{
	std::istringstream is(in);
	std::string word;
	uint32_t len = 0;

	while (is >> word)
	{
		// + 1 is trailing space.
		uint32_t wordlen = word.length() + 1;

		if((len + wordlen) <= (s_width-s_rightblock_start))
		{
			len += wordlen;
		}
		else
		{
			os << std::endl;
			os << std::left << std::setw(s_rightblock_start) << " ";
			len = wordlen;
		}

		os << word << " ";
	}
}

std::string gen_event_filter_factory::filter_fieldclass_info::as_markdown(const std::set<std::string>& event_sources)
{
	std::ostringstream os;

	os << "## Field Class: " << name << std::endl << std::endl;

	if(desc != "")
	{
		os << desc << std::endl << std::endl;
	}

	if(!event_sources.empty())
	{
		os << "Event Sources: ";

		for(const auto &src : event_sources)
		{
			os << src << " ";
		}

		os << std::endl << std::endl;
	}

	os << "Name | Type | Description" << std::endl;
	os << ":----|:-----|:-----------" << std::endl;

	for(auto &fld_info : fields)
	{
		// Skip fields that should not be included
		// (e.g. hidden fields)
		if(fld_info.is_skippable())
		{
			continue;
		}

		os << "`" << fld_info.name << "` | " << fld_info.data_type << " | " << fld_info.desc << std::endl;
	}

	return os.str();
}

std::string gen_event_filter_factory::filter_fieldclass_info::as_string(bool verbose, const std::set<std::string>& event_sources)
{
	std::ostringstream os;

	os << "-------------------------------" << std::endl;

	os << std::left << std::setw(s_rightblock_start) << "Field Class:" << name;
	if(shortdesc != "")
	{
		os << " (" << shortdesc << ")";
	}
	os << std::endl;

	if(desc != "")
	{
		os << std::left << std::setw(s_rightblock_start) << "Description:";

		wrapstring(desc, os);
		os << std::endl;
	}

	if(!event_sources.empty())
	{
		os << std::left << std::setw(s_rightblock_start) << "Event Sources:";

		for(const auto &src : event_sources)
		{
			os << src << " ";
		}

		os << std::endl;
	}

	os << std::endl;

	for(auto &fld_info : fields)
	{
		// Skip fields that should not be included
		// (e.g. hidden fields)
		if(fld_info.is_skippable())
		{
			continue;
		}

		if(fld_info.name.length() > s_rightblock_start)
		{
			os << fld_info.name << std::endl;
			os << std::left << std::setw(s_rightblock_start) << " ";
		}
		else
		{
			os << std::left << std::setw(s_rightblock_start) << fld_info.name;
		}

		// Append any tags, and if verbose, add the type, to the description.
		std::string desc = fld_info.desc;

		if(!fld_info.tags.empty())
		{
			std::string tagsstr = "(";
			for(const auto &tag : fld_info.tags)
			{
				if(tagsstr != "(")
				{
					tagsstr += ",";
				}

				tagsstr += tag;
			}

			tagsstr += ")";

			desc = tagsstr + " " + desc;
		}

		if(verbose)
		{
			desc = "(Type: " + fld_info.data_type + ") " + desc;
		}

		wrapstring(desc, os);
		os << std::endl;
	}

	return os.str();
}

gen_event_formatter::gen_event_formatter()
{
}

gen_event_formatter::~gen_event_formatter()
{
}

gen_event_formatter_factory::gen_event_formatter_factory()
{
}

gen_event_formatter_factory::~gen_event_formatter_factory()
{
}
