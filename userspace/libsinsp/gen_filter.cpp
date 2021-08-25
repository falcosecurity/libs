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
#include <algorithm>
#include "stdint.h"
#include "gen_filter.h"
#include "sinsp.h"
#include "sinsp_int.h"

std::set<uint16_t> gen_event_filter_check::s_default_evttypes{1};

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

const std::set<uint16_t> &gen_event_filter_check::evttypes()
{
	return s_default_evttypes;
}

const std::set<uint16_t> &gen_event_filter_check::possible_evttypes()
{
	return s_default_evttypes;
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

uint8_t *gen_event_filter_expression::extract(gen_event *evt, uint32_t *len, bool sanitize_strings)
{
	return NULL;
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

std::set<uint16_t> gen_event_filter_expression::inverse(const std::set<uint16_t> &evttypes)
{
	std::set<uint16_t> ret;

	// The inverse of "all events" is still "all events". This
	// ensures that when no specific set of event types are named
	// in the filter that the filter still runs for all event
	// types.
	if(evttypes == m_expr_possible_evttypes)
	{
		ret = evttypes;
		return ret;
	}

	std::set_difference(m_expr_possible_evttypes.begin(), m_expr_possible_evttypes.end(),
			    evttypes.begin(), evttypes.end(),
			    std::inserter(ret, ret.begin()));

	return ret;
}

void gen_event_filter_expression::combine_evttypes(boolop op,
						   const std::set<uint16_t> &chk_evttypes)
{
	switch(op)
	{
	case BO_NONE:
		// Overwrite with contents of set
		// Should only occur for the first check in a list
		m_expr_event_types = chk_evttypes;
		break;
	case BO_NOT:
		m_expr_event_types = inverse(chk_evttypes);
		break;
	case BO_ORNOT:
		combine_evttypes(BO_OR, inverse(chk_evttypes));
		break;
	case BO_ANDNOT:
		combine_evttypes(BO_AND, inverse(chk_evttypes));
		break;
	case BO_OR:
		// Merge the event types from the
		// other set into this one.
		m_expr_event_types.insert(chk_evttypes.begin(), chk_evttypes.end());
		break;
	case BO_AND:
		// Set to the intersection of event types between this
		// set and the provided set.

		std::set<uint16_t> intersect;
		std::set_intersection(m_expr_event_types.begin(), m_expr_event_types.end(),
				      chk_evttypes.begin(), chk_evttypes.end(),
				      std::inserter(intersect, intersect.begin()));
		m_expr_event_types = intersect;
		break;
	}
}

const std::set<uint16_t> &gen_event_filter_expression::evttypes()
{
	m_expr_event_types.clear();

	m_expr_possible_evttypes = possible_evttypes();

	for(uint32_t i = 0; i < m_checks.size(); i++)
	{
		gen_event_filter_check *chk = m_checks[i];
		ASSERT(chk != NULL);

		const std::set<uint16_t> &chk_evttypes = m_checks[i]->evttypes();

		combine_evttypes(chk->m_boolop, chk_evttypes);
	}

	return m_expr_event_types;
}

const std::set<uint16_t> &gen_event_filter_expression::possible_evttypes()
{
	// Return the set of possible event types from the first filtercheck.
	if(m_checks.size() == 0)
	{
		// Shouldn't happen--every filter expression should have a
		// real filtercheck somewhere below it.
		ASSERT(false);
		m_expr_possible_evttypes = s_default_evttypes;
	}
	else
	{
		m_expr_possible_evttypes = m_checks[0]->possible_evttypes();
	}

	return m_expr_possible_evttypes;
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

std::set<uint16_t> gen_event_filter::evttypes()
{
	return m_filter->evttypes();
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
