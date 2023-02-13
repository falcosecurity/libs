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

#include <filter/parser.h>
#include <string>
#include <set>
#include <memory>
#include <functional>
#include <stdexcept>
#include "event.h"


/* Using a custom / optimized event type for performance optimization reasons.
 *
 * We found that regular set operations, even with unordered_set, slowed down Falco's 
 * initialization by orders of magnitude, because of exhaustive evttypes scanning 
 * when loading rulesets.
 * For this reason the custom event type optimizes operations over sets of numbers.
*/

typedef uint16_t ppme_type;

namespace libsinsp {
namespace filter {

template<typename ppme_type>
class sinsp_event_types
{
private:
	using vec_t = std::vector<uint8_t>;
	vec_t m_types{};
	static const auto enum_max = PPM_EVENT_MAX;

	static inline void check_range(ppme_type e)
	{
		if(e > enum_max)
		{
			throw std::range_error("invalid event type");
		}
	}

public:
	sinsp_event_types(sinsp_event_types&&) = default;
	sinsp_event_types(const sinsp_event_types&) = default;
	sinsp_event_types& operator=(sinsp_event_types&&) = default;
	sinsp_event_types& operator=(const sinsp_event_types&) = default;

	inline sinsp_event_types():
		m_types(enum_max + 1, 0)
	{
	}

	inline void insert(ppme_type e)
	{
		check_range(e);
		m_types[e] = 1;
	}

	void merge(const sinsp_event_types& other)
	{
		for(size_t i = 0; i <= enum_max; ++i)
		{
			m_types[i] |= other.m_types[i];
		}
	}

	void merge(const std::set<ppme_type>& other)
	{
		for(const auto& e : other)
		{
			insert(e);
		}
	}

	inline bool contains(ppme_type e) const
	{
		check_range(e);
		return m_types[e] != 0;
	}

	void clear()
	{
		for(auto& v : m_types)
		{
			v = 0;
		}
	}

	bool equals(const sinsp_event_types& other) const
	{
		return m_types == other.m_types;
	}

	sinsp_event_types diff(const sinsp_event_types& other) const
	{
		sinsp_event_types<ppme_type> ret;
		for(size_t i = 0; i <= enum_max; ++i)
		{
			if(m_types[i] == 1 && other.m_types[i] == 0)
			{
				ret.m_types[i] = 1;
			}
		}
		return ret;
	}

	sinsp_event_types intersect(const sinsp_event_types& other) const
	{
		sinsp_event_types<ppme_type> ret;
		for(size_t i = 0; i <= enum_max; ++i)
		{
			if(m_types[i] == 1 && other.m_types[i] == 1)
			{
				ret.m_types[i] = 1;
			}
		}
		return ret;
	}

	void for_each(std::function<bool(ppme_type)> consumer) const
	{
		for(size_t i = 0; i < m_types.size(); ++i)
		{
			if(m_types[i] != 0)
			{
				if(!consumer((ppme_type)i))
				{
					return;
				}
			}
		}
	}
};

inline bool operator==(const sinsp_event_types<ppme_type>& lhs, const sinsp_event_types<ppme_type>& rhs)
{
	return lhs.equals(rhs);
}

inline bool operator!=(const sinsp_event_types<ppme_type>& lhs, const sinsp_event_types<ppme_type>& rhs)
{
	return !(lhs == rhs);
}

/*!
	\brief Helper class for finding event types
*/
class evttype_resolver
{
public:
	/*!
		\brief Collects the evttypes related to the provided event name.
		The event types are inserted in the set provided as parameter.
		The set is not cleared before inserting the elements.
		\param evtname The event name used to search event types. If an empty
		string is passed, all the available evttypes are collected
		\param out The set to be filled with the evttypes
	*/
	inline void evttypes(const std::string& evtname, sinsp_event_types<ppme_type>& out) const
	{
		sinsp_event_types<ppme_type> evt_types;
		visitor().evttypes(evtname, evt_types);
		evt_types.for_each([&out](ppme_type val)
				   {out.insert(val); return true; });
	}

	/*!
		\brief Visits a filter AST and collects all the evttypes for which
		the filter expression can be evaluated as true. The event types are
		inserted in the set provided as parameter. The set is not cleared before
		inserting the elements.
		\param filter The filter AST to be explored
		\param out The set to be filled with the evttypes
	*/
	void evttypes(
		libsinsp::filter::ast::expr* filter,
		std::set<ppme_type>& out) const;

	/*!
		\brief Overloaded version of evttypes() that supports filters wrapped
		in shared pointers
	*/
	void evttypes(
		std::shared_ptr<libsinsp::filter::ast::expr> filter,
		std::set<ppme_type>& out) const;

private:
	struct visitor : public libsinsp::filter::ast::expr_visitor
	{
		visitor():
			m_expect_value(false),
			m_inside_negation(false),
			m_last_node_has_evttypes(false),
			m_last_node_evttypes({}),
			m_all_events({})
		{
			evttypes("", m_all_events);
		}
		visitor(visitor&&) = default;
		visitor& operator = (visitor&&) = default;
		visitor(const visitor&) = default;
		visitor& operator = (const visitor&) = default;

		bool m_expect_value;
		bool m_inside_negation;
		bool m_last_node_has_evttypes;
		sinsp_event_types<ppme_type> m_last_node_evttypes;
		sinsp_event_types<ppme_type> m_all_events;

		void visit(libsinsp::filter::ast::and_expr* e) override;
		void visit(libsinsp::filter::ast::or_expr* e) override;
		void visit(libsinsp::filter::ast::not_expr* e) override;
		void visit(libsinsp::filter::ast::value_expr* e) override;
		void visit(libsinsp::filter::ast::list_expr* e) override;
		void visit(libsinsp::filter::ast::unary_check_expr* e) override;
		void visit(libsinsp::filter::ast::binary_check_expr* e) override;
		void try_inversion(sinsp_event_types<ppme_type>& types);
		void inversion(sinsp_event_types<ppme_type>& types);
		void evttypes(const std::string& evtname, sinsp_event_types<ppme_type>& out);
		void conjunction(const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>&);
		void disjunction(const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>&);
	};
};

}
}
