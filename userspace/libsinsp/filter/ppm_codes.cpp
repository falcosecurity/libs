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

#include <libsinsp/filter/ppm_codes.h>

/**
 * NOTE: the following code has been ported from Falco and updated with the
 * new definitions and API of libsinsp::events. See previous code:
 * https://github.com/falcosecurity/falco/commit/2495827e0cd64452a7d696047ea1365bb0050ffa
 * 
 * Given a rule filtering condition (in AST form), the following logic is
 * responsible of returning the set of event types for which the
 * filtering condition can be evaluated to true.
 * 
 * This implementation is based on the boolean algebraic properties of sets 
 * and works as follows depending on the type of nodes:
 * - the evt types of "and" nodes are the intersection set of the evt types of
 *   their children nodes.
 * - the evt types of "or" nodes are the union set of the evt types of
 *   their children nodes.
 * - the evt types of leaf nodes (e.g. "evt.type=open" or "proc.name=cat")
 *   depend on the type of check:
 *   * checks based on evt types (e.g. =xxx, != xxx, in (xxx)) give a clear
 *     definition of the matched event types. The "evt.type exists" check
 *     matches every evt type.
 *   * checks non-related to evt types are neutral and match all evt types
 *     (e.g. proc.name=cat).
 * 
 * The tricky part is handling negation (e.g. "not evt.type=open").
 * Given a set of event types, its negation is the difference between the
 * "set of all events" and the set (e.g. all types but not the ones in the set).
 * Reasonably, negation should not affect checks unrelated to evt types (e.g.
 * "proc.name=cat" is equivalent to "not proc.name=cat" for evt type matching).
 * The knowledge of whether a set of event types should be negated or not
 * can't be handled nor propagated in "and" and "or" nodes. Since rules'
 * conditions are boolean expression, the solution is to use De Morgan's Laws
 * to push the negation evaluations down to the leaf nodes as follows:
 * - "not (A and B)" is evaluated as "not A or not B"
 * - "not (A or B)" is evaluated as "not A and not B"
 * By happening only on leaf nodes, the set of matching event types can safely
 * be constructed and negated depending on the different cases.
 */

static bool is_evttype_operator(const std::string& op)
{
    return op == "==" || op == "=" || op == "!=" || op == "in";
}

using name_set_t = std::unordered_set<std::string>;

template<typename code_set_t,
         code_set_t all_codes_set(),
         code_set_t names_to_codes(const name_set_t&)>
struct ppm_code_visitor: public libsinsp::filter::ast::const_expr_visitor
{
    ppm_code_visitor():
		m_expect_value(false),
		m_inside_negation(false),
		m_last_node_has_codes(false),
		m_last_node_codes({}) { };
    ppm_code_visitor(ppm_code_visitor&&) = default;
    ppm_code_visitor& operator = (ppm_code_visitor&&) = default;
    ppm_code_visitor(const ppm_code_visitor&) = default;
    ppm_code_visitor& operator = (const ppm_code_visitor&) = default;

    bool m_expect_value;
    bool m_inside_negation;
    bool m_last_node_has_codes;
    code_set_t m_last_node_codes;

    void inversion(code_set_t& types)
    {
        // we don't invert "neutral" checks
        if (m_last_node_has_codes)
        {
            types = all_codes_set().diff(types);
        }
    }
    
	void try_inversion(code_set_t& types)
    {
        if (m_inside_negation)
        {
            inversion(types);
        }
    }

    void conjunction(const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>& children)
    {
        code_set_t types = all_codes_set();
        m_last_node_codes.clear();
        for (auto &c : children)
        {
            c->accept(this);
            types = types.intersect(m_last_node_codes);
        }
        m_last_node_codes = types;
    }

    void disjunction(const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>& children)
    {
        code_set_t types;
        m_last_node_codes.clear();
        for (auto &c : children)
        {
            c->accept(this);
            types = types.merge(m_last_node_codes);
        }
        m_last_node_codes = types;
    }

    void visit(const libsinsp::filter::ast::and_expr* e) override
    {
        if (m_inside_negation)
        {
            disjunction(e->children);
        }
        else
        {
            conjunction(e->children);
        }
    }

    void visit(const libsinsp::filter::ast::or_expr* e) override
    {
        if (m_inside_negation)
        {
            conjunction(e->children);
        }
        else
        {
            disjunction(e->children);
        }
    }
    
    void visit(const libsinsp::filter::ast::not_expr* e) override
    {
        m_last_node_codes.clear();
        auto inside_negation = m_inside_negation;
        m_inside_negation = !m_inside_negation;
        e->child->accept(this);
        m_inside_negation = inside_negation;
    }

    void visit(const libsinsp::filter::ast::binary_check_expr* e) override
    {
        m_last_node_codes.clear();
        m_last_node_has_codes = false;
        if (e->field == "evt.type" && is_evttype_operator(e->op))
        {
            // note: we expect m_inside_negation and m_last_node_has_codes
            // to be handled and altered by the child node
            m_expect_value = true;
            e->value->accept(this);
            m_expect_value = false;
            if (e->op == "!=")
            {
                // note: since we push the "negation" down to the tree leaves
                // (following de morgan's laws logic), the child node may have
                // already inverted the set of matched event type. As such,
                // inverting here again is safe for supporting both the
                // single-negation and double-negation cases.
                inversion(m_last_node_codes);
            }
            return;
        }
        m_last_node_codes = all_codes_set();
        try_inversion(m_last_node_codes);
    }

	void visit(const libsinsp::filter::ast::unary_check_expr* e) override
    {
        m_last_node_codes.clear();
        m_last_node_has_codes = e->field == "evt.type" && e->op == "exists";
        m_last_node_codes = all_codes_set();
        try_inversion(m_last_node_codes);
    }

    void visit(const libsinsp::filter::ast::value_expr* e) override
    {
        m_last_node_codes.clear();
        m_last_node_has_codes = m_expect_value;
        if (m_expect_value)
        {
            m_last_node_codes = names_to_codes({e->value});
        }
        else
        {
            // this case only happens if a macro has not yet been substituted
            // with an actual condition. Should not happen, but we handle it
            // for consistency.
            m_last_node_codes = all_codes_set();
        }
        try_inversion(m_last_node_codes);
    }

    void visit(const libsinsp::filter::ast::list_expr* e) override
    {
        m_last_node_codes.clear();
        m_last_node_has_codes = false;
        if (m_expect_value)
        {
            m_last_node_has_codes = true;
            name_set_t names;
            for (const auto& n : e->values)
            {
                names.insert(n);
            }
            m_last_node_codes = names_to_codes(names);
            try_inversion(m_last_node_codes);
            return;
        }
        m_last_node_codes = all_codes_set();
        try_inversion(m_last_node_codes);
    }
};

libsinsp::events::set<ppm_sc_code>
libsinsp::filter::ast::ppm_sc_codes(const libsinsp::filter::ast::expr* e)
{
    ppm_code_visitor<
        libsinsp::events::set<ppm_sc_code>,
        libsinsp::events::all_sc_set,
        libsinsp::events::event_names_to_sc_set> v;
// note(jasondellaluce): ppm_sc code mappings are available for linux only so far
#ifdef __linux__
    e->accept(&v);
#else
    v.m_last_node_codes = { };
#endif
    return v.m_last_node_codes;
}

// todo(jasondellaluce): should we deal with PPME_ASYNCEVENT_E at this level?
libsinsp::events::set<ppm_event_code>
libsinsp::filter::ast::ppm_event_codes(const libsinsp::filter::ast::expr* e)
{
    ppm_code_visitor<
        libsinsp::events::set<ppm_event_code>,
        libsinsp::events::all_event_set,
        libsinsp::events::names_to_event_set> v;
    e->accept(&v);
    return v.m_last_node_codes;
}
