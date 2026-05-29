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
#include <libsinsp/utils.h>

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
 *   * checks on fields with a known runtime invariant (e.g. evt.num, whose
 *     values start at 1) can be statically resolved to either the empty
 *     set (when the condition is unsatisfiable, like "evt.num=0") or the
 *     universal set (when the condition is a tautology, like "evt.num>0").
 *     See evaluate_field_invariant().
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

static bool is_evttype_operator(const std::string& op) {
	return op == "==" || op == "=" || op == "!=" || op == "in";
}

// Outcome of a static evaluation of a binary_check_expr against the runtime
// invariants of the fields it references.
enum class invariant_result {
	known_empty,   // condition is provably false; matches no event type
	known_all,     // condition is provably true; matches every event type
	indeterminate  // analyzer cannot decide; caller must over-approximate
};

// Statically evaluates a binary_check_expr against the runtime invariants of
// known fields. Currently the only field with a documented invariant is
// `evt.num`, whose values are monotonically increasing and start at 1 for
// every event delivered through the live/replay event loop (see sinsp::next(),
// which pre-increments m_nevts before calling sinsp_evt::set_num()). This lets
// us resolve conditions like "evt.num=0" or "evt.num<1" to known_empty
// (unsatisfiable), and their duals like "evt.num!=0" or "evt.num>=1" to
// known_all (tautology), without claiming general satisfiability analysis.
//
// Literals are parsed with sinsp_numparser::tryparseu64 - the very same parser
// libsinsp uses at runtime for PT_UINT64 fields - so the analysis reasons about
// the exact value the runtime will compare against. In particular, a negative
// literal wraps around to a large unsigned value (just like at runtime), which
// the thresholds below correctly treat as indeterminate rather than mistaking
// it for unsatisfiable.
//
// Anything we cannot decide (unknown field, non-numeric literal, unsupported
// operator, transformer on either side, etc.) yields indeterminate so the
// caller falls back to the existing over-approximation.
static invariant_result evaluate_field_invariant(
        const libsinsp::filter::ast::binary_check_expr* e) {
	// Only a bare `evt.num` field is recognized. A transformer on the
	// left, an argument, or any other field name short-circuits to
	// indeterminate.
	auto field = dynamic_cast<const libsinsp::filter::ast::field_expr*>(e->left.get());
	if(field == nullptr || field->field != "evt.num" || field->arg) {
		return invariant_result::indeterminate;
	}

	const auto& op = e->op;

	// List operator: "evt.num in (...)". Since evt.num >= 1, the condition
	// matches nothing iff every listed value is 0 (the only non-positive
	// value an unsigned literal can take). An empty list never matches either.
	if(op == "in") {
		auto list = dynamic_cast<const libsinsp::filter::ast::list_expr*>(e->right.get());
		if(list == nullptr) {
			return invariant_result::indeterminate;
		}
		if(list->values.empty()) {
			return invariant_result::known_empty;
		}
		for(const auto& v : list->values) {
			uint64_t n;
			if(!sinsp_numparser::tryparseu64(v, &n) || n != 0) {
				return invariant_result::indeterminate;
			}
		}
		return invariant_result::known_empty;
	}

	// Scalar operators: the right-hand side must be a literal value.
	auto value = dynamic_cast<const libsinsp::filter::ast::value_expr*>(e->right.get());
	if(value == nullptr) {
		return invariant_result::indeterminate;
	}
	uint64_t n;
	if(!sinsp_numparser::tryparseu64(value->value, &n)) {
		return invariant_result::indeterminate;
	}

	// Given evt.num >= 1 (with n unsigned):
	//   evt.num =  N , N == 0  is unsatisfiable
	//   evt.num != N , N == 0  is a tautology
	//   evt.num <  N , N <= 1  is unsatisfiable (no value < 1)
	//   evt.num <= N , N == 0  is unsatisfiable
	//   evt.num >  N , N == 0  is a tautology
	//   evt.num >= N , N <= 1  is a tautology
	if(op == "=" || op == "==") {
		return n == 0 ? invariant_result::known_empty : invariant_result::indeterminate;
	}
	if(op == "!=") {
		return n == 0 ? invariant_result::known_all : invariant_result::indeterminate;
	}
	if(op == "<") {
		return n <= 1 ? invariant_result::known_empty : invariant_result::indeterminate;
	}
	if(op == "<=") {
		return n == 0 ? invariant_result::known_empty : invariant_result::indeterminate;
	}
	if(op == ">") {
		return n == 0 ? invariant_result::known_all : invariant_result::indeterminate;
	}
	if(op == ">=") {
		return n <= 1 ? invariant_result::known_all : invariant_result::indeterminate;
	}
	return invariant_result::indeterminate;
}

using name_set_t = std::unordered_set<std::string>;

template<typename code_set_t,
         code_set_t all_codes_set(),
         code_set_t names_to_codes(const name_set_t&)>
struct ppm_code_visitor : public libsinsp::filter::ast::const_expr_visitor {
	ppm_code_visitor() = default;
	virtual ~ppm_code_visitor() = default;
	ppm_code_visitor(ppm_code_visitor&&) = default;
	ppm_code_visitor& operator=(ppm_code_visitor&&) = default;
	ppm_code_visitor(const ppm_code_visitor&) = default;
	ppm_code_visitor& operator=(const ppm_code_visitor&) = default;

	bool m_last_node_is_evttype_field = false;
	bool m_last_node_is_field_or_transformer = true;
	bool m_inside_negation = false;
	bool m_last_node_has_codes = false;
	code_set_t m_last_node_codes{};

	inline void inversion(code_set_t& types) {
		// we don't invert "neutral" checks
		if(m_last_node_has_codes) {
			types = all_codes_set().diff(types);
		}
	}

	inline void try_inversion(code_set_t& types) {
		if(m_inside_negation) {
			inversion(types);
		}
	}

	inline void conjunction(
	        const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>& children) {
		code_set_t types = all_codes_set();
		for(auto& c : children) {
			c->accept(this);
			types = types.intersect(m_last_node_codes);
		}
		m_last_node_codes = types;
		m_last_node_is_evttype_field = false;
	}

	inline void disjunction(
	        const std::vector<std::unique_ptr<libsinsp::filter::ast::expr>>& children) {
		code_set_t types;
		for(auto& c : children) {
			c->accept(this);
			types = types.merge(m_last_node_codes);
		}
		m_last_node_codes = types;
		m_last_node_is_evttype_field = false;
	}

	void visit(const libsinsp::filter::ast::and_expr* e) override {
		if(m_inside_negation) {
			disjunction(e->children);
		} else {
			conjunction(e->children);
		}
	}

	void visit(const libsinsp::filter::ast::or_expr* e) override {
		if(m_inside_negation) {
			conjunction(e->children);
		} else {
			disjunction(e->children);
		}
	}

	void visit(const libsinsp::filter::ast::not_expr* e) override {
		m_last_node_codes.clear();
		auto inside_negation = m_inside_negation;
		m_inside_negation = !m_inside_negation;
		e->child->accept(this);
		m_inside_negation = inside_negation;
		m_last_node_is_evttype_field = false;
	}

	void visit(const libsinsp::filter::ast::binary_check_expr* e) override {
		m_last_node_has_codes = false;

		// If a field invariant proves the leaf is statically true or false,
		// short-circuit with the corresponding set and apply leaf-level
		// inversion (the visitor pushes negation down to leaves via De
		// Morgan's laws, so try_inversion must run here too).
		switch(evaluate_field_invariant(e)) {
		case invariant_result::known_empty:
			m_last_node_codes = code_set_t{};
			m_last_node_has_codes = true;
			m_last_node_is_evttype_field = false;
			try_inversion(m_last_node_codes);
			return;
		case invariant_result::known_all:
			m_last_node_codes = all_codes_set();
			m_last_node_has_codes = true;
			m_last_node_is_evttype_field = false;
			try_inversion(m_last_node_codes);
			return;
		case invariant_result::indeterminate:
			break;
		}

		if(is_evttype_operator(e->op)) {
			e->left->accept(this);
			if(m_last_node_is_evttype_field) {
				// note: we expect m_inside_negation and m_last_node_has_codes
				// to be handled and altered by the child node
				m_last_node_is_field_or_transformer = false;
				e->right->accept(this);
				if(m_last_node_is_field_or_transformer) {
					throw sinsp_exception(
					        "right-hand field comparisons on `evt.type`/`syscall.type` checks are "
					        "not supported "
					        "by event code search");
				}
				if(e->op == "!=") {
					// note: since we push the "negation" down to the tree leaves
					// (following de morgan's laws logic), the child node may have
					// already inverted the set of matched event type. As such,
					// inverting here again is safe for supporting both the
					// single-negation and double-negation cases.
					inversion(m_last_node_codes);
				}
				m_last_node_is_evttype_field = false;
				return;
			}
		}
		m_last_node_codes = all_codes_set();
		m_last_node_is_evttype_field = false;
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::unary_check_expr* e) override {
		e->left->accept(this);
		m_last_node_has_codes = m_last_node_is_evttype_field && e->op == "exists";
		m_last_node_codes = all_codes_set();
		m_last_node_is_evttype_field = false;
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::identifier_expr* e) override {
		// this case only happens if a macro has not yet been substituted
		// with an actual condition. Should not happen, but we handle it
		// for consistency.
		m_last_node_has_codes = false;
		m_last_node_codes = all_codes_set();
		m_last_node_is_evttype_field = false;
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::value_expr* e) override {
		m_last_node_has_codes = true;
		m_last_node_codes = names_to_codes({e->value});
		m_last_node_is_evttype_field = false;
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::list_expr* e) override {
		m_last_node_has_codes = true;
		name_set_t names;
		for(const auto& n : e->values) {
			names.insert(n);
		}
		m_last_node_codes = names_to_codes(names);
		m_last_node_is_evttype_field = false;
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::transformer_list_expr* e) override {
		for(auto& c : e->children) {
			c->accept(this);
		}
	}

	void visit(const libsinsp::filter::ast::field_expr* e) override {
		m_last_node_has_codes = false;
		m_last_node_is_field_or_transformer = true;
		m_last_node_is_evttype_field =
		        (e->field == "evt.type" || e->field == "syscall.type") && !e->arg;
		m_last_node_codes = all_codes_set();
		try_inversion(m_last_node_codes);
	}

	void visit(const libsinsp::filter::ast::field_transformer_expr* e) override {
		for(auto& c : e->values) {
			c->accept(this);
			if(m_last_node_is_evttype_field) {
				throw sinsp_exception(
				        "event code search does not support `evt.type` checks with transformers");
			}
		}
		m_last_node_is_field_or_transformer = true;
	}
};

libsinsp::events::set<ppm_sc_code> libsinsp::filter::ast::ppm_sc_codes(
        const libsinsp::filter::ast::expr* e) {
	ppm_code_visitor<libsinsp::events::set<ppm_sc_code>,
	                 libsinsp::events::all_sc_set,
	                 libsinsp::events::event_names_to_sc_set>
	        v;
// note(jasondellaluce): ppm_sc code mappings are available for linux only so far
#ifdef __linux__
	e->accept(&v);
#else
	v.m_last_node_codes = {};
#endif
	return v.m_last_node_codes;
}

libsinsp::events::set<ppm_event_code> libsinsp::filter::ast::ppm_event_codes(
        const libsinsp::filter::ast::expr* e) {
	ppm_code_visitor<libsinsp::events::set<ppm_event_code>,
	                 libsinsp::events::all_event_set,
	                 libsinsp::events::names_to_event_set>
	        v;
	e->accept(&v);
	return v.m_last_node_codes;
}
