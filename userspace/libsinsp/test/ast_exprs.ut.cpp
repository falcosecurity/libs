// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libsinsp/filter/parser.h>
#include <gtest/gtest.h>

using namespace libsinsp::filter::ast;

static std::unique_ptr<expr> make_expr(const std::string& cond) {
	libsinsp::filter::parser p(cond);

	std::unique_ptr<expr> e = p.parse();

	return e;
}

TEST(ast, compare_binary_check_exprs) {
	std::unique_ptr<expr> e1 = make_expr("evt.num >= 0");
	std::unique_ptr<expr> e2 = make_expr("evt.num = 0");
	ASSERT_FALSE(e1->is_equal(e2.get()));
}

TEST(ast, compare_binary_check_exprs_with_modifier) {
	// same modifier → equal
	std::unique_ptr<expr> e1 = make_expr("proc.name == oneof (cat, nginx)");
	std::unique_ptr<expr> e2 = make_expr("proc.name == oneof (cat, nginx)");
	ASSERT_TRUE(e1->is_equal(e2.get()));

	// different modifier → not equal
	std::unique_ptr<expr> e3 = make_expr("proc.name == anyof (cat, nginx)");
	ASSERT_FALSE(e1->is_equal(e3.get()));

	// different base operator → not equal
	std::unique_ptr<expr> e4 = make_expr("proc.name != oneof (cat, nginx)");
	ASSERT_FALSE(e1->is_equal(e4.get()));

	// modifier vs no modifier (same base op, different rhs type) → not equal
	std::unique_ptr<expr> e5 = make_expr("proc.name == cat");
	ASSERT_FALSE(e1->is_equal(e5.get()));
}

TEST(ast, compare_modifier_list_vs_plain_list) {
	// modifier check with list rhs vs list operator (in) with same list → not equal
	std::unique_ptr<expr> e_mod = make_expr("proc.name == oneof (cat, nginx)");
	std::unique_ptr<expr> e_in = make_expr("proc.name in (cat, nginx)");
	ASSERT_FALSE(e_mod->is_equal(e_in.get()));
}

TEST(ast, modifier_all_variants) {
	std::unique_ptr<expr> oneof_eq = make_expr("proc.name == oneof (cat)");
	std::unique_ptr<expr> anyof_eq = make_expr("proc.name == anyof (cat)");
	std::unique_ptr<expr> allof_eq = make_expr("proc.name == allof (cat)");

	// each modifier produces a distinct op string
	ASSERT_FALSE(oneof_eq->is_equal(anyof_eq.get()));
	ASSERT_FALSE(oneof_eq->is_equal(allof_eq.get()));
	ASSERT_FALSE(anyof_eq->is_equal(allof_eq.get()));

	// same modifier, same operator, different list → not equal
	std::unique_ptr<expr> oneof_eq2 = make_expr("proc.name == oneof (nginx)");
	ASSERT_FALSE(oneof_eq->is_equal(oneof_eq2.get()));
}

TEST(ast, modifier_as_string_roundtrip) {
	// as_string output contains the modifier and is itself parseable (stable roundtrip)
	auto check = [](const std::string& input, const std::string& expected_str) {
		libsinsp::filter::parser p1(input);
		auto e1 = p1.parse();
		std::string s1 = as_string(e1.get());
		EXPECT_EQ(s1, expected_str) << "as_string mismatch for: " << input;

		libsinsp::filter::parser p2(s1);
		auto e2 = p2.parse();
		EXPECT_TRUE(e1->is_equal(e2.get())) << "roundtrip not equal for: " << input;
	};

	check("proc.name == oneof (cat, nginx)", "proc.name == oneof (cat, nginx)");
	check("proc.name != anyof (cat, nginx)", "proc.name != anyof (cat, nginx)");
	check("proc.name = allof (cat)", "proc.name = allof (cat)");
}
