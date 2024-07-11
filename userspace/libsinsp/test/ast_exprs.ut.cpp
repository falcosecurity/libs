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

static std::unique_ptr<expr> make_expr(const std::string& cond)
{
	libsinsp::filter::parser p(cond);

	std::unique_ptr<expr> e = p.parse();

	return e;
}

TEST(ast, compare_binary_check_exprs)
{
	std::unique_ptr<expr> e1 = make_expr("evt.num >= 0");
	std::unique_ptr<expr> e2 = make_expr("evt.num = 0");
	ASSERT_FALSE(e1->is_equal(e2.get()));
}
