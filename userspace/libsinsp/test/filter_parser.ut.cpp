#include <libsinsp/filter/parser.h>
#include <gtest/gtest.h>

using namespace std;
using namespace libsinsp::filter;
using namespace libsinsp::filter::ast;

static void test_equal_ast(string in, expr* ast)
{
	parser parser(in);
	try
	{
		auto res = parser.parse();
		if (!res->is_equal(ast))
		{
			FAIL() << "parsed ast is not equal to the expected one -> " << in;
		}
	}
	catch (runtime_error& e)
	{
		auto pos = parser.get_pos();
		FAIL() << "at " << pos.as_string() << ": " << e.what() << " -> " << in;
	}
};

static void test_accept(string in, ast::pos_info* out_pos = NULL)
{
	parser parser(in);
	try
	{
	   	parser.parse();
	}
	catch (runtime_error& e)
	{
		auto pos = parser.get_pos();
		FAIL() << "at " << pos.as_string() << ": " << e.what() << " -> " << in;
	}
	if (out_pos)
	{
		*out_pos = parser.get_pos();
	}
}

static void test_reject(string in)
{
	parser parser(in);
	try
	{
		parser.parse();
		FAIL() << "error expected but not received -> " << in;
	}
	catch (runtime_error& e)
	{
		// all good
	}
}

TEST(pos_info, equality_assignments)
{
	pos_info a;
	pos_info b(5, 1, 3);
	ASSERT_EQ(a.idx, 0);
	ASSERT_EQ(a.line, 1);
	ASSERT_EQ(a.col, 1);
	ASSERT_EQ(b.idx, 5);
	ASSERT_EQ(b.line, 1);
	ASSERT_EQ(b.col, 3);
	ASSERT_NE(a, b);

	a = b;
	ASSERT_EQ(a.idx, 5);
	ASSERT_EQ(a.line, 1);
	ASSERT_EQ(a.col, 3);
	ASSERT_EQ(a, b);
}

TEST(parser, supported_operators)
{
	static vector<string> expected_all = {
		"=", "==", "!=", "<=", ">=", "<", ">", "exists",
		"contains", "icontains", "bcontains", "glob", "iglob", "bstartswith",
		"startswith", "endswith", "in", "intersects", "pmatch"};
	static vector<string> expected_list_only = {
		"in", "intersects", "pmatch"};
	
	auto actual_all = parser::supported_operators();
	ASSERT_EQ(actual_all.size(), expected_all.size());
	for (auto &op : expected_all)
	{
		if (count(actual_all.begin(), actual_all.end(), op) != 1)
		{
			FAIL() << "expected support for operator: " << op;
		}
	}

	auto actual_list_only = parser::supported_operators(true);
	ASSERT_EQ(actual_list_only.size(), actual_list_only.size());
	for (auto &op : expected_list_only)
	{
		if (count(actual_list_only.begin(), actual_list_only.end(), op) != 1)
		{
			FAIL() << "expected support for list operator: " << op;
		}
	}
}

// Based on and extended Falco's parser smoke tests:
// https://github.com/falcosecurity/falco/blob/204f9ff875be035e620ca1affdf374dd1c610a98/userspace/engine/lua/parser-smoke.sh#L41
TEST(parser, parse_smoke_test)
{
	// good
	test_accept("  a");
	test_accept("(a)");
	test_accept("a and b");
	test_accept("a and b and c");
	test_accept("a and b and(c)");
	test_accept("(a)and(b)and(c)");
	test_accept("(a and b)");
	test_accept("a or b");
	test_accept("a or b or c");
	test_accept("a or b or(c)");
	test_accept("(a)or(b)or(c)");
	test_accept("(a or b)");
	test_accept("(a.a exists and b)");
	test_accept("(a.a exists) and (b)");
	test_accept("a.a exists and b");
	test_accept("a.a=1 or b.b=2 and c");
	test_accept("not (a)");
	test_accept("not(a)");
	test_accept("not (not (a))");
	test_accept("not (a.b=1)");
	test_accept("not (a.a exists)");
	test_accept("not a");
	test_accept("a.b = 1 and not a");
	test_accept("not not a");
	test_accept("(not not a)");
	test_accept("not not(a)");
	test_accept("not(not(a))");
	test_accept("not(a)and(not(b))");
	test_accept("not a.b=1");
	test_accept("not a.a exists");
	test_accept("a.b = bla");
	test_accept("a.b = 'bla'");
	test_accept("a.b = not");
	test_accept("a.b contains bla");
	test_accept("a.b icontains 'bla'");
	test_accept("a.g in (1, 'a', b)");
	test_accept("evt.dir=> and fd.name=*.log");
	test_accept("a.g in (1, 'a', b.c)");
	test_accept("a.b = a.a");
	test_accept("a and notb");
	test_accept("a or notb");
	test_accept("notz and a and b");
	test_accept("macro and not_macro");
	test_accept("macro and not not_macro");
	test_accept("macro and not(not_macro)");
	test_accept("((macro) and (not_macro))");
	test_accept("macro and and_macro");
	test_accept("((macro) and (and_macro))");
	test_accept("macro and or_macro");
	test_accept("((macro) and (or_macro))");

	// marked as bad in Falco smoke checks, but they should be good instead
	test_accept("evt.arg[0] contains /bin");
	test_accept("evt.arg[a] contains /bin");

	// bad
	test_reject("a andb");
	test_reject("aand b");
	test_reject("a and b and");
	test_reject("a and b or");
	test_reject("a and b not");
	test_reject("and a");
	test_reject("or a");
	test_reject("a or b and");
	test_reject("a or b or");
	test_reject("a or b not");
	test_reject("a not b and");
	test_reject("a not b or");
	test_reject("a not b not");
	test_reject("a orb");
	test_reject("aor b");
	test_reject("a and or b");
	test_reject("a andor b");
	test_reject("a not b");
	test_reject("a notb");
	test_reject("anot b");
	test_reject("a andnot b");
	test_reject("a andnotb");
	test_reject("(a)andnot(b)");
	test_reject("a ornot b");
	test_reject("a ornotb");
	test_reject("(a)ornot(b)");
	test_reject("evt.arg[] contains /bin");
	test_reject("a.b = b = 1");
	test_reject("(a.b = 1");
	test_reject("a.a invalidoperator xxx");
	test_reject("macro > 12");

	// marked as good in Falco smoke checks, but they should be bad instead
	test_reject("a.g in ( 1 ,, , b)");
	test_reject("#a and b; a and b");
	test_reject("#a and b; # ; ; a and b");
	test_reject("evt.dir=> and fd.name=/var/lo);g/httpd.log");
}

TEST(parser, parse_str)
{
	// valid bare strings
	test_accept("test.str = testval");
	test_accept("test.str = 0a!@#456:/\\.;!$%^&*[]{}|");

	// valid quoted strings
	test_accept("test.str = \"\"");
	test_accept("test.str = ''");
	test_accept("test.str = \"0a!@#456:/.; !$%^&*[]{}|\"");
	test_accept("test.str = \"test value\"");
	test_accept("test.str = 'test value'");

	// valid field args
	test_accept("test.str[0a!@#456:/\\.;!$%^&*(){}|] = testval");
	test_accept("test.str[aaaa1] = a");
	test_accept("test.str[1234] = a");
	test_accept("test.str[+0.25e+10] = a");
	test_accept("test.str[\"\"] = empty");
	test_accept("test.str['a aa'] = a");
	test_accept("test.str[\"test \\\"with\\\"escaping\"] = a");

	// valid string escaping
	test_accept("test.str = \"escape double quote \\\" \"");
	test_accept("test.str = \"escape double quote \\\" \"");
	test_accept("test.str = 'escape single quote \\' '");
	test_accept("test.str = 'multiple escape single quote \\' \\\\''");
	test_accept("test.str = 'mixed \"'");
	test_accept("test.str = \"mixed '\"");
	test_accept("test.str = \"bad escape \\ \" "); // todo(jasondellaluce): reject this case in the future

	// invalid bare strings
	test_reject("test.str = a,");
	test_reject("test.str = a=");
	test_reject("test.str = a('\")");

	// invalid quoted strings
	test_reject("test.str = '");
	test_reject("test.str = \"");
	test_reject("test.str = '\"");
	test_reject("test.str = \"'");

	// invalid string escaping
	test_reject("test.str = missing start quote");
	test_reject("test.str = 'missing end quote");
	test_reject("test.str = \"broken escape double quote\"\"");
	test_reject("test.str = 'broken escape single quote''");
	test_reject("test.str = \"mixed \\\'\"");
	test_reject("test.str = 'mixed \\\"'");

	// invalid field args
	test_reject("test.str[0a!@#456:/\\.;!$%^&*[]{}] = testval");
	test_reject("test.str[] = testval");
	test_reject("test.str[[] = testval");
	test_reject("test.str[]] = testval");
	test_reject("test.str['''] = a");
	test_reject("test.str[aaa\"] = a");
	test_reject("test.str[   test   ] = testval");
	test_reject("test.str[ = testval");
	test_reject("test.str] = testval");
}

TEST(parser, parse_numbers)
{
	// valid numbers
	test_accept("test.num > 1000");
	test_accept("test.num < +1");
	test_accept("test.num >= -1");
	test_accept("test.num <= 0x12345");
	test_accept("test.num <= 0XaB00AB");
	test_accept("test.num > 1.2");
	test_accept("test.num < -1.2");
	test_accept("test.num > -0.1222e+10");

	// treat numbers as strings
	// (the operator does not restrict the scope to only numbers)
	test_accept("test.str = !0.1222e+10");
	test_accept("test.str = 0xAAA.1");
	test_accept("test.str = 0aaaaa");
	test_accept("test.str = a");

	// invalid numbers
	test_reject("test.num > !0.1222e+10");
	test_reject("test.num < 0xAAA.1");
	test_reject("test.num >= 0aaaaa");
	test_reject("test.num <= a");
}

TEST(parser, parse_lists)
{
	// valid list
	test_accept("test.list in ()");
	test_accept("test.list in (a)");
	test_accept("test.list in ('single-quoted')");
	test_accept("test.list in (\"double-quoted\")");
	test_accept("test.list in (0a!@#456:/\\.;!$%^&*[]{}|)");
	test_accept("test.list in (0a!@#456:/\\.;!$%^&*[]{}|, value)");
	test_accept("test.list in (value, \"value\", 'value')");

	// valid list operators
	test_accept("test.list in (value)");
	test_accept("test.list intersects (value)");
	test_accept("test.list pmatch (value)");

	// invalid list
	test_reject("test.list in (");
	test_reject("test.list in )");
	test_reject("test.list in (value,)");
	test_reject("test.list in (value,,)");
	test_reject("test.list in (,)");
	test_reject("test.list in (,   ,)");

	// invalid list operators
	test_reject("test.list > (value)");
	test_reject("test.list = (value)");
	test_reject("test.list < (value)");
	test_reject("test.list startswith (value)");
	test_reject("test.list bstartswith (value)");
	test_reject("test.list contains (value)");
	test_reject("test.list icontains (value)");
}

TEST(parser, parse_operators)
{
	// valid operators
	test_accept("test.op exists and macro");
	test_accept("test.op exists");
	test_accept("test.op = value");
	test_accept("test.op == value");
	test_accept("test.op != value");
	test_accept("test.op glob value");
	test_accept("test.op iglob value");
	test_accept("test.op contains value");
	test_accept("test.op icontains value");
	test_accept("test.op bcontains 48545450");
	test_accept("test.op startswith value");
	test_accept("test.op bstartswith 12ab001fc5");
	test_accept("test.op endswith value");
	test_accept("test.op > 1");
	test_accept("test.op < 1");
	test_accept("test.op >= 1");
	test_accept("test.op <= 1");
	test_accept("test.op in ()");
	test_accept("test.op intersects ()");
	test_accept("test.op pmatch ()");
	test_accept("test.op in()");

	// invalid operators
	test_accept("test.op existsand macro");
	test_reject("test.op ExIsTs");
	test_reject("test.op exists something");
	test_reject("test.op ===");
	test_reject("test.op !==");
	test_reject("test.op startswithvalue");
	test_reject("test.op bstartswithvalue");
	test_reject("test.op endswithvalue");
	test_reject("test.op containsvalue");
	test_reject("test.op icontainsvalue");
	test_reject("test.op bcontainsvalue");
	test_reject("test.op globvalue");
	test_reject("test.op iglobvalue");
}

TEST(parser, parse_position_info)
{
	ast::pos_info pos;

	test_accept("a and b", &pos);
	EXPECT_EQ(pos.idx, 7);
	EXPECT_EQ(pos.line, 1);
	EXPECT_EQ(pos.col, pos.idx + 1);
	test_accept("a and b    ", &pos);
	EXPECT_EQ(pos.idx, 11);
	EXPECT_EQ(pos.line, 1);
	EXPECT_EQ(pos.col, pos.idx + 1);
	test_accept("not b", &pos);
	EXPECT_EQ(pos.idx, 5);
	EXPECT_EQ(pos.line, 1);
	EXPECT_EQ(pos.col, pos.idx + 1);
	test_accept("not b    ", &pos);
	EXPECT_EQ(pos.idx, 9);
	EXPECT_EQ(pos.line, 1);
	EXPECT_EQ(pos.col, pos.idx + 1);
	test_accept("a    ", &pos);
	EXPECT_EQ(pos.idx, 5);
	EXPECT_EQ(pos.line, 1);
	EXPECT_EQ(pos.col, pos.idx + 1);
	test_accept("a \n and \n  b", &pos);
	EXPECT_EQ(pos.idx, 12);
	EXPECT_EQ(pos.line, 3);
	EXPECT_EQ(pos.col, 4);
	test_accept("a \n and \n not \n b", &pos);
	EXPECT_EQ(pos.idx, 17);
	EXPECT_EQ(pos.line, 4);
	EXPECT_EQ(pos.col, 3);
}

// complex test case with all supported node types
TEST(parser, expr_all_node_types)
{
	std::vector<std::unique_ptr<expr>> and_children;
	and_children.push_back(unary_check_expr::create("evt.name", "", "exists"));
	and_children.push_back(binary_check_expr::create("evt.type", "", "in", list_expr::create({"a", "b"})));
	and_children.push_back(not_expr::create(binary_check_expr::create("evt.dir", "", "=", value_expr::create("<"))));

	std::vector<std::unique_ptr<expr>> or_children;
	or_children.push_back(and_expr::create(and_children));
	or_children.push_back(binary_check_expr::create("proc.name", "", "=", value_expr::create("cat")));

	std::unique_ptr<expr> ast = or_expr::create(or_children);

	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		ast.get()
	);
}

// complex example with parenthesis
TEST(parser, expr_parenthesis)
{
	std::vector<std::unique_ptr<expr>> and_children;
	and_children.push_back(unary_check_expr::create("evt.name", "", "exists"));
	and_children.push_back(binary_check_expr::create("evt.type", "", "in", list_expr::create({"a", "b"})));
	and_children.push_back(not_expr::create(binary_check_expr::create("evt.dir", "", "=", value_expr::create("<"))));

	std::vector<std::unique_ptr<expr>> or_children;
	or_children.push_back(and_expr::create(and_children));
	or_children.push_back(binary_check_expr::create("proc.name", "", "=", value_expr::create("cat")));

	std::unique_ptr<expr> ast = or_expr::create(or_children);

	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		ast.get()
	);
}

// stressing nested negation and identifiers
TEST(parser, expr_multi_negation)
{
	std::vector<std::unique_ptr<expr>> and_children;
	and_children.push_back(unary_check_expr::create("evt.name", "", "exists"));
	and_children.push_back(binary_check_expr::create("evt.type", "", "in", list_expr::create({"a", "b"})));
	and_children.push_back(not_expr::create(binary_check_expr::create("evt.dir", "", "=", value_expr::create("<"))));

	std::vector<std::unique_ptr<expr>> or_children;
	or_children.push_back(and_expr::create(and_children));
	or_children.push_back(binary_check_expr::create("proc.name", "", "=", value_expr::create("cat")));

	std::unique_ptr<expr> ast = or_expr::create(or_children);

	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		ast.get()
	);

	ast = not_expr::create(not_expr::create(value_expr::create("not_macro")));

	test_equal_ast(
		"not not not not not(not not(not not_macro))",
		ast.get()
	);
}

struct pos_visitor : public expr_visitor
{
public:
	void visit(and_expr* e) override
	{
		visit_logical_op("and", e->get_pos(), e->children);
	};

	virtual void visit(or_expr* e) override
	{
		visit_logical_op("or", e->get_pos(), e->children);
	}

	virtual void visit(not_expr* e) override
	{
		m_str += "not";
		add_pos(e->get_pos());

		e->child->accept(this);
	}

	virtual void visit(value_expr* e) override
	{
		m_str += "value";
		add_pos(e->get_pos());
	}

	virtual void visit(list_expr* e) override
	{
		m_str += "list";
		add_pos(e->get_pos());
	}

	virtual void visit(unary_check_expr* e) override
	{
		m_str += "unary";
		add_pos(e->get_pos());
	}

	virtual void visit(binary_check_expr* e) override
	{
		m_str += "binary";
		add_pos(e->get_pos());

		e->value->accept(this);
	}

	const std::string& as_string() {
		return m_str;
	};

private:

	void visit_logical_op(const char* op,
			      const pos_info& pos,
			      const std::vector<std::unique_ptr<expr>> &children)
	{
		m_str += op;
		add_pos(pos);

		for(auto&c : children)
		{
			c->accept(this);
		}
	}

	void add_pos(const pos_info& pos)
	{
		m_str += std::to_string(pos.idx) + " " +
			std::to_string(pos.line) + " " +
			std::to_string(pos.col);
	}

	std::string m_str;
};

TEST(parser, position_unary_check)
{
	parser parser("proc.name exists");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "unary0 1 1");
}

TEST(parser, position_binary_check)
{
	parser parser("proc.name=nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1value10 1 11");
}

TEST(parser, position_binary_check_params)
{
	parser parser("proc.aname[3]=nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1value14 1 15");
}

TEST(parser, position_binary_check_space_before)
{
	parser parser("proc.name =nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1value11 1 12");
}

TEST(parser, position_binary_check_space_after)
{
	parser parser("proc.name= nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1value11 1 12");
}

TEST(parser, position_binary_check_space_both)
{
	parser parser("proc.name = nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1value12 1 13");
}

TEST(parser, position_binary_check_list)
{
	parser parser("proc.name in (nginx, apache)");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1list13 1 14");
}

TEST(parser, position_binary_check_list_space_after)
{
	parser parser("proc.name in ( nginx, apache)");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "binary0 1 1list13 1 14");
}

TEST(parser, position_not)
{
	parser parser("not proc.name=nginx");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "not0 1 1binary4 1 5value14 1 15");
}

TEST(parser, position_or)
{
	parser parser("proc.name=nginx or proc.name=apache");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "or0 1 1binary0 1 1value10 1 11binary19 1 20value29 1 30");
}

TEST(parser, position_or_parens)
{
	parser parser("(proc.name=nginx or proc.name=apache)");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "or1 1 2binary1 1 2value11 1 12binary20 1 21value30 1 31");
}

TEST(parser, position_and)
{
	parser parser("proc.name=nginx and proc.name=apache");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "and0 1 1binary0 1 1value10 1 11binary20 1 21value30 1 31");
}

TEST(parser, position_and_parens)
{
	parser parser("(proc.name=nginx and proc.name=apache)");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "and1 1 2binary1 1 2value11 1 12binary21 1 22value31 1 32");
}

TEST(parser, position_complex)
{
	parser parser("(proc.aname[2]=nginx and evt.type in (connect,accept)) or (not fd.name exists) or (proc.name=apache and evt.type=switch)");

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "or0 1 1and1 1 2binary1 1 2value15 1 16binary25 1 26list37 1 38not59 1 60unary63 1 64and83 1 84binary83 1 84value93 1 94binary104 1 105value113 1 114");
}

TEST(parser, position_complex_multiline)
{
	const char* str = R"EOF(
(proc.aname[2]=nginx
     and evt.type in (connect,accept))
   or (not fd.name exists)
   or (proc.name=apache
       and evt.type=switch))EOF";

	parser parser(str);

	auto expr = parser.parse();

	pos_visitor pv;

	expr->accept(&pv);

	EXPECT_STREQ(pv.as_string().c_str(), "or0 1 1and2 2 2binary2 2 2value16 2 16binary31 3 10list43 3 22not68 4 8unary72 4 12and95 5 8binary95 5 8value105 5 18binary123 6 12value132 6 21");
}

