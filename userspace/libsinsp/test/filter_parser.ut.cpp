#include <filter/parser.h>
#include <gtest.h>

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
		delete res;
	}
	catch (runtime_error& e)
	{
		auto pos = parser.get_pos();
		FAIL() << "at " << pos.as_string() << ": " << e.what() << " -> " << in;
	}
	delete ast;
};

static void test_accept(string in)
{
	parser parser(in);
	try
	{
	   	delete parser.parse();
	}
	catch (runtime_error& e)
	{
		auto pos = parser.get_pos();
		FAIL() << "at " << pos.as_string() << ": " << e.what() << " -> " << in;
	}
}

static void test_reject(string in)
{
	parser parser(in);
	try
	{
		delete parser.parse();
		FAIL() << "error expected but not received";
	}
	catch (runtime_error& e)
	{
		// all good
	}
}

// Inspired by Falco's parser smoke tests:
// https://github.com/falcosecurity/falco/blob/204f9ff875be035e620ca1affdf374dd1c610a98/userspace/engine/lua/parser-smoke.sh#L41
TEST(parser, smoke_accept_reject)
{
	// good
	test_accept("  a");
	test_accept("a and b");
	test_accept("(a)");
	test_accept("(a and b)");
	test_accept("(a.a exists and b)");
	test_accept("(a.a exists) and (b)");
	test_accept("a.a exists and b");
	test_accept("a.a=1 or b.b=2 and c");
	test_accept("not (a)");
	test_accept("not (not (a))");
	test_accept("not (a.b=1)");
	test_accept("not (a.a exists)");
	test_accept("not a");
	test_accept("a.b = 1 and not a");
	test_accept("not not a");
	test_accept("(not not a)");
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

	// marked as bad in Falco smoke checks, but they should be good instead
	test_accept("evt.arg[0] contains /bin");
	test_accept("evt.arg[a] contains /bin");

	// bad
	test_reject("evt.arg[] contains /bin");
	test_reject("a.b = b = 1");
	test_reject("(a.b = 1");
	test_reject("a.a invalidoperator xxx");

	// marked as good in Falco smoke checks, but they should be bad instead
	test_reject("a.g in ( 1 ,, , b)");
	test_reject("#a and b; a and b");
	test_reject("#a and b; # ; ; a and b");
	test_reject("evt.dir=> and fd.name=/var/lo);g/httpd.log");
	test_reject("notz and a and b");
}

// complex test case with all supported node types
TEST(parser, expr_all_node_types)
{
	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		new or_expr({
			new and_expr({
				new unary_check_expr("evt.name", "", "exists"), 
				new binary_check_expr("evt.type", "", "in", new list_expr({"a", "b"})),
				new not_expr(
					new binary_check_expr("evt.dir", "", "=", new value_expr("<"))
				),
			}),
			new binary_check_expr("proc.name", "", "=", new value_expr("cat")),
		})
	);
}

// complex example with parenthesis
TEST(parser, expr_parenthesis)
{
	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		new or_expr({
			new and_expr({
				new unary_check_expr("evt.name", "", "exists"), 
				new binary_check_expr("evt.type", "", "in", new list_expr({"a", "b"})),
				new not_expr(
					new binary_check_expr("evt.dir", "", "=", new value_expr("<"))
				),
			}),
			new binary_check_expr("proc.name", "", "=", new value_expr("cat")),
		})
	);
}

// stressing nested negation and identifiers
TEST(parser, expr_multi_negation)
{
	test_equal_ast(
		"evt.name exists and evt.type in (a, b) and not evt.dir=< or proc.name=cat",
		new or_expr({
			new and_expr({
				new unary_check_expr("evt.name", "", "exists"), 
				new binary_check_expr("evt.type", "", "in", new list_expr({"a", "b"})),
				new not_expr(
					new binary_check_expr("evt.dir", "", "=", new value_expr("<"))
				),
			}),
			new binary_check_expr("proc.name", "", "=", new value_expr("cat")),
		})
	);
}