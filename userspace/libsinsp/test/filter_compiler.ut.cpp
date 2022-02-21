#include <sinsp.h>
#include <filter.h>
#include <gtest.h>
#include <list>

using namespace std;

// A mock filtercheck that returns always true or false depending on
// the passed-in field name. The operation is ignored.
class mock_compiler_filter_check: public gen_event_filter_check
{
public:
	inline int32_t parse_field_name(const char* str, bool a, bool n) override
	{
		m_name = string(str);
		return 0;
	}

	inline bool compare(gen_event *evt) override
	{
		if (m_name == "c.true")
		{
			return true;
		}
		if (m_name == "c.false")
		{
			return false;
		}
		if (m_name == "c.doublequote")
		{
			return m_value == "hello \"quoted\"";
		}
		if (m_name == "c.singlequote")
		{
			return m_value == "hello 'quoted'";
		}
		return false;
	}

	inline void add_filter_value(const char* str, uint32_t l, uint32_t i) override
	{ 
		m_value = string(str);
	}

	inline uint8_t* extract(gen_event *e, uint32_t* l, bool s) override { return NULL; }

	string m_name;
	string m_value;
};

// A factory that creates mock filterchecks
class mock_compiler_filter_factory: public gen_event_filter_factory
{
public:
	inline gen_event_filter *new_filter() override
	{
		return new sinsp_filter(NULL);
	}

	inline gen_event_filter_check *new_filtercheck(const char *fldname) override
	{
		return new mock_compiler_filter_check();
	}

	inline list<gen_event_filter_factory::filter_fieldclass_info> get_fields() override
	{
		return m_list;
	}

	list<gen_event_filter_factory::filter_fieldclass_info> m_list;
};

// Compile a filter, pass a mock event to it, and
// check that the result of the boolean evaluation is
// the expected one
void test_filter_run(bool result, string filter_str)
{
	std::shared_ptr<gen_event_filter_factory> factory;
	factory.reset(new mock_compiler_filter_factory());
	sinsp_filter_compiler compiler(factory, filter_str);
	try
	{
		auto filter = compiler.compile();
		if (filter->run(NULL) != result)
		{
			FAIL() << filter_str << " -> unexpected '" << (result ? "false" : "true") << "' result";
		}
		delete filter;
	}
	catch(const sinsp_exception& e)
	{
		FAIL() << filter_str << " -> " << e.what();
	}
}

void test_filter_compile(string filter_str)
{
	std::shared_ptr<gen_event_filter_factory> factory;
	factory.reset(new mock_compiler_filter_factory());
	sinsp_filter_compiler compiler(factory, filter_str);
	try
	{
		auto filter = compiler.compile();
		delete filter;
	}
	catch(const sinsp_exception& e)
	{
		FAIL() << filter_str << " -> " << e.what();
	}
}

// In each of these test cases, we compile filter expression
// of which we can control the truth state of each filtercheck,
// so that we can deterministically check the result of running
// a mock event in the compiled filters. The purpose is verifying
// that the compiler constructs valid boolean expressions.
TEST(sinsp_filter_compiler, boolean_evaluation)
{
	test_filter_run(true,  "c.true=1");
	test_filter_run(false, "c.false=1");
	test_filter_run(false, "not c.true=1");
	test_filter_run(true,  "not not c.true=1");
	test_filter_run(true,  "not (not c.true=1)");
	test_filter_run(false, "not not not c.true=1");
	test_filter_run(false, "not (not (not c.true=1))");
	test_filter_run(true,  "not not not not c.true=1");
	test_filter_run(true,  "c.true=1 and c.true=1");
	test_filter_run(false, "c.true=1 and c.false=1");
	test_filter_run(false, "c.false=1 and c.true=1");
	test_filter_run(false, "c.false=1 and c.false=1");
	test_filter_run(false, "c.true=1 and not c.true=1");
	test_filter_run(false, "not c.true=1 and c.true=1");
	test_filter_run(true,  "c.true=1 or c.true=1");
	test_filter_run(true,  "c.true=1 or c.false=1");
	test_filter_run(true,  "c.false=1 or c.true=1");
	test_filter_run(false, "c.false=1 or c.false=1");
	test_filter_run(true,  "c.false=1 or not c.false=1");
	test_filter_run(true,  "not c.false=1 or c.false=1");
	test_filter_run(true,  "c.true=1 or c.true=1 and c.false=1");
	test_filter_run(false, "(c.true=1 or c.true=1) and c.false=1");
	test_filter_run(true,  "not (not (c.true=1 or c.true=1) and c.false=1)");
	test_filter_run(false, "not (c.false=1 or c.false=1 or c.true=1)");
	test_filter_run(true,  "not (c.false=1 or c.false=1 and not c.true=1)");
	test_filter_run(false, "not (c.false=1 or not c.false=1 and c.true=1)");
	test_filter_run(false, "not ((c.false=1 or not (c.false=1 and not c.true=1)) and c.true=1)");
}

TEST(sinsp_filter_compiler, str_escape)
{
	test_filter_run(true, "c.singlequote = 'hello \\'quoted\\''");
	test_filter_run(true, "c.singlequote = \"hello 'quoted'\"");
	test_filter_run(true, "c.doublequote = 'hello \"quoted\"'");
	test_filter_run(true, "c.doublequote = \"hello \\\"quoted\\\"\"");

	test_filter_run(false, "c.singlequote = 'hello \\\\'quoted\\\\''");
	test_filter_run(false, "c.singlequote = \"hello ''quoted''\"");
	test_filter_run(false, "c.doublequote = \"hello \\\\\"quoted\\\\\"\"");
	test_filter_run(false, "c.doublequote = 'hello \"\"quoted\"\"'");
}

TEST(sinsp_filter_compiler, supported_operators)
{
	// valid operators
	test_filter_compile("c.true exists");
	test_filter_compile("c.true = value");
	test_filter_compile("c.true == value");
	test_filter_compile("c.true != value");
	test_filter_compile("c.true glob value");
	test_filter_compile("c.true contains value");
	test_filter_compile("c.true icontains value");
	test_filter_compile("c.true startswith value");
	test_filter_compile("c.true endswith value");
	test_filter_compile("c.true > 1");
	test_filter_compile("c.true < 1");
	test_filter_compile("c.true >= 1");
	test_filter_compile("c.true <= 1");
	test_filter_compile("c.true in ()");
	test_filter_compile("c.true intersects ()");
	test_filter_compile("c.true pmatch ()");
	test_filter_compile("c.true in()");
}
