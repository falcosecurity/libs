#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <gtest/gtest.h>
#include <list>

using namespace std;

// A mock filtercheck that returns always true or false depending on
// the passed-in field name. The operation is ignored.
class mock_compiler_filter_check : public sinsp_filter_check
{
public:
	inline int32_t parse_field_name(const char* str, bool a, bool n) override
	{
		m_name = string(str);
		return 0;
	}

	inline bool compare(sinsp_evt*) override
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
		m_value = string(str, l);
	}

	inline bool extract(sinsp_evt *e, OUT vector<extract_value_t>& v, bool) override
	{
		return false;
	}

	string m_name;
	string m_value;
};

// A factory that creates mock filterchecks
class mock_compiler_filter_factory: public sinsp_filter_factory
{
public:
	mock_compiler_filter_factory(sinsp *inspector): sinsp_filter_factory(inspector, m_filterlist) {}

	inline std::unique_ptr<sinsp_filter> new_filter() const override
	{
		return std::make_unique<sinsp_filter>(m_inspector);
	}

	inline std::unique_ptr<sinsp_filter_check> new_filtercheck(const char *fldname) const override
	{
		return std::make_unique<mock_compiler_filter_check>();
	}

	inline list<sinsp_filter_factory::filter_fieldclass_info> get_fields() const override
	{
		return m_list;
	}

	sinsp_filter_check_list m_filterlist;
	list<sinsp_filter_factory::filter_fieldclass_info> m_list;
};

// Compile a filter, pass a mock event to it, and
// check that the result of the boolean evaluation is
// the expected one
void test_filter_run(bool result, string filter_str)
{
	sinsp inspector;
	std::shared_ptr<sinsp_filter_factory> factory;
	factory.reset(new mock_compiler_filter_factory(&inspector));
	sinsp_filter_compiler compiler(factory, filter_str);
	try
	{
		auto filter = compiler.compile();
		if (filter->run(NULL) != result)
		{
			FAIL() << filter_str << " -> unexpected '" << (result ? "false" : "true") << "' result";
		}
	}
	catch(const sinsp_exception& e)
	{
		FAIL() << filter_str << " -> " << e.what();
	}
}

void test_filter_compile(
		std::shared_ptr<sinsp_filter_factory> factory,
		string filter_str,
		bool expect_fail=false)
{
	sinsp_filter_compiler compiler(factory, filter_str);
	try
	{
		auto filter = compiler.compile();
		if (expect_fail)
		{
			FAIL() << filter_str << " -> expected failure but compilation was successful";
		}
	}
	catch(const sinsp_exception& e)
	{
		if (!expect_fail)
		{
			FAIL() << filter_str << " -> " << e.what();
		}
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
	test_filter_run(false, "not(c.true=1)");
	test_filter_run(true,  "not not c.true=1");
	test_filter_run(true,  "not not(c.true=1)");
	test_filter_run(true,  "not (not c.true=1)");
	test_filter_run(false, "not not not c.true=1");
	test_filter_run(false, "not not not(c.true=1)");
	test_filter_run(false, "not (not (not c.true=1))");
	test_filter_run(false, "not(not(not c.true=1))");
	test_filter_run(true,  "not not not not c.true=1");
	test_filter_run(true,  "not not(not not c.true=1)");
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
	sinsp inspector;
	std::shared_ptr<sinsp_filter_factory> factory(new mock_compiler_filter_factory(&inspector));

	// valid operators
	test_filter_compile(factory, "c.true exists");
	test_filter_compile(factory, "c.true = value");
	test_filter_compile(factory, "c.true == value");
	test_filter_compile(factory, "c.true != value");
	test_filter_compile(factory, "c.true glob value");
	test_filter_compile(factory, "c.true contains value");
	test_filter_compile(factory, "c.true icontains value");
	test_filter_compile(factory, "c.true bcontains 12ab001fc5");
	test_filter_compile(factory, "c.true startswith value");
	test_filter_compile(factory, "c.true bstartswith 48545450");
	test_filter_compile(factory, "c.true endswith value");
	test_filter_compile(factory, "c.true > 1");
	test_filter_compile(factory, "c.true < 1");
	test_filter_compile(factory, "c.true >= 1");
	test_filter_compile(factory, "c.true <= 1");
	test_filter_compile(factory, "c.true in ()");
	test_filter_compile(factory, "c.true intersects ()");
	test_filter_compile(factory, "c.true pmatch ()");
	test_filter_compile(factory, "c.true in()");

	// operators incompatibilites
	test_filter_compile(factory, "c.true bstartswith g", true);
	test_filter_compile(factory, "c.true bstartswith 123Z", true);
	test_filter_compile(factory, "c.true bstartswith abc_1", true);
	test_filter_compile(factory, "c.true bstartswith g", true);
	test_filter_compile(factory, "c.true bstartswith 123Z", true);
	test_filter_compile(factory, "c.true bstartswith abc_1", true);
}

TEST(sinsp_filter_compiler, complex_filter)
{
	sinsp inspector;
	std::shared_ptr<sinsp_filter_factory> factory(new mock_compiler_filter_factory(&inspector));

	// This is derived from the Falco default rule
	// "Unexpected outbound connection destination" coming from here:
	// https://github.com/falcosecurity/falco/blob/167c5bc6910ba9e48fbd1548686146c9dad850fd/rules/falco_rules.yaml#L381
	// The rule has been expanded with all its Falco macros, lists,
	// and exceptions, so it makes a good integration test case.
	string filter_str =
		"("
		"	(evt.type = open or evt.type = openat)"
		"	and evt.is_open_write = true"
		"	and fd.typechar = f"
		"	and fd.num >= 0"
		")"
		"and ("
		"	fd.filename in ("
		"		.bashrc, .bash_profile, .bash_history, .bash_login,"
		"		.bash_logout, .inputrc, .profile, .cshrc, .login, .logout,"
		"		.history, .tcshrc, .cshdirs, .zshenv, .zprofile, .zshrc,"
		"		.zlogin, .zlogout"
		"	)"
		"	or fd.name in (/etc/profile, /etc/bashrc, /etc/csh.cshrc, /etc/csh.login)"
		"	or fd.directory in (/etc/zsh)"
		")"
		"and not proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash)"
		"and not ("
		"	proc.name = exe"
		"	and (proc.cmdline contains \"/var/lib/docker\" or proc.cmdline contains '/var/run/docker')"
		"	and proc.pname in (dockerd, docker, dockerd-current, docker-current)"
		")";

	test_filter_compile(factory, filter_str);
}
