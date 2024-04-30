#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <gtest/gtest.h>
#include <list>
#include <sinsp_with_test_input.h>

using namespace std;

// A mock filtercheck that returns always true or false depending on
// the passed-in field name. The operation is ignored.
class mock_compiler_filter_check : public sinsp_filter_check
{
public:
	int32_t parse_field_name(std::string_view str, bool alloc_state, bool needed_for_filtering) override
	{
		m_name = str;
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

	inline void add_filter_value(std::unique_ptr<sinsp_filter_check> f) override
	{
		throw sinsp_exception("unexpected right-hand side filter comparison");
	}

	inline bool extract(sinsp_evt *e, vector<extract_value_t>& v, bool) override
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

	inline std::unique_ptr<sinsp_filter_check> new_filtercheck(std::string_view fldname) const override
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
	auto factory = std::make_shared<mock_compiler_filter_factory>(&inspector);
	sinsp_filter_compiler compiler(factory, filter_str);
	try
	{
		auto filter = compiler.compile();
		if (filter->run(NULL) != result)
		{
			FAIL() << filter_str << " -> unexpected '" << (result ? "false" : "true") << "' result";
		}
	}
	catch(const std::exception& e)
	{
		FAIL() << filter_str << " -> " << e.what();
	}
	catch(...)
	{
		FAIL() << filter_str << " -> " << "UNKNOWN ERROR";
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
	catch(const std::exception& e)
	{
		if (!expect_fail)
		{
			FAIL() << filter_str << " -> " << e.what();
		}
	}
	catch(...)
	{
		if (!expect_fail)
		{
			FAIL() << filter_str << " -> " << "UNKNOWN ERROR";
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

//////////////////////////////
// Test filter strings against real events.
//////////////////////////////

static bool evaluate_filter_str(sinsp* inspector, std::string filter_str, sinsp_evt* evt)
{
	sinsp_filter_check_list filter_list;
	sinsp_filter_compiler compiler(std::make_shared<sinsp_filter_factory>(inspector, filter_list), filter_str);
	auto filter = compiler.compile();
	return filter->run(evt);
}

TEST_F(sinsp_with_test_input, filter_simple_evaluation)
{
	// Basic case just to assert that the basic setup works
	add_default_init_thread();
	open_inspector();
	ASSERT_TRUE(evaluate_filter_str(&m_inspector, "(evt.type = getcwd)", generate_getcwd_failed_entry_event()));
	ASSERT_TRUE(
		evaluate_filter_str(&m_inspector, "(evt.arg.res = val(evt.arg.res))", generate_getcwd_failed_entry_event()));
}

TEST_F(sinsp_with_test_input, filter_val_transformer)
{
	add_default_init_thread();
	open_inspector();
	// Please note that with `evt.args = evt.args` we are evaluating the field `evt.args` against the const value
	// `evt.args`.
	ASSERT_FALSE(evaluate_filter_str(&m_inspector, "(evt.args = evt.args)", generate_getcwd_failed_entry_event()));
	ASSERT_TRUE(evaluate_filter_str(&m_inspector, "(evt.args = val(evt.args))", generate_getcwd_failed_entry_event()));

	// val() expects a field inside it is not a transformer
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "(syscall.type = val(tolower(toupper(syscall.type))))",
					 generate_getcwd_failed_entry_event()),
		     sinsp_exception);

	// val() is not supported on the left
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "(val(evt.args) = val(evt.args))", generate_getcwd_failed_entry_event()),
		     sinsp_exception);

	// val() cannot support a list
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "(syscall.type = val(syscall.type, evt.type))",
					 generate_getcwd_failed_entry_event()),
		     sinsp_exception);
}

TEST_F(sinsp_with_test_input, filter_transformers_combination)
{
	add_default_init_thread();
	open_inspector();

	ASSERT_TRUE(
		evaluate_filter_str(&m_inspector, "(tolower(syscall.type) = getcwd)", generate_getcwd_failed_entry_event()));

	ASSERT_TRUE(
		evaluate_filter_str(&m_inspector, "(toupper(syscall.type) = GETCWD)", generate_getcwd_failed_entry_event()));

	ASSERT_TRUE(evaluate_filter_str(&m_inspector, "(tolower(toupper(syscall.type)) = getcwd)",
					generate_getcwd_failed_entry_event()));

	ASSERT_TRUE(evaluate_filter_str(&m_inspector, "(tolower(syscall.type) = tolower(syscall.type))",
					generate_getcwd_failed_entry_event()));
	ASSERT_TRUE(evaluate_filter_str(&m_inspector, "(toupper(syscall.type) = toupper(syscall.type))",
					generate_getcwd_failed_entry_event()));
	ASSERT_TRUE(evaluate_filter_str(&m_inspector,
					"(tolower(toupper(syscall.type)) = tolower(toupper(syscall.type)))",
					generate_getcwd_failed_entry_event()));
}

TEST_F(sinsp_with_test_input, filter_different_types)
{
	add_default_init_thread();
	open_inspector();

	// The 2 fields checks have different types
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "syscall.type = val(evt.is_wait)", generate_getcwd_failed_entry_event()),
		     sinsp_exception);
}

TEST_F(sinsp_with_test_input, filter_not_supported_rhs_field)
{
	add_default_init_thread();
	open_inspector();

	// `evt.around` cannot be used as a rhs filter check
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "evt.buflen.in = val(evt.around[1404996934793590564])",
					 generate_getcwd_failed_entry_event()),
		     sinsp_exception);

	// `evt.around` cannot support a rhs filter check
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "evt.around[1404996934793590564] = val(evt.buflen.in)",
					 generate_getcwd_failed_entry_event()),
		     sinsp_exception);
}

TEST_F(sinsp_with_test_input, filter_not_supported_transformers)
{
	add_default_init_thread();
	open_inspector();

	// `evt.rawarg` doesn't support a transformer
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "toupper(evt.rawarg.res) = -1", generate_getcwd_failed_entry_event()),
		     sinsp_exception);
}

TEST_F(sinsp_with_test_input, filter_transformers_wrong_input_type)
{
	add_default_init_thread();
	open_inspector();

	//  These transformers are not supported on `PT_INT64` type
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "toupper(evt.rawres) = -1", generate_getcwd_failed_entry_event()),
		     sinsp_exception);
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "tolower(evt.rawres) = -1", generate_getcwd_failed_entry_event()),
		     sinsp_exception);
	ASSERT_THROW(evaluate_filter_str(&m_inspector, "b64(evt.rawres) = -1", generate_getcwd_failed_entry_event()),
		     sinsp_exception);
}
