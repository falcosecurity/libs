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
		if (str == "c.buffer")
		{
			m_field_info.m_type = PT_BYTEBUF;
		}
		return 0;
	}

	inline bool compare(sinsp_evt*) override
	{
		if (m_name == "c.true")
		{
			return true;
		}
		if (m_name == "c.false" || m_name == "c.buffer")
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

	const filtercheck_field_info* get_field_info() const override
	{
		return &m_field_info;
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

	std::string m_name;
	std::string m_value;
	filtercheck_field_info m_field_info{PT_CHARBUF, 0, PF_NA, "", "", ""};
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
	test_filter_compile(factory, "c.true startswith value");
	test_filter_compile(factory, "c.true endswith value");
	test_filter_compile(factory, "c.true > 1");
	test_filter_compile(factory, "c.true < 1");
	test_filter_compile(factory, "c.true >= 1");
	test_filter_compile(factory, "c.true <= 1");
	test_filter_compile(factory, "c.true in ()");
	test_filter_compile(factory, "c.true intersects ()");
	test_filter_compile(factory, "c.true pmatch ()");
	test_filter_compile(factory, "c.true in()");
	test_filter_compile(factory, "c.buffer bcontains 12ab001fc5");
	test_filter_compile(factory, "c.buffer bstartswith 48545450");

	// operators incompatibilites
	test_filter_compile(factory, "c.buffer bstartswith g", true);
	test_filter_compile(factory, "c.buffer bstartswith 123Z", true);
	test_filter_compile(factory, "c.buffer bstartswith abc_1", true);
	test_filter_compile(factory, "c.buffer bstartswith g", true);
	test_filter_compile(factory, "c.buffer bstartswith 123Z", true);
	test_filter_compile(factory, "c.buffer bstartswith abc_1", true);
}

TEST(sinsp_filter_compiler, operators_field_types_compatibility)
{
	sinsp inspector;
	sinsp_filter_check_list filterlist;
	auto factory = std::make_shared<sinsp_filter_factory>(&inspector, filterlist);

	// PT_ABSTIME
	test_filter_compile(factory, "evt.rawtime exists");
	test_filter_compile(factory, "evt.rawtime = 1");
	test_filter_compile(factory, "evt.rawtime != 1");
	test_filter_compile(factory, "evt.rawtime < 1");
	test_filter_compile(factory, "evt.rawtime <= 1");
	test_filter_compile(factory, "evt.rawtime > 1");
	test_filter_compile(factory, "evt.rawtime >= 1");
	test_filter_compile(factory, "evt.rawtime contains 1", true);
	test_filter_compile(factory, "evt.rawtime in (1)");
	test_filter_compile(factory, "evt.rawtime intersects (1)");
	test_filter_compile(factory, "evt.rawtime icontains 1", true);
	test_filter_compile(factory, "evt.rawtime startswith 1", true);
	test_filter_compile(factory, "evt.rawtime glob 1", true);
	test_filter_compile(factory, "evt.rawtime pmatch (1)", true);
	test_filter_compile(factory, "evt.rawtime endswith 1", true);
	test_filter_compile(factory, "evt.rawtime bcontains 303000", true);
	test_filter_compile(factory, "evt.rawtime bstartswith 303000", true);
	test_filter_compile(factory, "evt.rawtime iglob 1", true);
	
	// PT_BOOL
	test_filter_compile(factory, "evt.is_io exists");
	test_filter_compile(factory, "evt.is_io = true");
	test_filter_compile(factory, "evt.is_io != true");
	test_filter_compile(factory, "evt.is_io < true", true);
	test_filter_compile(factory, "evt.is_io <= true", true);
	test_filter_compile(factory, "evt.is_io > true", true);
	test_filter_compile(factory, "evt.is_io >= true", true);
	test_filter_compile(factory, "evt.is_io contains true", true);
	test_filter_compile(factory, "evt.is_io in (true)");
	test_filter_compile(factory, "evt.is_io intersects (true)");
	test_filter_compile(factory, "evt.is_io icontains true", true);
	test_filter_compile(factory, "evt.is_io startswith true", true);
	test_filter_compile(factory, "evt.is_io glob true", true);
	test_filter_compile(factory, "evt.is_io pmatch (true)", true);
	test_filter_compile(factory, "evt.is_io endswith true", true);
	test_filter_compile(factory, "evt.is_io bcontains 7472756500", true);
	test_filter_compile(factory, "evt.is_io bstartswith 7472756500", true);
	test_filter_compile(factory, "evt.is_io iglob true", true);

	// PT_BYTEBUF
	test_filter_compile(factory, "evt.buffer exists");
	test_filter_compile(factory, "evt.buffer = test");
	test_filter_compile(factory, "evt.buffer != test");
	test_filter_compile(factory, "evt.buffer < 1", true);
	test_filter_compile(factory, "evt.buffer <= 2", true);
	test_filter_compile(factory, "evt.buffer > 3", true);
	test_filter_compile(factory, "evt.buffer >= 4", true);
	test_filter_compile(factory, "evt.buffer contains test");
	test_filter_compile(factory, "evt.buffer in (test)");
	test_filter_compile(factory, "evt.buffer intersects (test)");
	test_filter_compile(factory, "evt.buffer icontains test", true);
	test_filter_compile(factory, "evt.buffer startswith test");
	test_filter_compile(factory, "evt.buffer glob test", true);
	test_filter_compile(factory, "evt.buffer pmatch (test)", true);
	test_filter_compile(factory, "evt.buffer endswith test");
	test_filter_compile(factory, "evt.buffer bcontains 303000");
	test_filter_compile(factory, "evt.buffer bstartswith 303000");
	test_filter_compile(factory, "evt.buffer iglob test", true);

	// PT_CHARBUF
	test_filter_compile(factory, "fd.name exists");
	test_filter_compile(factory, "fd.name = true");
	test_filter_compile(factory, "fd.name != true");
	test_filter_compile(factory, "fd.name < 1");
	test_filter_compile(factory, "fd.name <= 1");
	test_filter_compile(factory, "fd.name > 1");
	test_filter_compile(factory, "fd.name >= 1");
	test_filter_compile(factory, "fd.name contains true");
	test_filter_compile(factory, "fd.name in (true)");
	test_filter_compile(factory, "fd.name intersects (true)");
	test_filter_compile(factory, "fd.name icontains true");
	test_filter_compile(factory, "fd.name startswith true");
	test_filter_compile(factory, "fd.name glob true");
	test_filter_compile(factory, "fd.name pmatch (true)");
	test_filter_compile(factory, "fd.name endswith true");
	test_filter_compile(factory, "fd.name bcontains 303000", true);
	test_filter_compile(factory, "fd.name bstartswith 303000", true);
	test_filter_compile(factory, "fd.name iglob true");

	// PT_DOUBLE
	test_filter_compile(factory, "thread.cpu exists");
	test_filter_compile(factory, "thread.cpu = 1");
	// note: floating point values still not supported
	test_filter_compile(factory, "thread.cpu = 1.0", true);
	test_filter_compile(factory, "thread.cpu != 1");
	test_filter_compile(factory, "thread.cpu < 1");
	test_filter_compile(factory, "thread.cpu <= 1");
	test_filter_compile(factory, "thread.cpu > 1");
	test_filter_compile(factory, "thread.cpu >= 1");
	test_filter_compile(factory, "thread.cpu contains 1", true);
	test_filter_compile(factory, "thread.cpu in (1)");
	test_filter_compile(factory, "thread.cpu intersects (1)");
	test_filter_compile(factory, "thread.cpu icontains 1", true);
	test_filter_compile(factory, "thread.cpu startswith 1", true);
	test_filter_compile(factory, "thread.cpu glob 1", true);
	test_filter_compile(factory, "thread.cpu pmatch (1)", true);
	test_filter_compile(factory, "thread.cpu endswith 1", true);
	test_filter_compile(factory, "thread.cpu bcontains 303000", true);
	test_filter_compile(factory, "thread.cpu bstartswith 303000", true);
	test_filter_compile(factory, "thread.cpu iglob 1", true);

	// PT_INT16
	test_filter_compile(factory, "evt.cpu exists");
	test_filter_compile(factory, "evt.cpu = 1");
	test_filter_compile(factory, "evt.cpu != 1");
	test_filter_compile(factory, "evt.cpu < 1");
	test_filter_compile(factory, "evt.cpu <= 1");
	test_filter_compile(factory, "evt.cpu > 1");
	test_filter_compile(factory, "evt.cpu >= 1");
	test_filter_compile(factory, "evt.cpu contains 1", true);
	test_filter_compile(factory, "evt.cpu in (1)");
	test_filter_compile(factory, "evt.cpu intersects (1)");
	test_filter_compile(factory, "evt.cpu icontains 1", true);
	test_filter_compile(factory, "evt.cpu startswith 1", true);
	test_filter_compile(factory, "evt.cpu glob 1", true);
	test_filter_compile(factory, "evt.cpu pmatch (1)", true);
	test_filter_compile(factory, "evt.cpu endswith 1", true);
	test_filter_compile(factory, "evt.cpu bcontains 303000", true);
	test_filter_compile(factory, "evt.cpu bstartswith 303000", true);
	test_filter_compile(factory, "evt.cpu iglob 1", true);

	// PT_INT32
	test_filter_compile(factory, "fd.dev exists");
	test_filter_compile(factory, "fd.dev = 1");
	test_filter_compile(factory, "fd.dev != 1");
	test_filter_compile(factory, "fd.dev < 1");
	test_filter_compile(factory, "fd.dev <= 1");
	test_filter_compile(factory, "fd.dev > 1");
	test_filter_compile(factory, "fd.dev >= 1");
	test_filter_compile(factory, "fd.dev contains 1", true);
	test_filter_compile(factory, "fd.dev in (1)");
	test_filter_compile(factory, "fd.dev intersects (1)");
	test_filter_compile(factory, "fd.dev icontains 1", true);
	test_filter_compile(factory, "fd.dev startswith 1", true);
	test_filter_compile(factory, "fd.dev glob 1", true);
	test_filter_compile(factory, "fd.dev pmatch (1)", true);
	test_filter_compile(factory, "fd.dev endswith 1", true);
	test_filter_compile(factory, "fd.dev bcontains 303000", true);
	test_filter_compile(factory, "fd.dev bstartswith 303000", true);
	test_filter_compile(factory, "fd.dev iglob 1", true);

	// PT_INT64
	test_filter_compile(factory, "proc.pid exists");
	test_filter_compile(factory, "proc.pid = 1");
	test_filter_compile(factory, "proc.pid != 1");
	test_filter_compile(factory, "proc.pid < 1");
	test_filter_compile(factory, "proc.pid <= 1");
	test_filter_compile(factory, "proc.pid > 1");
	test_filter_compile(factory, "proc.pid >= 1");
	test_filter_compile(factory, "proc.pid contains 1", true);
	test_filter_compile(factory, "proc.pid in (1)");
	test_filter_compile(factory, "proc.pid intersects (1)");
	test_filter_compile(factory, "proc.pid icontains 1", true);
	test_filter_compile(factory, "proc.pid startswith 1", true);
	test_filter_compile(factory, "proc.pid glob 1", true);
	test_filter_compile(factory, "proc.pid pmatch (1)", true);
	test_filter_compile(factory, "proc.pid endswith 1", true);
	test_filter_compile(factory, "proc.pid bcontains 303000", true);
	test_filter_compile(factory, "proc.pid bstartswith 303000", true);
	test_filter_compile(factory, "proc.pid iglob 1", true);

	// PT_IPADDR
	test_filter_compile(factory, "fd.ip exists");
	test_filter_compile(factory, "fd.ip = 127.0.0.1");
	test_filter_compile(factory, "fd.ip != 127.0.0.1");
	test_filter_compile(factory, "fd.ip < 127", true);
	test_filter_compile(factory, "fd.ip <= 127", true);
	test_filter_compile(factory, "fd.ip > 127", true);
	test_filter_compile(factory, "fd.ip >= 127", true);
	test_filter_compile(factory, "fd.ip contains 127.0.0.1", true);
	test_filter_compile(factory, "fd.ip in (127.0.0.1)");
	test_filter_compile(factory, "fd.ip intersects (127.0.0.1)");
	test_filter_compile(factory, "fd.ip icontains 127.0.0.1", true);
	test_filter_compile(factory, "fd.ip startswith 127.0.0.1", true);
	test_filter_compile(factory, "fd.ip glob 127.0.0.1", true);
	test_filter_compile(factory, "fd.ip pmatch (127.0.0.1)", true);
	test_filter_compile(factory, "fd.ip endswith 127.0.0.1", true);
	test_filter_compile(factory, "fd.ip bcontains 3132372e302e302e3100", true);
	test_filter_compile(factory, "fd.ip bstartswith 3132372e302e302e3100", true);
	test_filter_compile(factory, "fd.ip iglob 127.0.0.1", true);

	// PT_IPNET
	test_filter_compile(factory, "fd.net exists");
	test_filter_compile(factory, "fd.net = 127.0.0.1/32");
	test_filter_compile(factory, "fd.net != 127.0.0.1/32");
	test_filter_compile(factory, "fd.net < 127", true);
	test_filter_compile(factory, "fd.net <= 127", true);
	test_filter_compile(factory, "fd.net > 127", true);
	test_filter_compile(factory, "fd.net >= 127", true);
	test_filter_compile(factory, "fd.net contains 127.0.0.1/32", true);
	test_filter_compile(factory, "fd.net in (127.0.0.1/32)");
	test_filter_compile(factory, "fd.net intersects (127.0.0.1/32)");
	test_filter_compile(factory, "fd.net icontains 127.0.0.1/32", true);
	test_filter_compile(factory, "fd.net startswith 127.0.0.1/32", true);
	test_filter_compile(factory, "fd.net glob 127.0.0.1/32", true);
	test_filter_compile(factory, "fd.net pmatch (127.0.0.1/32)", true);
	test_filter_compile(factory, "fd.net endswith 127.0.0.1/32", true);
	test_filter_compile(factory, "fd.net bcontains 3132372e302e302e312f333200", true);
	test_filter_compile(factory, "fd.net bstartswith 3132372e302e302e312f333200", true);
	test_filter_compile(factory, "fd.net iglob 127.0.0.1/32", true);

	// PT_PORT
	test_filter_compile(factory, "fd.port exists");
	test_filter_compile(factory, "fd.port = 1");
	test_filter_compile(factory, "fd.port != 1");
	test_filter_compile(factory, "fd.port < 1");
	test_filter_compile(factory, "fd.port <= 1");
	test_filter_compile(factory, "fd.port > 1");
	test_filter_compile(factory, "fd.port >= 1");
	test_filter_compile(factory, "fd.port contains 1", true);
	test_filter_compile(factory, "fd.port in (1)");
	test_filter_compile(factory, "fd.port intersects (1)");
	test_filter_compile(factory, "fd.port icontains 1", true);
	test_filter_compile(factory, "fd.port startswith 1", true);
	test_filter_compile(factory, "fd.port glob 1", true);
	test_filter_compile(factory, "fd.port pmatch (1)", true);
	test_filter_compile(factory, "fd.port endswith 1", true);
	test_filter_compile(factory, "fd.port bcontains 303000", true);
	test_filter_compile(factory, "fd.port bstartswith 303000", true);
	test_filter_compile(factory, "fd.port iglob 1", true);

	// PT_RELTIME
	test_filter_compile(factory, "proc.pid.ts exists");
	test_filter_compile(factory, "proc.pid.ts = 1");
	test_filter_compile(factory, "proc.pid.ts != 1");
	test_filter_compile(factory, "proc.pid.ts < 1");
	test_filter_compile(factory, "proc.pid.ts <= 1");
	test_filter_compile(factory, "proc.pid.ts > 1");
	test_filter_compile(factory, "proc.pid.ts >= 1");
	test_filter_compile(factory, "proc.pid.ts contains 1", true);
	test_filter_compile(factory, "proc.pid.ts in (1)");
	test_filter_compile(factory, "proc.pid.ts intersects (1)");
	test_filter_compile(factory, "proc.pid.ts icontains 1", true);
	test_filter_compile(factory, "proc.pid.ts startswith 1", true);
	test_filter_compile(factory, "proc.pid.ts glob 1", true);
	test_filter_compile(factory, "proc.pid.ts pmatch (1)", true);
	test_filter_compile(factory, "proc.pid.ts endswith 1", true);
	test_filter_compile(factory, "proc.pid.ts bcontains 303000", true);
	test_filter_compile(factory, "proc.pid.ts bstartswith 303000", true);
	test_filter_compile(factory, "proc.pid.ts iglob 1", true);

	// PT_UINT32
	test_filter_compile(factory, "evt.count exists");
	test_filter_compile(factory, "evt.count = 1");
	test_filter_compile(factory, "evt.count != 1");
	test_filter_compile(factory, "evt.count < 1");
	test_filter_compile(factory, "evt.count <= 1");
	test_filter_compile(factory, "evt.count > 1");
	test_filter_compile(factory, "evt.count >= 1");
	test_filter_compile(factory, "evt.count contains 1", true);
	test_filter_compile(factory, "evt.count in (1)");
	test_filter_compile(factory, "evt.count intersects (1)");
	test_filter_compile(factory, "evt.count icontains 1", true);
	test_filter_compile(factory, "evt.count startswith 1", true);
	test_filter_compile(factory, "evt.count glob 1", true);
	test_filter_compile(factory, "evt.count pmatch (1)", true);
	test_filter_compile(factory, "evt.count endswith 1", true);
	test_filter_compile(factory, "evt.count bcontains 303000", true);
	test_filter_compile(factory, "evt.count bstartswith 303000", true);
	test_filter_compile(factory, "evt.count iglob 1", true);

	// PT_UINT64
	test_filter_compile(factory, "evt.num exists");
	test_filter_compile(factory, "evt.num = 1");
	test_filter_compile(factory, "evt.num != 1");
	test_filter_compile(factory, "evt.num < 1");
	test_filter_compile(factory, "evt.num <= 1");
	test_filter_compile(factory, "evt.num > 1");
	test_filter_compile(factory, "evt.num >= 1");
	test_filter_compile(factory, "evt.num contains 1", true);
	test_filter_compile(factory, "evt.num in (1)");
	test_filter_compile(factory, "evt.num intersects (1)");
	test_filter_compile(factory, "evt.num icontains 1", true);
	test_filter_compile(factory, "evt.num startswith 1", true);
	test_filter_compile(factory, "evt.num glob 1", true);
	test_filter_compile(factory, "evt.num pmatch (1)", true);
	test_filter_compile(factory, "evt.num endswith 1", true);
	test_filter_compile(factory, "evt.num bcontains 303000", true);
	test_filter_compile(factory, "evt.num bstartswith 303000", true);
	test_filter_compile(factory, "evt.num iglob 1", true);
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
