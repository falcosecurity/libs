#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <gtest/gtest.h>
#include <list>
#include <sinsp_with_test_input.h>
#include <plugins/test_plugins.h>

using namespace std;

// A mock filtercheck that returns always true or false depending on
// the passed-in field name. The operation is ignored.
class mock_compiler_filter_check : public sinsp_filter_check {
public:
	int32_t parse_field_name(std::string_view str,
	                         bool alloc_state,
	                         bool needed_for_filtering) override {
		static const std::unordered_set<std::string> s_supported_fields = {"c.true",
		                                                                   "c.false",
		                                                                   "c.buffer",
		                                                                   "c.doublequote",
		                                                                   "c.singlequote"};

		m_name = str;
		if(str == "c.buffer") {
			m_field_info.m_type = PT_BYTEBUF;
		}

		if(s_supported_fields.find(m_name) != s_supported_fields.end()) {
			return m_name.size();
		}

		return -1;
	}

	inline bool compare(sinsp_evt*) override {
		if(m_name == "c.true") {
			return true;
		}
		if(m_name == "c.false" || m_name == "c.buffer") {
			return false;
		}
		if(m_name == "c.doublequote") {
			return m_value == "hello \"quoted\"";
		}
		if(m_name == "c.singlequote") {
			return m_value == "hello 'quoted'";
		}
		return false;
	}

	const filtercheck_field_info* get_field_info() const override { return &m_field_info; }

	inline void add_filter_value(const char* str, uint32_t l, uint32_t i) override {
		m_value = string(str, l);
	}

	inline void add_filter_value(std::unique_ptr<sinsp_filter_check> f) override {
		throw sinsp_exception("unexpected right-hand side filter comparison");
	}

	inline bool extract_nocache(sinsp_evt* e, vector<extract_value_t>& v, bool) override {
		return false;
	}

	std::string m_name;
	std::string m_value;
	filtercheck_field_info m_field_info{PT_CHARBUF, 0, PF_NA, "", "", ""};
};

struct test_sinsp_filter_cache_factory : public exprstr_sinsp_filter_cache_factory {
	bool docache = true;
	const std::shared_ptr<sinsp_filter_cache_metrics> metrics =
	        std::make_shared<sinsp_filter_cache_metrics>();

	virtual ~test_sinsp_filter_cache_factory() = default;

	test_sinsp_filter_cache_factory(bool cached = true): docache(cached) {}

	std::shared_ptr<sinsp_filter_extract_cache> new_extract_cache(const ast_expr_t* e,
	                                                              node_info_t& info) override {
		if(!docache) {
			return nullptr;
		}
		return exprstr_sinsp_filter_cache_factory::new_extract_cache(e, info);
	}

	std::shared_ptr<sinsp_filter_compare_cache> new_compare_cache(const ast_expr_t* e,
	                                                              node_info_t& info) override {
		if(!docache) {
			return nullptr;
		}
		return exprstr_sinsp_filter_cache_factory::new_compare_cache(e, info);
	}

	std::shared_ptr<sinsp_filter_cache_metrics> new_metrics(const ast_expr_t* e,
	                                                        node_info_t& info) override {
		return metrics;
	}
};

// A factory that creates mock filterchecks
class mock_compiler_filter_factory : public sinsp_filter_factory {
public:
	mock_compiler_filter_factory(sinsp* inspector): sinsp_filter_factory(inspector, m_filterlist) {}

	inline std::unique_ptr<sinsp_filter_check> new_filtercheck(
	        std::string_view fldname) const override {
		if(mock_compiler_filter_check{}.parse_field_name(fldname, false, true) > 0) {
			return std::make_unique<mock_compiler_filter_check>();
		}

		if(auto check = sinsp_filter_factory::new_filtercheck(fldname); check != nullptr) {
			return check;
		}

		return nullptr;
	}

	inline list<sinsp_filter_factory::filter_fieldclass_info> get_fields() const override {
		return m_list;
	}

	sinsp_filter_check_list m_filterlist;
	list<sinsp_filter_factory::filter_fieldclass_info> m_list;
};

// Compile a filter, pass a mock event to it, and
// check that the result of the boolean evaluation is
// the expected one
void test_filter_run(bool result, string filter_str) {
	sinsp inspector;
	auto factory = std::make_shared<mock_compiler_filter_factory>(&inspector);
	sinsp_filter_compiler compiler(factory, filter_str);
	try {
		auto filter = compiler.compile();
		if(filter->run(NULL) != result) {
			FAIL() << filter_str << " -> unexpected '" << (result ? "false" : "true") << "' result";
		}
	} catch(const std::exception& e) {
		FAIL() << filter_str << " -> " << e.what();
	} catch(...) {
		FAIL() << filter_str << " -> " << "UNKNOWN ERROR";
	}
}

void test_filter_compile(std::shared_ptr<sinsp_filter_factory> factory,
                         string filter_str,
                         bool expect_fail = false,
                         size_t expected_warnings = 0) {
	sinsp_filter_compiler compiler(factory, filter_str);
	try {
		auto filter = compiler.compile();
		if(expect_fail) {
			FAIL() << filter_str << " -> expected failure but compilation was successful";
		}
	} catch(const std::exception& e) {
		if(!expect_fail) {
			FAIL() << filter_str << " -> " << e.what();
		}
	} catch(...) {
		if(!expect_fail) {
			FAIL() << filter_str << " -> " << "UNKNOWN ERROR";
		}
	}

	std::string warnings_fmt;
	for(const auto& warn : compiler.get_warnings()) {
		warnings_fmt.append("\n").append(warn.pos.as_string()).append(" -> ").append(warn.msg);
	}
	ASSERT_EQ(compiler.get_warnings().size(), expected_warnings)
	        << "filter: " + filter_str + "\nactual warnings: " + warnings_fmt;
}

// In each of these test cases, we compile filter expression
// of which we can control the truth state of each filtercheck,
// so that we can deterministically check the result of running
// a mock event in the compiled filters. The purpose is verifying
// that the compiler constructs valid boolean expressions.
TEST(sinsp_filter_compiler, boolean_evaluation) {
	test_filter_run(true, "c.true=1");
	test_filter_run(false, "c.false=1");
	test_filter_run(false, "not c.true=1");
	test_filter_run(false, "not(c.true=1)");
	test_filter_run(true, "not not c.true=1");
	test_filter_run(true, "not not(c.true=1)");
	test_filter_run(true, "not (not c.true=1)");
	test_filter_run(false, "not not not c.true=1");
	test_filter_run(false, "not not not(c.true=1)");
	test_filter_run(false, "not (not (not c.true=1))");
	test_filter_run(false, "not(not(not c.true=1))");
	test_filter_run(true, "not not not not c.true=1");
	test_filter_run(true, "not not(not not c.true=1)");
	test_filter_run(true, "c.true=1 and c.true=1");
	test_filter_run(false, "c.true=1 and c.false=1");
	test_filter_run(false, "c.false=1 and c.true=1");
	test_filter_run(false, "c.false=1 and c.false=1");
	test_filter_run(false, "c.true=1 and not c.true=1");
	test_filter_run(false, "not c.true=1 and c.true=1");
	test_filter_run(true, "c.true=1 or c.true=1");
	test_filter_run(true, "c.true=1 or c.false=1");
	test_filter_run(true, "c.false=1 or c.true=1");
	test_filter_run(false, "c.false=1 or c.false=1");
	test_filter_run(true, "c.false=1 or not c.false=1");
	test_filter_run(true, "not c.false=1 or c.false=1");
	test_filter_run(true, "c.true=1 or c.true=1 and c.false=1");
	test_filter_run(false, "(c.true=1 or c.true=1) and c.false=1");
	test_filter_run(true, "not (not (c.true=1 or c.true=1) and c.false=1)");
	test_filter_run(false, "not (c.false=1 or c.false=1 or c.true=1)");
	test_filter_run(true, "not (c.false=1 or c.false=1 and not c.true=1)");
	test_filter_run(false, "not (c.false=1 or not c.false=1 and c.true=1)");
	test_filter_run(false, "not ((c.false=1 or not (c.false=1 and not c.true=1)) and c.true=1)");
}

TEST(sinsp_filter_compiler, str_escape) {
	test_filter_run(true, "c.singlequote = 'hello \\'quoted\\''");
	test_filter_run(true, "c.singlequote = \"hello 'quoted'\"");
	test_filter_run(true, "c.doublequote = 'hello \"quoted\"'");
	test_filter_run(true, "c.doublequote = \"hello \\\"quoted\\\"\"");

	test_filter_run(false, "c.singlequote = 'hello \\\\'quoted\\\\''");
	test_filter_run(false, "c.singlequote = \"hello ''quoted''\"");
	test_filter_run(false, "c.doublequote = \"hello \\\\\"quoted\\\\\"\"");
	test_filter_run(false, "c.doublequote = 'hello \"\"quoted\"\"'");
}

TEST(sinsp_filter_compiler, supported_operators) {
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

TEST(sinsp_filter_compiler, operators_field_types_compatibility) {
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
	test_filter_compile(factory, "evt.rawtime regex '1'", true);

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
	test_filter_compile(factory, "evt.is_io regex '1'", true);

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
	test_filter_compile(factory, "evt.buffer regex '.*'", true);

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
	test_filter_compile(factory, "fd.name regex '/home/.*/dev'");

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
	test_filter_compile(factory, "thread.cpu regex '1'", true);

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
	test_filter_compile(factory, "evt.cpu regex '1'", true);

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
	test_filter_compile(factory, "fd.dev regex '1'", true);

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
	test_filter_compile(factory, "proc.pid regex '1'", true);

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
	test_filter_compile(factory, "fd.ip regex '.*'", true);

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
	test_filter_compile(factory, "fd.net regex '.*'", true);

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
	test_filter_compile(factory, "fd.port regex '1'", true);

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
	test_filter_compile(factory, "proc.pid.ts regex '1'", true);

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
	test_filter_compile(factory, "evt.count regex '1'", true);

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
	test_filter_compile(factory, "evt.num regex '1'", true);
}

TEST(sinsp_filter_compiler, complex_filter) {
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
	        "	and (proc.cmdline contains \"/var/lib/docker\" or proc.cmdline contains "
	        "'/var/run/docker')"
	        "	and proc.pname in (dockerd, docker, dockerd-current, docker-current)"
	        ")";

	test_filter_compile(factory, filter_str);
}

TEST(sinsp_filter_compiler, compilation_warnings) {
	sinsp inspector;
	std::shared_ptr<sinsp_filter_factory> factory(new mock_compiler_filter_factory(&inspector));

	// warnings expected
	test_filter_compile(factory, "evt.source = evt.plugininfo", false, 1);
	test_filter_compile(factory, "evt.source = 'tolower(evt.plugininfo)'", false, 1);
	test_filter_compile(factory, "evt.source regex syscall", false, 1);
	test_filter_compile(factory, "evt.source regex ^syscall$", false, 1);
	test_filter_compile(factory, "evt.source regex ^syscall", false, 1);
	test_filter_compile(factory, "evt.source regex syscall$", false, 1);
	test_filter_compile(factory, "evt.source regex .*syscall", false, 1);
	test_filter_compile(factory, "evt.source regex syscall.*", false, 1);
	test_filter_compile(factory, "evt.source regex .*syscall.*", false, 1);
	test_filter_compile(factory, "evt.source regex .+syscall", false, 1);
	test_filter_compile(factory, "evt.source regex syscall.+", false, 1);
	test_filter_compile(factory, "evt.source regex .+syscall.+", false, 1);
	test_filter_compile(factory, "evt.source regex .?syscall", false, 1);
	test_filter_compile(factory, "evt.source regex syscall.?", false, 1);
	test_filter_compile(factory, "evt.source regex .?syscall.?", false, 1);

	// warnings not expected (not part of our euristics)
	test_filter_compile(factory, "evt.source = unknown.field", false, 0);
	test_filter_compile(factory, "evt.source = tolower", false, 0);
	test_filter_compile(factory, "evt.source = tolower(evt.plugininfo)", false, 0);
	test_filter_compile(factory, "evt.source = 'tolow(evt.plugininfo)'", false, 0);
	test_filter_compile(factory, "evt.source regex syscall.{1}", false, 0);
	test_filter_compile(factory, "evt.source regex syscall\\.*", false, 0);
	test_filter_compile(factory, "evt.source regex s.*l", false, 0);
	test_filter_compile(factory, "evt.source regex syscal[l]?", false, 0);
}

//////////////////////////////
// Test filter strings against real events.
//////////////////////////////

TEST_F(sinsp_with_test_input, filter_simple_evaluation) {
	// Basic case just to assert that the basic setup works
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = generate_getcwd_failed_entry_event();
	ASSERT_TRUE(eval_filter(evt, "(evt.type = getcwd)"));
	ASSERT_TRUE(eval_filter(evt, "(evt.arg.res = val(evt.arg.res))"));
}

TEST_F(sinsp_with_test_input, filter_val_transformer) {
	add_default_init_thread();
	open_inspector();
	// Please note that with `evt.args = evt.args` we are evaluating the field `evt.args` against
	// the const value `evt.args`.

	sinsp_evt* evt = generate_getcwd_failed_entry_event();

	ASSERT_FALSE(eval_filter(evt, "(evt.args = evt.args)"));
	ASSERT_TRUE(eval_filter(evt, "(evt.args = val(evt.args))"));

	// val() expects a field inside it is not a transformer
	ASSERT_FALSE(filter_compiles("(syscall.type = val(tolower(toupper(syscall.type))))"));

	// val() is not supported on the left
	ASSERT_FALSE(filter_compiles("(val(evt.args) = val(evt.args))"));

	// val() cannot support a list
	ASSERT_FALSE(filter_compiles("(syscall.type = val(syscall.type, evt.type))"));
}

TEST_F(sinsp_with_test_input, filter_transformers_combination) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt = generate_getcwd_failed_entry_event();

	ASSERT_TRUE(eval_filter(evt, "(tolower(syscall.type) = getcwd)"));
	ASSERT_TRUE(eval_filter(evt, "(toupper(syscall.type) = GETCWD)"));
	ASSERT_TRUE(eval_filter(evt, "(tolower(toupper(syscall.type)) = getcwd)"));
	ASSERT_TRUE(eval_filter(evt, "(tolower(syscall.type) = tolower(syscall.type))"));
	ASSERT_TRUE(eval_filter(evt, "(toupper(syscall.type) = toupper(syscall.type))"));
	ASSERT_TRUE(
	        eval_filter(evt, "(tolower(toupper(syscall.type)) = tolower(toupper(syscall.type)))"));
}

TEST_F(sinsp_with_test_input, filter_different_types) {
	add_default_init_thread();
	open_inspector();

	ASSERT_FALSE(filter_compiles("syscall.type = val(evt.is_wait)"));
}

TEST_F(sinsp_with_test_input, filter_not_supported_rhs_field) {
	add_default_init_thread();
	open_inspector();

	// `evt.around` cannot be used as a rhs filter check
	ASSERT_FALSE(filter_compiles("evt.buflen.in = val(evt.around[1404996934793590564])"));

	// `evt.around` cannot support a rhs filter check
	ASSERT_FALSE(filter_compiles("evt.around[1404996934793590564] = val(evt.buflen.in)"));
}

TEST_F(sinsp_with_test_input, filter_not_supported_transformers) {
	add_default_init_thread();
	open_inspector();

	// `evt.rawarg` doesn't support a transformer
	ASSERT_FALSE(filter_compiles("toupper(evt.rawarg.res) = -1"));
}

TEST_F(sinsp_with_test_input, filter_transformers_wrong_input_type) {
	add_default_init_thread();
	open_inspector();

	ASSERT_FALSE(filter_compiles("toupper(evt.rawres) = -1"));
	ASSERT_FALSE(filter_compiles("tolower(evt.rawres) = -1"));
	ASSERT_FALSE(filter_compiles("b64(evt.rawres) = -1"));
}

TEST_F(sinsp_with_test_input, filter_cache_disabled) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_getcwd_failed_entry_event();
	auto cf = std::make_shared<test_sinsp_filter_cache_factory>(false);

	ASSERT_TRUE(eval_filter(evt, "evt.type = openat or evt.type = getcwd", cf));
	ASSERT_TRUE(eval_filter(evt, "evt.type = getcwd", cf));
	evt->set_num(evt->get_num() + 1);
	ASSERT_TRUE(eval_filter(evt, "evt.type = openat or evt.type = getcwd", cf));

	EXPECT_EQ(cf->metrics->m_num_compare, 5);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 0);
	EXPECT_EQ(cf->metrics->m_num_extract, 5);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 0);
}

TEST_F(sinsp_with_test_input, filter_cache_enabled) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_getcwd_failed_entry_event();
	auto cf = std::make_shared<test_sinsp_filter_cache_factory>();

	ASSERT_TRUE(eval_filter(evt, "evt.type = openat or evt.type = getcwd", cf));
	ASSERT_TRUE(eval_filter(evt, "evt.type = getcwd", cf));
	evt->set_num(evt->get_num() + 1);
	ASSERT_TRUE(eval_filter(evt, "evt.type = openat or evt.type = getcwd", cf));

	EXPECT_EQ(cf->metrics->m_num_compare, 5);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract, 4);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 2);
}

TEST_F(sinsp_with_test_input, filter_cache_corner_cases) {
	sinsp_filter_check_list flist;

	add_default_init_thread();
	open_inspector();

	// Register a plugin with extraction capabilities
	std::string err;
	plugin_api papi;
	get_plugin_api_sample_syscall_extract(papi);
	auto pl = m_inspector.register_plugin(&papi);
	ASSERT_TRUE(pl->init("", err)) << err;
	flist.add_filter_check(m_inspector.new_generic_filtercheck());
	flist.add_filter_check(sinsp_plugin::new_filtercheck(pl));

	auto ff = std::make_shared<sinsp_filter_factory>(&m_inspector, flist);
	auto cf = std::make_shared<test_sinsp_filter_cache_factory>();
	auto evt = generate_getcwd_failed_entry_event();

	// plugin fields
	ASSERT_TRUE(eval_filter(evt, "sample.is_open exists and sample.is_open = 0", ff, cf));
	ASSERT_TRUE(eval_filter(evt, "sample.is_open = 0", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract,
	          2);  // the third extraction never happens as the check is cached
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 1);
	cf->metrics->reset();

	// special comparison logic
	ASSERT_FALSE(eval_filter(evt, "fd.ip = 127.0.0.1 or fd.ip = 10.0.0.1", ff, cf));
	ASSERT_FALSE(eval_filter(evt, "fd.ip = 10.0.0.1", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract, 0);  // special logic avoids extraction entirely :/
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 0);
	cf->metrics->reset();

	// fields with ambiguous comparison (no caching expected)
	ASSERT_FALSE(eval_filter(evt, "fd.net = 127.0.0.1/32 or fd.net = 10.0.0.1/32", ff, cf));
	ASSERT_FALSE(eval_filter(evt, "fd.net = 10.0.0.1/32", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 0);
	EXPECT_EQ(cf->metrics->m_num_extract, 0);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 0);
	cf->metrics->reset();

	// fields with arguments
	ASSERT_TRUE(eval_filter(evt, "evt.arg[1] startswith /etc or evt.arg[1] = /test/dir", ff, cf));
	ASSERT_TRUE(eval_filter(evt, "evt.arg[1] = /test/dir", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract, 2);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 1);
	cf->metrics->reset();

	// fields with transformers
	ASSERT_TRUE(
	        eval_filter(evt, "toupper(evt.source) = SYS or toupper(evt.source) = SYSCALL", ff, cf));
	ASSERT_TRUE(eval_filter(evt, "toupper(evt.source) = SYSCALL", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract, 2);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 1);
	cf->metrics->reset();

	// field-to-field comparisons
	ASSERT_TRUE(eval_filter(evt,
	                        "evt.source = val(evt.plugininfo) or evt.source = val(evt.source)",
	                        ff,
	                        cf));
	ASSERT_TRUE(eval_filter(evt, "evt.source = val(evt.source)", ff, cf));
	EXPECT_EQ(cf->metrics->m_num_compare, 3);
	EXPECT_EQ(cf->metrics->m_num_compare_cache, 1);
	EXPECT_EQ(cf->metrics->m_num_extract, 4);
	EXPECT_EQ(cf->metrics->m_num_extract_cache, 2);
	cf->metrics->reset();
}

TEST_F(sinsp_with_test_input, filter_cache_pointer_instability) {
	sinsp_filter_check_list flist;

	add_default_init_thread();
	open_inspector();

	auto ff = std::make_shared<sinsp_filter_factory>(&m_inspector, flist);
	auto cf = std::make_shared<test_sinsp_filter_cache_factory>();
	auto evt = generate_proc_exit_event(2, INIT_TID);

	EXPECT_FALSE(eval_filter(evt, "(evt.arg.ret = val(evt.arg.reaper_tid))"));
}

TEST_F(sinsp_with_test_input, filter_regex_operator_evaluation) {
	// Basic case just to assert that the basic setup works
	add_default_init_thread();
	open_inspector();

	auto evt = generate_getcwd_failed_entry_event();

	// legit use case with a string
	EXPECT_TRUE(eval_filter(evt, "evt.source regex '^[s]{1}ysca[l]{2}$'"));

	// respect anchors
	EXPECT_FALSE(eval_filter(evt, "evt.source regex 'yscal.*'"));
	EXPECT_FALSE(eval_filter(evt, "evt.source regex '.*yscal'"));
	EXPECT_TRUE(eval_filter(evt, "evt.source regex 'syscal.*'"));

	// legit use case with a string, evaluating as false
	EXPECT_FALSE(eval_filter(evt, "evt.source regex '^unknown$'"));

	// legit use case with a string, also using transformers
	EXPECT_TRUE(eval_filter(evt, "toupper(evt.source) regex '^[A-Z]+$'"));

	// can't be used with field-to-field comparisons
	EXPECT_THROW(eval_filter(evt, "evt.plugininfo regex val(evt.source)"), sinsp_exception);
}
