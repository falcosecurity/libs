#include <test/helpers/threads_helpers.h>

constexpr const char *name = "/tmp/random/dir...///../../name/";
constexpr const char *resolved_name = "/tmp/name";

TEST_F(sinsp_with_test_input, FSPATH_FILTER_open) {
	add_default_init_thread();
	open_inspector();
	auto evt = generate_open_event(sinsp_test_input::open_params{
	        .path = name,
	});
	ASSERT_EQ(get_field_as_string(evt, "fs.path.name"), resolved_name);
	ASSERT_EQ(get_field_as_string(evt, "fs.path.nameraw"), name);
	ASSERT_FALSE(field_has_value(evt, "fs.path.source"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.sourceraw"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.target"));
	ASSERT_FALSE(field_has_value(evt, "fs.path.targetraw"));
}
