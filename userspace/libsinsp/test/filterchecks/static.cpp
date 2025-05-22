// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <test/helpers/threads_helpers.h>
#include <libsinsp/sinsp_filtercheck_static.h>

static std::unique_ptr<filter_check_list> pl_flist;
static std::shared_ptr<sinsp_filter_factory> filter_factory;

static void ensure_filter_list_set(sinsp* inspector) {
	if(pl_flist == nullptr) {
		pl_flist.reset(new sinsp_filter_check_list());
		filter_factory.reset(new sinsp_filter_factory(inspector, *pl_flist.get()));

		std::map<std::string, std::string> filters;
		filters["example"] = "example_value";
		pl_flist->add_filter_check(std::make_unique<sinsp_filter_check_static>(filters));
	}
}

TEST_F(sinsp_with_test_input, STATIC_FILTER_suggested_output) {
	ensure_filter_list_set(&m_inspector);

	// Since `%static.example` is a static field,
	// thus its filtercheck shall have the EPF_FORMAT_SUGGESTED flag.
	std::vector<const filter_check_info*> fields;
	pl_flist->get_all_fields(fields);
	for(const auto& field : fields) {
		if(field->m_name == "static.example") {
			ASSERT_TRUE(field->m_flags & EPF_FORMAT_SUGGESTED);
		}
	}

	add_default_init_thread();
	open_inspector();

	std::string path = "/home/file.txt";
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_E,
	                                      3,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                      (uint32_t)0);
	ASSERT_EQ(get_field_as_string(evt, "static.example", *pl_flist), "example_value");
}

TEST_F(sinsp_with_test_input, STATIC_FILTER_filter) {
	ensure_filter_list_set(&m_inspector);

	sinsp_filter_compiler compiler(filter_factory, "static.example=example_value");
	std::unique_ptr<sinsp_filter> s = compiler.compile();
	m_inspector.set_filter(std::move(s), "static.example=example_value");

	add_default_init_thread();
	open_inspector();

	std::string path = "/home/file.txt";
	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_E,
	                                      3,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                      (uint32_t)0);
	ASSERT_NE(evt, nullptr);
	ASSERT_EQ(get_field_as_string(evt, "static.example", *pl_flist), "example_value");
}

TEST_F(sinsp_with_test_input, STATIC_FILTER_filter_wrong) {
	ensure_filter_list_set(&m_inspector);

	sinsp_filter_compiler compiler(filter_factory, "static.example=wrong_value");
	std::unique_ptr<sinsp_filter> s = compiler.compile();
	m_inspector.set_filter(std::move(s), "static.example=wrong_value");

	add_default_init_thread();
	open_inspector();

	std::string path = "/home/file.txt";
	// Exception thrown because no event matches the required filter
	ASSERT_ANY_THROW(add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_OPEN_E,
	                                      3,
	                                      path.c_str(),
	                                      (uint32_t)PPM_O_RDWR | PPM_O_CREAT,
	                                      (uint32_t)0));
}
