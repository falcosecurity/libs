/*
Copyright (C) 2022 The Falco Authors.

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

#include <gtest/gtest.h>
#include <plugin.h>
#include <plugin_manager.h>

class mock_sinsp_plugin: public sinsp_plugin
{
public:
	inline mock_sinsp_plugin(): sinsp_plugin(nullptr) { }
	inline plugin_caps_t caps() const override { return m_caps; };
	inline uint32_t id() const override { return m_id; };
	inline const std::string &name() const { return m_name; }
	inline const std::string &event_source() const override { return m_source; }

	uint32_t m_id;
	std::string m_source;
	std::string m_name;
	plugin_caps_t m_caps;
};

TEST(sinsp_plugin_manager, add_and_queries)
{
	sinsp_plugin_manager m;

	std::shared_ptr<mock_sinsp_plugin> p1(new mock_sinsp_plugin());
	p1->m_name = "plugin1";
	p1->m_caps = CAP_SOURCING;
	p1->m_id = 1;
	p1->m_source = "source1";
	m.add(p1);

	std::shared_ptr<mock_sinsp_plugin> p2(new mock_sinsp_plugin());
	p2->m_name = "plugin2";
	p2->m_caps = CAP_SOURCING;
	p2->m_id = 2;
	p2->m_source = "source2";
	m.add(p2);

	std::shared_ptr<mock_sinsp_plugin> p3(new mock_sinsp_plugin());
	p3->m_name = "plugin3";
	p3->m_caps = CAP_EXTRACTION;
	m.add(p3);
	
	ASSERT_EQ(m.plugins().size(), (std::size_t) 3);
	ASSERT_EQ(m.plugins()[0], p1);
	ASSERT_EQ(m.plugins()[1], p2);
	ASSERT_EQ(m.plugins()[2], p3);

	ASSERT_EQ(m.plugin_by_id(0), nullptr);
	ASSERT_EQ(m.plugin_by_id(1), p1);
	ASSERT_EQ(m.plugin_by_id(2), p2);
	ASSERT_EQ(m.plugin_by_id(3), nullptr);

	ASSERT_EQ(m.sources().size(), (std::size_t) 2);
	ASSERT_EQ(m.sources()[0], "source1");
	ASSERT_EQ(m.sources()[1], "source2");

	bool found = false;
	std::size_t res = 0;
	res = m.source_idx_by_plugin_id(0, found);
	ASSERT_EQ(found, false);
	res = m.source_idx_by_plugin_id(1, found);
	ASSERT_EQ(res, (std::size_t) 0);
	ASSERT_EQ(found, true);
	res = m.source_idx_by_plugin_id(2, found);
	ASSERT_EQ(res, (std::size_t) 1);
	ASSERT_EQ(found, true);
	res = m.source_idx_by_plugin_id(3, found);
	ASSERT_EQ(found, false);
}

// note: this is a design chocie, but we may drop this constraint in the future
TEST(sinsp_plugin_manager, add_with_same_name)
{
	sinsp_plugin_manager m;

	std::shared_ptr<mock_sinsp_plugin> p1(new mock_sinsp_plugin());
	p1->m_name = "plugin1";
	p1->m_caps = CAP_SOURCING;
	p1->m_id = 1;
	p1->m_source = "source1";

	std::shared_ptr<mock_sinsp_plugin> p2(new mock_sinsp_plugin());
	p2->m_name = "plugin1";
	p2->m_caps = CAP_EXTRACTION;

	EXPECT_NO_THROW(m.add(p1));
	EXPECT_ANY_THROW(m.add(p1));
	EXPECT_ANY_THROW(m.add(p2));
}
