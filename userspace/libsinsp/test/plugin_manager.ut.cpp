// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#include <libsinsp/plugin.h>
#include <libsinsp/plugin_manager.h>

class mock_sinsp_plugin: public sinsp_plugin
{
public:
	inline mock_sinsp_plugin(
		plugin_caps_t caps,
		const std::string& name,
		uint32_t id,
		const std::string& source): sinsp_plugin(nullptr, nullptr, nullptr)
	{
		m_caps = caps;
		m_name = name;
		m_id = id;
		m_event_source = source;
	}
};

TEST(sinsp_plugin_manager, add_and_queries)
{
	std::vector<std::string> sources;
	sinsp_plugin_manager m(sources);

	sources.push_back("some_source");

	auto p1 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin1", 1, "source1");
	m.add(p1);

	auto p2 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin2", 2, "source2");
	m.add(p2);

	auto p3 = std::make_shared<mock_sinsp_plugin>(CAP_EXTRACTION, "plugin3", -1, "");
	m.add(p3);

	// note: same source as p1 (should not create duplicates in source list)
	auto p4 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin4", 4, "source1");
	m.add(p4);

	// note: these have source cap but no ID (we can add more than one)
	auto p5 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin5", 0, "");
	m.add(p5);
	auto p6 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin6", 0, "");
	m.add(p6);
	
	ASSERT_EQ(m.plugins().size(), (std::size_t) 6);
	ASSERT_EQ(m.plugins()[0], p1);
	ASSERT_EQ(m.plugins()[1], p2);
	ASSERT_EQ(m.plugins()[2], p3);
	ASSERT_EQ(m.plugins()[3], p4);
	ASSERT_EQ(m.plugins()[4], p5);
	ASSERT_EQ(m.plugins()[5], p6);

	ASSERT_EQ(m.plugin_by_id(0), nullptr);
	ASSERT_EQ(m.plugin_by_id(1), p1);
	ASSERT_EQ(m.plugin_by_id(2), p2);
	ASSERT_EQ(m.plugin_by_id(3), nullptr);
	ASSERT_EQ(m.plugin_by_id(4), p4);

	ASSERT_EQ(sources.size(), (std::size_t) 3);
	ASSERT_EQ(sources[0], "some_source");
	ASSERT_EQ(sources[1], "source1");
	ASSERT_EQ(sources[2], "source2");

	bool found = false;
	std::size_t res = 0;
	res = m.source_idx_by_plugin_id(0, found);
	ASSERT_EQ(found, false);
	ASSERT_EQ(res, sinsp_no_event_source_idx);
	res = m.source_idx_by_plugin_id(1, found);
	ASSERT_EQ(res, (std::size_t) 1);
	ASSERT_EQ(found, true);
	res = m.source_idx_by_plugin_id(2, found);
	ASSERT_EQ(res, (std::size_t) 2);
	ASSERT_EQ(found, true);
	res = m.source_idx_by_plugin_id(3, found);
	ASSERT_EQ(res, sinsp_no_event_source_idx);
	ASSERT_EQ(found, false);
	res = m.source_idx_by_plugin_id(4, found);
	ASSERT_EQ(res, (std::size_t) 1);
	ASSERT_EQ(found, true);
}

// note(jasondellaluce): this is a design chocie, but we may drop this
// constraint in the future
TEST(sinsp_plugin_manager, add_conflicts)
{
	std::vector<std::string> sources;
	sinsp_plugin_manager m(sources);

	auto p1 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin1", 1, "source1");
	EXPECT_NO_THROW(m.add(p1));

	// adding twice
	EXPECT_ANY_THROW(m.add(p1));

	// adding with same name
	auto p2 = std::make_shared<mock_sinsp_plugin>(CAP_EXTRACTION, "plugin1", -1, "");
	EXPECT_ANY_THROW(m.add(p2));

	// adding with same ID
	p2 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin2", 1, "source2");
	EXPECT_ANY_THROW(m.add(p2));

	// adding with same source (should be ok, but should not produce duplicates)
	p2 = std::make_shared<mock_sinsp_plugin>(CAP_SOURCING, "plugin2", 2, "source1");
	EXPECT_NO_THROW(m.add(p2));
	ASSERT_EQ(sources.size(), (std::size_t) 1);
}
