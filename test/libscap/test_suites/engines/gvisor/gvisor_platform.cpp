// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <libscap/scap.h>
#include <libscap/engine/gvisor/gvisor.h>

TEST(gvisor_platform, generate_sandbox_id)
{
	char lasterr[SCAP_LASTERR_SIZE];

	scap_gvisor::platform p(lasterr, "/the/root/path");
	uint32_t id;

	std::set<uint32_t> seen_ids;
	uint32_t insertions = 0;

	// insert sandboxes
	id = p.get_numeric_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff817");
	EXPECT_NE(id, 0);
	seen_ids.insert(id);
	EXPECT_EQ(seen_ids.size(), ++insertions);

	uint32_t id_18 = p.get_numeric_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff818");
	EXPECT_NE(id_18, 0);
	seen_ids.insert(id_18);
	EXPECT_EQ(seen_ids.size(), ++insertions);

	id = p.get_numeric_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff819");
	EXPECT_NE(id, 0);
	seen_ids.insert(id);
	EXPECT_EQ(seen_ids.size(), ++insertions);

	id = p.get_numeric_sandbox_id("hello");
	EXPECT_NE(id, 0);
	seen_ids.insert(id);
	EXPECT_EQ(seen_ids.size(), ++insertions);

	id = p.get_numeric_sandbox_id("A");
	EXPECT_NE(id, 0);
	seen_ids.insert(id);
	EXPECT_EQ(seen_ids.size(), ++insertions);

	// retrieve ID
	id = p.get_numeric_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff818");
	EXPECT_NE(id, 0);
	EXPECT_EQ(id_18, id);

	// release and retrieve
	p.release_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff818");
	id = p.get_numeric_sandbox_id("8d966e94e52551866762589eecdd9d44a9d9f87f27cd85af4cf45b7d3d2ff820");
	EXPECT_NE(id, 0);
}
