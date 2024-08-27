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
#include <driver/ppm_api_version.h>

TEST(api_version, unpack)
{
	uint64_t ver1_2_3 = (1ULL << 44) | (2ULL << 24) | 3;
	ASSERT_EQ(ver1_2_3, PPM_API_VERSION(1, 2, 3));
}

TEST(api_version, pack)
{
	uint64_t ver1_2_3 = (1ULL << 44) | (2ULL << 24) | 3;
	EXPECT_EQ(1u, PPM_API_VERSION_MAJOR(ver1_2_3));
	EXPECT_EQ(2u, PPM_API_VERSION_MINOR(ver1_2_3));
	EXPECT_EQ(3u, PPM_API_VERSION_PATCH(ver1_2_3));
}
