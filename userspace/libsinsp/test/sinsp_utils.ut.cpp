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
#include "utils.h"

TEST(sinsp_utils_test, concatenate_paths)
{
	std::string path1, path2, res;

	/*
	 * SUCCESS concatenate_paths
	*/

	path1 = "";
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ(path2, res);

	path1 = "//";
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("//dir/term", res);

	path1 = "////";
	path2 = "dir/term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("////dir/term", res);

	path1 = "///../.../";
	path2 = "dir/./././///./term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/.../dir/term", res);

	path1 = "../.../";
	path2 = "dir/././././../../.../term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("../.../term", res);

	/*
	 * FAILED concatenate_paths
	*/

	res = sinsp_utils::concatenate_paths("", "");
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "/dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ(path2, res);

	path1 = "//";
	path2 = "/dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "//";
	path2 = "////dir/../../././term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/term", res);

	path1 = "//";
	path2 = "////";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("///", res);
}
