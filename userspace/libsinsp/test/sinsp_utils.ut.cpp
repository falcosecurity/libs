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

// Following helpers are not exported in utils.h
void copy_and_sanitize_path(char* target, char* targetbase, const char* path, char separator);
void rewind_to_parent_path(char* targetbase, char** tc, const char** pc, uint32_t delta);

TEST(sinsp_utils_test, concatenate_paths)
{
	char fullpath[SCAP_MAX_PATH_SIZE];
	std::string path1;
	std::string path2;
	bool res;

	/*
	 * SUCCESS concatenate_paths
	*/

	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									"\0",
									0,
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ(path2, std::string(fullpath));
	ASSERT_TRUE(res);

	path1 = "//";
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("//dir/term", std::string(fullpath));
	ASSERT_TRUE(res);

	path1 = "////";
	path2 = "dir/term/";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("////dir/term", std::string(fullpath));
	ASSERT_TRUE(res);

	path1 = "///../.../../";
	path2 = "dir/term/";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("///../.../../dir/term", std::string(fullpath));
	ASSERT_TRUE(res);

	path1 = "///../.../";
	path2 = "dir/./././///./term/";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("///../.../dir/term", std::string(fullpath));
	ASSERT_TRUE(res); // only path2 gets sanitized and ./ or multiple //// removed

	path1 = "../.../";
	path2 = "dir/././././../../.../term/";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("../.../term", std::string(fullpath));
	ASSERT_TRUE(res); // only path2 gets sanitized and ./ removed and directory traversed up

	path1 = "././";
	path2 = "./dir/term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("././dir/term", std::string(fullpath));
	ASSERT_TRUE(res); // only path2 gets sanitized and ./ removed


	/*
	 * FAILED concatenate_paths
	*/

	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									"\0",
									0,
									"\0",
									0);
	EXPECT_EQ("\0", std::string(fullpath));
	ASSERT_FALSE(res); // nothing to concat as path2 is empty

	path1 = "//";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									"\0",
									 0);
	EXPECT_EQ("\0", std::string(fullpath));
	ASSERT_FALSE(res); // nothing to concat as path2 is empty

	path2 = "/dir/term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									"\0",
									0,
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ(path2, std::string(fullpath));
	ASSERT_FALSE(res); // because path2 is absolute

	path1 = "//";
	path2 = "/dir/term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("/dir/term", std::string(fullpath));
	ASSERT_FALSE(res); // because path2 is absolute

	path1 = "//";
	path2 = "////dir/../../././term";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("/term", std::string(fullpath));
	ASSERT_FALSE(res); // because path2 is absolute, path2 gets directory traversed up

	path1 = "//";
	path2 = "////";
	res = sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									path1.c_str(),
									(uint32_t)path1.length(),
									path2.c_str(),
									(uint32_t)path2.length());
	EXPECT_EQ("/", std::string(fullpath));
	ASSERT_FALSE(res); // because not actually paths here just repeated separators

}


TEST(sinsp_utils_test, copy_and_sanitize_path)
{
	char target[SCAP_MAX_PATH_SIZE];

	std::string path = "/dir/term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ(path, std::string(target));

	path = "/dir/term/";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir/../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/term", std::string(target));

	path = "/dir/dir/../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir/dir/../../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/term", std::string(target));

	path = "/dir/term/..";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir", std::string(target));

	path = "/dir/./term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir/././term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir/term/.";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir/.../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/.../term", std::string(target));

	path = "/dir/term/...";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term/...", std::string(target));

	path = "/dir/term/....";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term/....", std::string(target));

	path = "/dir/..../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/..../term", std::string(target));

	path = "/dir/dir../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/dir../term", std::string(target));

	path = "/dir/dir./term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/dir./term", std::string(target));

	path = "/dir/..dir/term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/..dir/term", std::string(target));

	path = "/dir/.dir/term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/.dir/term", std::string(target));

	path = ".dir";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ(".dir", std::string(target));

	path = "./";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = "./.";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = ".";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = "../";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = "../..";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = "..";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("", std::string(target));

	path = "/dir//./term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/term", std::string(target));

	path = "/dir//../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/term", std::string(target));

	path = "/dir//.../term";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/.../term", std::string(target));

	path = "/dir//...";
	copy_and_sanitize_path(target, target, path.c_str(), '/');
	EXPECT_EQ("/dir/...", std::string(target));
}
