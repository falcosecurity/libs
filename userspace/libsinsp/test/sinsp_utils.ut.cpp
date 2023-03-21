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

// copy_and_sanitize_path is not exported in utils.h
void copy_and_sanitize_path(char* target, char* targetbase, const char* path, char separator);

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
