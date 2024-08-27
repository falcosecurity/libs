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
#include <libscap/linux/scap_cgroup.h>
#include <libscap/linux/scap_cgroup.c>

TEST(cgroups, path_relative)
{
	char final_path[4096];
	const char* prefix = "/1/2/3";
	const char* path = "/../../../init.scope";
	size_t prefix_len = 0;
	size_t path_strip_len = 0;
	ASSERT_EQ(scap_cgroup_prefix_path(prefix, path, &prefix_len, &path_strip_len), SCAP_SUCCESS);
	snprintf(final_path, sizeof(final_path), "%.*s%s", (int)prefix_len, prefix, path + path_strip_len);
	ASSERT_STREQ(final_path,"/init.scope");
}

TEST(cgroups, path_relative_with_final_slash)
{
	char final_path[4096];
	const char* prefix = "/1/2/3/";
	const char* path = "/../../../init.scope";
	size_t prefix_len = 0;
	size_t path_strip_len = 0;
	ASSERT_EQ(scap_cgroup_prefix_path(prefix, path, &prefix_len, &path_strip_len), SCAP_SUCCESS);
	snprintf(final_path, sizeof(final_path), "%.*s%s", (int)prefix_len, prefix, path + path_strip_len);
	ASSERT_STREQ(final_path,"/1/init.scope");
}

TEST(cgroups, path_absolute)
{
	char final_path[4096];
	const char* prefix = "/1/2/3";
	const char* path = "/absolute";
	size_t prefix_len = 0;
	size_t path_strip_len = 0;
	ASSERT_EQ(scap_cgroup_prefix_path(prefix, path, &prefix_len, &path_strip_len), SCAP_SUCCESS);
	snprintf(final_path, sizeof(final_path), "%.*s%s", (int)prefix_len, prefix, path + path_strip_len);
	ASSERT_STREQ(final_path,"/1/2/3/absolute");
}

TEST(cgroups, prefix_empty)
{
	const char* prefix = "";
	const char* path = "/../../absolute";
	size_t prefix_len = 0;
	size_t path_strip_len = 0;
	ASSERT_EQ(scap_cgroup_prefix_path(prefix, path, &prefix_len, &path_strip_len), SCAP_FAILURE);
}

TEST(cgroups, path_empty)
{
	char final_path[4096];
	const char* prefix = "/1/2/3";
	const char* path = "";
	size_t prefix_len = 0;
	size_t path_strip_len = 0;
	ASSERT_EQ(scap_cgroup_prefix_path(prefix, path, &prefix_len, &path_strip_len), SCAP_SUCCESS);
	snprintf(final_path, sizeof(final_path), "%.*s%s", (int)prefix_len, prefix, path + path_strip_len);
	ASSERT_STREQ(final_path,"/1/2/3");
}
