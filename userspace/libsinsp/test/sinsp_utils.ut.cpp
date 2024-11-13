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
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_exception.h>

TEST(sinsp_utils_test, concatenate_paths) {
	// Some tests were motivated by this resource:
	// https://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap04.html#tag_04_11

	// PLEASE NOTE:
	// * current impl does not support unicode.
	// * current impl does not sanitize path1
	// * current impl expects path1 to end with '/'
	// * current impl skips path1 altogether if path2 is absolute

	std::string path1, path2, res;

	res = sinsp_utils::concatenate_paths("", "");
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "../";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "..";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "/";
	path2 = "../";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/", res);

	path1 = "a";
	path2 = "../";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("a..", res);  // since the helper does not add any "/" between path1 and path2, we end
	                        // up with this.

	path1 = "a/";
	path2 = "../";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "/foo";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/foo", res);

	path1 = "foo/";
	path2 = "..//a";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("a", res);  // path2 has been sanitized, plus we moved up a folder because of ".."

	path1 = "/foo/";
	path2 = "..//a";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/a", res);  // path2 has been sanitized, plus we moved up a folder because of ".."

	path1 = "heolo";
	path2 = "w////////////..//////.////////r.|";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("r.|", res);  // since the helper does not add any "/" between path1 and path2, we end
	                        // up with this.

	path1 = "heolo";
	path2 = "w/////////////..//";  // heolow/////////////..// > heolow/..// -> /
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);  // since the helper does not add any "/" between path1 and path2, we end up
	                     // with this, ie a folder up from "heolow/"

	path1 = "";
	path2 = "./";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ(path2, res);

	path1 = "";
	path2 = "//dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "/";
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "";
	path2 = "///dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "";
	path2 = "./dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("dir/term", res);

	path1 = "/";
	path2 = "//dir//////term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "/";
	path2 = "/dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "../.../";
	path2 = "dir/././././../../.../term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("../.../term", res);

	path1 = "../.../";
	path2 = "/app/custom/dir/././././../../.../term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/.../term", res);

	path1 = "../.../";
	path2 = "/app/custom/dir/././././../../term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/term", res);

	path1 = "./app";
	path2 = "custom/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("./appcustom/term", res);  // since path1 is not '/' terminated, we expect a string
	                                     // concat without further path fields

	path1 = "/app";
	path2 = "custom/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/appcustom/term", res);  // since path1 is not '/' terminated, we expect a string
	                                    // concat without further path fields

	path1 = "app";
	path2 = "custom/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("appcustom/term", res);  // since path1 is not '/' terminated, we expect a string
	                                   // concat without further path fields

	path1 = "app/";
	path2 = "custom/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("app/custom/term", res);

	// We don't support sanitizing path1
	path1 = "app/////";
	path2 = "custom////term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("app/////custom/term", res);

	path1 = "/";
	path2 = "/app/custom/dir/././././../../term/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/term", res);

	path1 = "/";
	path2 = "////app";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/app", res);

	// This path is too long so we should receive our predefined string.
	path1 = std::string(1500, 'C');
	path2 = "dir/term";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/DIR_TOO_LONG/FILENAME_TOO_LONG", res);

	/* No unicode support
	path1 = "/root/";
	path2 = "../😉";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/😉", res);

	path1 = "/root/";
	path2 = "../诶比西";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/诶比西", res);

	path1 = "/root/";
	path2 = "../АБВЙЛж";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/АБВЙЛж", res);

	path1 = "/root";
	path2 = "c:/hello/world/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/root/c:/hello/world", res); */
}

TEST(sinsp_utils_test, sinsp_split) {
	const char *in = "hello\0world\0";
	size_t len = 11;
	std::vector<std::string> split = sinsp_split({in, len}, '\0');

	EXPECT_EQ(split.size(), 2);
	EXPECT_EQ(split[0], "hello");
	EXPECT_EQ(split[1], "world");

	std::string str;

	str = "A,B,C";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 3);
	EXPECT_EQ(split[0], "A");
	EXPECT_EQ(split[1], "B");
	EXPECT_EQ(split[2], "C");

	str = ",B,C";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 3);
	EXPECT_EQ(split[0], "");
	EXPECT_EQ(split[1], "B");
	EXPECT_EQ(split[2], "C");

	str = "A,B,";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 3);
	EXPECT_EQ(split[0], "A");
	EXPECT_EQ(split[1], "B");
	EXPECT_EQ(split[2], "");

	str = "";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 0);

	str = "A";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 1);
	EXPECT_EQ(split[0], "A");

	str = ",";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 2);
	EXPECT_EQ(split[0], "");
	EXPECT_EQ(split[1], "");

	str = ",,";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 3);
	EXPECT_EQ(split[0], "");
	EXPECT_EQ(split[1], "");
	EXPECT_EQ(split[2], "");

	str = "A,";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 2);
	EXPECT_EQ(split[0], "A");
	EXPECT_EQ(split[1], "");

	str = ",B";
	split = sinsp_split(str, ',');
	EXPECT_EQ(split.size(), 2);
	EXPECT_EQ(split[0], "");
	EXPECT_EQ(split[1], "B");
}
