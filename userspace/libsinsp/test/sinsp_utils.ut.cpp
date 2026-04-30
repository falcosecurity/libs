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
	// * current impl supports UTF-8 encoding.
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

	// Valid UTF-8 multibyte characters pass through unchanged.
	path1 = "/root/";
	path2 = "../😀";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/😀", res);

	path1 = "/root/";
	path2 = "../诶比西";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/诶比西", res);

	path1 = "/root/";
	path2 = "../АБВЙЛж";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/АБВЙЛж", res);

	// Invalid UTF-8 bytes are replaced with U+FFFD (EF BF BD).
	path1 = "/root/";
	path2 = "../\xFF\xFE/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD\xEF\xBF\xBD/test", res);

	// Mix of valid UTF-8 (é = C3 A9) and an invalid byte (FF).
	path1 = "/root/";
	path2 = "../\xC3\xA9\xFF/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xC3\xA9\xEF\xBF\xBD/test", res);

	// C1 control character encoded as valid-but-non-printable UTF-8 (U+0085, NEL = C2 85) is
	// replaced.
	path1 = "/root/";
	path2 = "../\xC2\x85/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD/test", res);

	// Non-printable ASCII control characters are replaced with U+FFFD.
	path1 = "/root/";
	path2 = "../\x01\x1F/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD\xEF\xBF\xBD/test", res);

	// Unicode non-characters are replaced with U+FFFD.
	// U+FDD0 (EF B7 90) - non-character in the range U+FDD0..U+FDEF.
	path1 = "/root/";
	path2 = "../\xEF\xB7\x90/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD/test", res);

	// U+FFFF (EF BF BF) - non-character U+FFFF.
	path1 = "/root/";
	path2 = "../\xEF\xBF\xBF/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD/test", res);

	// U+1FFFE (F0 9F BF BE) - end-of-plane non-character in plane 1.
	path1 = "/root/";
	path2 = "../\xF0\x9F\xBF\xBE/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD/test", res);

	// Maximal-subpart: 3-byte lead (E1) + valid first continuation (80) + bad second continuation
	// (2F = '/'). The maximal subpart is 2 bytes, so the pair is replaced with one U+FFFD.
	path1 = "/root/";
	path2 = "../\xE1\x80/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD/test", res);

	// Maximal-subpart: surrogate bytes (ED A0 80). The first continuation A0 is outside the valid
	// range 80-9F for lead ED, so the maximal subpart is just ED, and the entire sequence is
	// replaced with three individual U+FFFDs.
	path1 = "/root/";
	path2 = "../\xED\xA0\x80/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD/test", res);

	// Maximal-subpart: overlong 3-byte (E0 9F BF). The first continuation 9F is outside the valid
	// range A0-BF for lead E0, so the maximal subpart is just E0, and the entire sequence is
	// replaced with three individual U+FFFDs.
	path1 = "/root/";
	path2 = "../\xE0\x9F\xBF/test";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD/test", res);

	// todo(ekoops): path1 and Windows-style path2... What to do here?
	/* path1 = "/root";
	path2 = "c:/hello/world/";
	res = sinsp_utils::concatenate_paths(path1, path2);
	EXPECT_EQ("/rootc:/hello/world", res); */
}

TEST(sinsp_utils_test, sanitize_string) {
	std::string str;
	std::string storage;
	std::string_view res;

	// Empty string passes through unchanged.
	str = "";
	res = sanitize_string(str, storage);
	EXPECT_EQ("", res);

	// Valid pure ASCII passes through unchanged.
	str = "hello world";
	res = sanitize_string(str, storage);
	EXPECT_EQ("hello world", res);

	// Valid multibyte UTF-8 passes through unchanged.
	str = "😀";  // U+1F600, 4-byte sequence
	res = sanitize_string(str, storage);
	EXPECT_EQ("😀", res);

	str = "诶比西";  // 3-byte sequences
	res = sanitize_string(str, storage);
	EXPECT_EQ("诶比西", res);

	str = "АБВЙЛж";  // 2-byte sequences (Cyrillic)
	res = sanitize_string(str, storage);
	EXPECT_EQ("АБВЙЛж", res);

	// Mixed valid ASCII and valid multibyte UTF-8 passes through unchanged.
	str = "hello 😀 world";
	res = sanitize_string(str, storage);
	EXPECT_EQ("hello 😀 world", res);

	// Non-printable ASCII control characters (0x00-0x1F) are replaced with U+FFFD.
	str = "foo\x01\x1Fxyz";
	res = sanitize_string(str, storage);
	EXPECT_EQ("foo\xEF\xBF\xBD\xEF\xBF\xBDxyz", res);

	// DEL (0x7F) is replaced with U+FFFD.
	str = "foo\x7Fxyz";
	res = sanitize_string(str, storage);
	EXPECT_EQ("foo\xEF\xBF\xBDxyz", res);

	// C1 control character encoded as valid-but-non-printable UTF-8 (U+0085, NEL = C2 85) is
	// replaced with U+FFFD.
	str = "foo\xC2\x85xyz";
	res = sanitize_string(str, storage);
	EXPECT_EQ("foo\xEF\xBF\xBDxyz", res);

	// Invalid UTF-8 bytes are replaced with U+FFFD (EF BF BD).
	str = "foo\xFF\xFExyz";
	res = sanitize_string(str, storage);
	EXPECT_EQ("foo\xEF\xBF\xBD\xEF\xBF\xBDxyz", res);

	// Mix of valid UTF-8 (é = C3 A9) and an invalid byte (FF).
	str = "\xC3\xA9\xFF";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xC3\xA9\xEF\xBF\xBD", res);

	// Invalid byte at the start of the string.
	str = "\x80xyz";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBDxyz", res);

	// Invalid byte at the end of the string.
	str = "foo\xFF";
	res = sanitize_string(str, storage);
	EXPECT_EQ("foo\xEF\xBF\xBD", res);

	// All bytes invalid.
	str = "\x80\xFF\xFE";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD", res);

	// Unicode non-characters are replaced with U+FFFD.
	// U+FDD0 (EF B7 90) - non-character in the range U+FDD0..U+FDEF.
	str = "\xEF\xB7\x90";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD", res);

	// U+FFFF (EF BF BF) - non-character U+FFFF.
	str = "\xEF\xBF\xBF";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD", res);

	// U+1FFFE (F0 9F BF BE) - end-of-plane non-character in plane 1.
	str = "\xF0\x9F\xBF\xBE";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD", res);

	// Maximal-subpart: 3-byte lead (E1) + valid first continuation (80) + bad second continuation
	// (61 = 'a'). The maximal subpart is 2 bytes, so the pair is replaced with one U+FFFD.
	str = "\xE1\x80x";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBDx", res);

	// Maximal-subpart: truncated 3-byte sequence at end of string. Lead (E1) + valid first
	// continuation (80), missing second continuation. Replaced with one U+FFFD.
	str = "hello\xE1\x80";
	res = sanitize_string(str, storage);
	EXPECT_EQ("hello\xEF\xBF\xBD", res);

	// Maximal-subpart: surrogate bytes (ED A0 80). The first continuation A0 is outside the valid
	// range 80-9F for lead ED, so the maximal subpart is just ED, and the entire sequence is
	// replaced with three individual U+FFFDs.
	str = "\xED\xA0\x80";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD", res);

	// Maximal-subpart: overlong 3-byte (E0 9F BF). The first continuation 9F is outside the valid
	// range A0-BF for lead E0, so the maximal subpart is just E0, and the entire sequence is
	// replaced with three individual U+FFFDs.
	str = "\xE0\x9F\xBF";
	res = sanitize_string(str, storage);
	EXPECT_EQ("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD", res);
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
