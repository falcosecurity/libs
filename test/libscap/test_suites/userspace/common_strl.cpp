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
#include <libscap/strl.h>

static const char* s_10_chars = "0123456789";
static const char* s_20_chars = "abcdefghijklmnopqrst";

TEST(common_strl, strlcat_input)
{
    char buf[256];
    size_t res;

    strlcpy(buf, s_10_chars, sizeof(buf));

    res = strlcat(buf, s_20_chars, sizeof(buf));
    ASSERT_EQ(res, 30);
    ASSERT_STREQ(buf, "0123456789abcdefghijklmnopqrst");

    strlcpy(buf, s_10_chars, sizeof(buf));

    res = strlcat(buf, s_20_chars, 30);
    ASSERT_EQ(res, 30);
    ASSERT_STREQ(buf, "0123456789abcdefghijklmnopqrs");
    ASSERT_EQ(strlen(buf), 29);
}
