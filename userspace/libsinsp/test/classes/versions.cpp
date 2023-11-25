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

#include "../../version.h"

#include <gtest/gtest.h>

TEST(versions, valid)
{
    EXPECT_FALSE(sinsp_version("1").is_valid());
    EXPECT_FALSE(sinsp_version("1.1").is_valid());
    EXPECT_TRUE(sinsp_version("1.2.3").is_valid());
    EXPECT_EQ(sinsp_version("1.2.3").major(), 1);
    EXPECT_EQ(sinsp_version("1.2.3").minor(), 2);
    EXPECT_EQ(sinsp_version("1.2.3").patch(), 3);
}

TEST(versions, operator_eq)
{
    EXPECT_TRUE(sinsp_version("1.2.3") == sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.3") == sinsp_version("2.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.3") == sinsp_version("1.3.3"));
    EXPECT_FALSE(sinsp_version("1.2.3") == sinsp_version("1.2.4"));
}

TEST(versions, operator_ne)
{
    EXPECT_FALSE(sinsp_version("1.2.3") != sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.3") != sinsp_version("2.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.3") != sinsp_version("1.3.3"));
    EXPECT_TRUE(sinsp_version("1.2.3") != sinsp_version("1.2.4"));
}

TEST(versions, operator_gt)
{
    EXPECT_TRUE(sinsp_version("2.2.3") > sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.3.3") > sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.4") > sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.3") > sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("2.2.3") > sinsp_version("1.5.5"));

    EXPECT_TRUE(sinsp_version("2.2.3") >= sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.3.3") >= sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.4") >= sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.3") >= sinsp_version("1.2.3"));
}

TEST(versions, operator_lt)
{
    EXPECT_FALSE(sinsp_version("2.2.3") < sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.3.3") < sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.4") < sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.3") < sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.1.150") < sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("0.18.150") < sinsp_version("1.2.3"));

    EXPECT_FALSE(sinsp_version("2.2.3") <= sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.3.3") <= sinsp_version("1.2.3"));
    EXPECT_FALSE(sinsp_version("1.2.4") <= sinsp_version("1.2.3"));
    EXPECT_TRUE(sinsp_version("1.2.3") <= sinsp_version("1.2.3"));
}

TEST(versions, compatible_with)
{
    sinsp_version a("1.2.3");
    EXPECT_FALSE(a.compatible_with(sinsp_version("0.2.3")));
    EXPECT_FALSE(a.compatible_with(sinsp_version("2.2.3")));
    EXPECT_TRUE(a.compatible_with(sinsp_version("1.1.3")));
    EXPECT_FALSE(a.compatible_with(sinsp_version("1.3.3")));
    EXPECT_TRUE(a.compatible_with(sinsp_version("1.2.2")));
    EXPECT_FALSE(a.compatible_with(sinsp_version("1.2.4")));
    EXPECT_TRUE(a.compatible_with(sinsp_version("1.1.19")));
    EXPECT_TRUE(a.compatible_with(a));
}
