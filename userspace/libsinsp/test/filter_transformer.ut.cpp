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

#include <unordered_set>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_filter_transformer.h>

static std::unordered_set<ppm_param_type> all_param_types()
{
    std::unordered_set<ppm_param_type> ret;
    for (auto i = PT_NONE; i < PT_MAX; i = (ppm_param_type) ((size_t) i + 1))
    {
        ret.insert(i);
    }
    return ret;
}

static std::string supported_type_msg(ppm_param_type t, bool support_expected)
{
    return "expected param type to"
        + std::string((support_expected ? " " : " not "))
        + "be supported: "
        + std::string(param_type_to_string(t));
}

static std::string eq_test_msg(const std::pair<std::string, std::string> &tc)
{
    return "expected '" 
           + tc.first + "' (length: " + std::to_string(tc.first.length()) + ")"
           + " to be equal to '" + tc.second + "' (length: " + std::to_string(tc.second.length()) + ")";
}

static extract_value_t const_str_to_extract_value(const char* v)
{
    extract_value_t ret;
    ret.ptr = (uint8_t*) v;
    ret.len = strlen(v) + 1;
    return ret;
}

TEST(sinsp_filter_transformer, toupper)
{
    sinsp_filter_transformer tr(filter_transformer_type::FTR_TOUPPER);

    auto all_types = all_param_types();

    auto supported_types = std::unordered_set<ppm_param_type>({
        PT_CHARBUF, PT_FSPATH, PT_FSRELPATH });

    auto test_cases = std::vector<std::pair<std::string, std::string>>{
        {"hello", "HELLO"},
        {"world", "WORLD"},
        {"eXcItED", "EXCITED"},
        {"", ""},
    };

    std::vector<extract_value_t> sample_vals;

    for (auto& tc : test_cases)
    {
        sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
    }

    // check for unsupported types
    for (auto t : all_types)
    {
        if (supported_types.find(t) == supported_types.end())
        {
            auto vals = sample_vals;
            EXPECT_FALSE(tr.transform_type(t)) << supported_type_msg(t, false);
            EXPECT_ANY_THROW(tr.transform_values(vals, t)) << supported_type_msg(t, false);
        }
    }

    // check for supported types
    for (auto t : supported_types)
    {
        auto original = t;
        EXPECT_TRUE(tr.transform_type(t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t); // note: toupper is expected not to alter the type

        auto vals = sample_vals;
        EXPECT_TRUE(tr.transform_values(vals, t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t);
        EXPECT_EQ(vals.size(), test_cases.size());

        for (uint32_t i = 0; i < test_cases.size(); i++)
        {
            EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second) << eq_test_msg(test_cases[i]);
            EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
        }
    }
}

TEST(sinsp_filter_transformer, tolower)
{
    sinsp_filter_transformer tr(filter_transformer_type::FTR_TOLOWER);

    auto all_types = all_param_types();

    auto supported_types = std::unordered_set<ppm_param_type>({
        PT_CHARBUF, PT_FSPATH, PT_FSRELPATH });

    auto test_cases = std::vector<std::pair<std::string, std::string>>{
        {"HELLO", "hello"},
        {"world", "world"},
        {"NoT_eXcItED", "not_excited"},
        {"", ""},
    };

    std::vector<extract_value_t> sample_vals;

    for (auto& tc : test_cases)
    {
        sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
    }

    // check for unsupported types
    for (auto t : all_types)
    {
        if (supported_types.find(t) == supported_types.end())
        {
            auto vals = sample_vals;
            EXPECT_FALSE(tr.transform_type(t)) << supported_type_msg(t, false);
            EXPECT_ANY_THROW(tr.transform_values(vals, t)) << supported_type_msg(t, false);
        }
    }

    // check for supported types
    for (auto t : supported_types)
    {
        auto original = t;
        EXPECT_TRUE(tr.transform_type(t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t); // note: tolower is expected not to alter the type

        auto vals = sample_vals;
        EXPECT_TRUE(tr.transform_values(vals, t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t);
        EXPECT_EQ(vals.size(), test_cases.size());

        for (uint32_t i = 0; i < test_cases.size(); i++)
        {
            EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second) << eq_test_msg(test_cases[i]);
            EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
        }
    }
}

TEST(sinsp_filter_transformer, b64)
{
    sinsp_filter_transformer tr(filter_transformer_type::FTR_BASE64);

    auto all_types = all_param_types();

    auto supported_types = std::unordered_set<ppm_param_type>({
        PT_CHARBUF, PT_BYTEBUF });

    auto test_cases = std::vector<std::pair<std::string, std::string>>{
        {"aGVsbG8=", "hello"},
        {"d29ybGQgIQ==", "world !"},
        {"", ""},
    };

    std::vector<std::string> invalid_test_cases {
        "!!!"
    };

    std::vector<extract_value_t> sample_vals;
    for (auto& tc : test_cases)
    {
        sample_vals.push_back(const_str_to_extract_value(tc.first.c_str()));
    }

    // check for unsupported types
    for (auto t : all_types)
    {
        if (supported_types.find(t) == supported_types.end())
        {
            auto vals = sample_vals;
            EXPECT_FALSE(tr.transform_type(t)) << supported_type_msg(t, false);
            EXPECT_ANY_THROW(tr.transform_values(vals, t)) << supported_type_msg(t, false);
        }
    }

    // check for supported types
    for (auto t : supported_types)
    {
        auto original = t;
        EXPECT_TRUE(tr.transform_type(t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t); // note: tolower is expected not to alter the type

        auto vals = sample_vals;
        EXPECT_TRUE(tr.transform_values(vals, t)) << supported_type_msg(original, true);
        EXPECT_EQ(original, t);
        EXPECT_EQ(vals.size(), test_cases.size());

        for (uint32_t i = 0; i < test_cases.size(); i++)
        {
            EXPECT_EQ(std::string((const char *)vals[i].ptr), test_cases[i].second) << eq_test_msg(test_cases[i]);
            EXPECT_EQ(vals[i].len, test_cases[i].second.length() + 1) << eq_test_msg(test_cases[i]);
        }
    }

    std::vector<extract_value_t> invalid_vals;
    for (auto& tc : invalid_test_cases)
    {
        invalid_vals.push_back(const_str_to_extract_value(tc.c_str()));
    }

    // check invalid input being rejected
    {
        auto t = PT_CHARBUF;
        EXPECT_FALSE(tr.transform_values(invalid_vals, t));
        EXPECT_EQ(t, PT_CHARBUF);
    }
}
