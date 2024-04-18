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
#include <libsinsp/filter/parser.h>
#include <libsinsp/filter/ppm_codes.h>

// helps testing that ppm_sc_codes are correctly found in a filter
struct testdata_sc_set 
{
    using set_t = libsinsp::events::set<ppm_sc_code>;
    const set_t close_set = { PPM_SC_CLOSE };
    const set_t openat_set = { PPM_SC_OPENAT };

    virtual set_t all_set() const { return libsinsp::events::all_sc_set(); };
    virtual set_t filter_set(const std::string filter) const
    {
        return libsinsp::filter::ast::ppm_sc_codes(
            libsinsp::filter::parser(filter).parse().get());
    }
};

// helps testing that ppm_event_codes are correctly found in a filter
struct testdata_event_set 
{
    using set_t = libsinsp::events::set<ppm_event_code>;
    const set_t close_set = { PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X };
    const set_t openat_set = {
        PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
        PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X };

    virtual set_t all_set() const { return  libsinsp::events::all_event_set(); };
    virtual set_t filter_set(const std::string filter) const
    {
        return libsinsp::filter::ast::ppm_event_codes(
            libsinsp::filter::parser(filter).parse().get());
    }
};

// helps testing that ppm_event_codes can be obtained by searching for
// ppm_sc_codes in a filter, and then using the
// libsinsp::events::sc_set_to_event_set conversion utility
struct testdata_event_set_converted: testdata_event_set
{
    set_t all_set() const override {
        return libsinsp::events::all_event_set().filter([](ppm_event_code e) {
            // the following categories are expected to have information loss
            // loss as they are not mappable through the PPM_SC enumerative,
            // due to them not being related to actual linux kernel events.
            return !libsinsp::events::is_unused_event(e)
                && !libsinsp::events::is_metaevent(e)
                && !libsinsp::events::is_plugin_event(e);
        });
    };

    set_t filter_set(const std::string filter) const override
    {
        testdata_sc_set s;
        return libsinsp::events::sc_set_to_event_set(s.filter_set(filter));
    }
};

// helps testing that ppm_sc_codes can be obtained by searching for
// ppm_event_codes in a filter, and then using the
// libsinsp::events::event_set_to_sc_set conversion utility
struct testdata_sc_set_converted: testdata_sc_set
{
    set_t filter_set(const std::string filter) const override
    {
        testdata_event_set s;
        return libsinsp::events::event_set_to_sc_set(s.filter_set(filter));
    }
};

// helpers to make comparisons easier and more expressive in case of fail
#define ASSERT_FILTER_EQ(t, a, b) { ASSERT_EQ(t.filter_set(a), t.filter_set(b)); }
#define ASSERT_FILTER_SET_EQ(t, a, b) { ASSERT_EQ(t.filter_set(a), b); }

// helper for making sure tests are run on multiple testdata,
// so that we're sure that the tests covers the high-level semantics no
// matter how events are represented. At the same time, this is supposed to
// stress the ppm_sc_code <-> ppm_event_code conversions.
//
// NOTE: tests relying on the "_converted" testdata play with converting sets of
// ppm_sc_code <-> ppm_event_code, which in general can cause information loss.
// However, in none of the tests below this is significant, because no filter
// deals with corner cases such as generic events, meta events, etc.
#define TEST_CODES(test_suite_name, test_name) \
    template <typename T> void test_##test_name(); \
    TEST(test_suite_name, sc_##test_name) {test_##test_name<testdata_sc_set>();}; \
    TEST(test_suite_name, event_##test_name) {test_##test_name<testdata_event_set>();}; \
    TEST(test_suite_name, sc_converted_##test_name) {test_##test_name<testdata_sc_set_converted>();}; \
    TEST(test_suite_name, event_converted_##test_name) {test_##test_name<testdata_event_set_converted>();}; \
    template <typename T> void test_##test_name()


TEST_CODES(filter_ppm_codes, check_openat)
{
    T t;
    auto openat_only = t.openat_set;
    auto not_openat = t.all_set().diff(openat_only);

    /* `openat_only` */
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type = openat", openat_only);
    ASSERT_FILTER_SET_EQ(t, "not evt.type != openat", openat_only);
    ASSERT_FILTER_SET_EQ(t, "not not evt.type = openat", openat_only);
    ASSERT_FILTER_SET_EQ(t, "not not not not evt.type = openat", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type in (openat)", openat_only);
    ASSERT_FILTER_SET_EQ(t, "not (not evt.type=openat)", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and proc.name=nginx", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and not proc.name=nginx", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and (proc.name=nginx)", openat_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and not (evt.type=close and proc.name=nginx)", openat_only);

    /* `not_openat` */
    ASSERT_FILTER_SET_EQ(t, "evt.type!=openat", not_openat);
    ASSERT_FILTER_SET_EQ(t, "not not not evt.type = openat", not_openat);
    ASSERT_FILTER_SET_EQ(t, "not evt.type=openat", not_openat);
    ASSERT_FILTER_SET_EQ(t, "evt.type=close or evt.type!=openat", not_openat);
}

TEST_CODES(filter_ppm_codes, check_openat_or_close)
{
    T t;
    auto openat_close_only = t.openat_set.merge(t.close_set);
    auto not_openat_close = t.all_set().diff(openat_close_only);

    /* `openat_close_only` */
    ASSERT_FILTER_SET_EQ(t, "evt.type in (openat, close)", openat_close_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat or evt.type=close", openat_close_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat or (evt.type=close and proc.name=nginx)", openat_close_only);
    ASSERT_FILTER_SET_EQ(t, "evt.type=close or (evt.type=openat and proc.name=nginx)", openat_close_only);

    /* not `not_openat_close` */
    ASSERT_FILTER_SET_EQ(t, "not evt.type in (openat, close)", not_openat_close);
    ASSERT_FILTER_SET_EQ(t, "not not not evt.type in (openat, close)", not_openat_close);
    ASSERT_FILTER_SET_EQ(t, "evt.type!=openat and evt.type!=close", not_openat_close);
}

TEST_CODES(filter_ppm_codes, check_all_events)
{
    /* Computed as a difference of the empty set */
    T t;
    auto all_events = t.all_set();

    ASSERT_FILTER_SET_EQ(t, "evt.type!=openat or evt.type!=close", all_events);
    ASSERT_FILTER_SET_EQ(t, "proc.name=nginx", all_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat or proc.name=nginx", all_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat or (proc.name=nginx)", all_events);
    ASSERT_FILTER_SET_EQ(t, "(evt.type=openat) or proc.name=nginx", all_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=close or not (evt.type=openat and proc.name=nginx)", all_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat or not (evt.type=close and proc.name=nginx)", all_events);
}

TEST_CODES(filter_ppm_codes, check_no_events)
{
    T t;
    auto no_events = t.all_set();
    no_events.clear();

    ASSERT_FILTER_SET_EQ(t, "evt.type=close and evt.type=openat", no_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and (evt.type=close and proc.name=nginx)", no_events);
    ASSERT_FILTER_SET_EQ(t, "evt.type=openat and (evt.type=close)", no_events);
}

TEST_CODES(filter_ppm_codes, check_properties)
{
    T t;
    auto no_events = t.all_set();
    no_events.clear();

    // see: https://github.com/falcosecurity/libs/pull/854#issuecomment-1411151732
    ASSERT_FILTER_EQ(t, 
        "evt.type in (connect, execve, accept, mmap, container) and not (proc.name=cat and evt.type=mmap)",
        "evt.type in (accept, connect, container, execve, mmap)");
    ASSERT_FILTER_SET_EQ(t, "(evt.type=mmap and not evt.type=mmap)", no_events);

    // defining algebraic base sets
    std::string zerof = "(evt.type in ())"; ///< "zero"-set: no evt type should matches the filter
    std::string onef = "(evt.type exists)"; ///< "one"-set: all evt types should match the filter
    std::string neutral1 = "(proc.name=cat)"; ///< "neutral"-sets: evt types are not checked in the filter
    std::string neutral2 = "(not proc.name=cat)";
    ASSERT_FILTER_EQ(t, onef, neutral1);
    ASSERT_FILTER_EQ(t, onef, neutral2);

    // algebraic set properties
    // 1' = 0
    ASSERT_FILTER_EQ(t, "not " + onef, zerof);
    // 0' = 1
    ASSERT_FILTER_EQ(t, "not " + zerof, onef);
    // (A')' = A
    ASSERT_FILTER_EQ(t, "evt.type=mmap", "not (not evt.type=mmap)");
    // A * A' = 0
    ASSERT_FILTER_SET_EQ(t, (zerof), no_events);
    // A + A' = 1
    ASSERT_FILTER_EQ(t, "evt.type=mmap or not evt.type=mmap", onef);
    ASSERT_FILTER_EQ(t, "evt.type=mmap or not evt.type=mmap", neutral1);
    ASSERT_FILTER_EQ(t, "evt.type=mmap or not evt.type=mmap", neutral2);
    // 0 * 1 = 0
    ASSERT_FILTER_EQ(t, zerof + " and " + onef, zerof);
    ASSERT_FILTER_EQ(t, zerof + " and " + neutral1, zerof);
    ASSERT_FILTER_EQ(t, zerof + " and " + neutral2, zerof);
    // 0 + 1 = 1
    ASSERT_FILTER_EQ(t, zerof + " or " + onef, onef);
    ASSERT_FILTER_EQ(t, zerof + " or " + neutral1, onef);
    ASSERT_FILTER_EQ(t, zerof + " or " + neutral2, onef);
    // A * 0 = 0
    ASSERT_FILTER_EQ(t, "evt.type=mmap and " + zerof, zerof);
    // A * 1 = A
    ASSERT_FILTER_EQ(t, "evt.type=mmap and " + onef, "evt.type=mmap");
    ASSERT_FILTER_EQ(t, "evt.type=mmap and " + neutral1, "evt.type=mmap");
    ASSERT_FILTER_EQ(t, "evt.type=mmap and " + neutral2, "evt.type=mmap");
    // A + 0 = A
    ASSERT_FILTER_EQ(t, "evt.type=mmap or " + zerof, "evt.type=mmap");
    // A + 1 = 1
    ASSERT_FILTER_EQ(t, "evt.type=mmap or " + onef, onef);
    ASSERT_FILTER_EQ(t, "evt.type=mmap or " + neutral1, onef);
    ASSERT_FILTER_EQ(t, "evt.type=mmap or " + neutral2, onef);
    // A + A = A
    ASSERT_FILTER_EQ(t, "evt.type=mmap or evt.type=mmap", "evt.type=mmap");
    // A * A = A
    ASSERT_FILTER_EQ(t, "evt.type=mmap and evt.type=mmap", "evt.type=mmap");

    // de morgan's laws
    ASSERT_FILTER_EQ(t, 
        "not (proc.name=cat or evt.type=mmap)",
        "not proc.name=cat and not evt.type=mmap");
    ASSERT_FILTER_EQ(t, 
        "not (proc.name=cat or fd.type=file)",
        "not proc.name=cat and not fd.type=file");
    ASSERT_FILTER_EQ(t, 
        "not (evt.type=execve or evt.type=mmap)",
        "not evt.type=execve and not evt.type=mmap");
    ASSERT_FILTER_EQ(t, 
        "not (evt.type=mmap or evt.type=mmap)",
        "not evt.type=mmap and not evt.type=mmap");
    ASSERT_FILTER_EQ(t, 
        "not (proc.name=cat and evt.type=mmap)",
        "not proc.name=cat or not evt.type=mmap");
    ASSERT_FILTER_EQ(t, 
        "not (proc.name=cat and fd.type=file)",
        "not proc.name=cat or not fd.type=file");
    ASSERT_FILTER_EQ(t, 
        "not (evt.type=execve and evt.type=mmap)",
        "not evt.type=execve or not evt.type=mmap");
    ASSERT_FILTER_EQ(t, 
        "not (evt.type=mmap and evt.type=mmap)",
        "not evt.type=mmap or not evt.type=mmap");

    // negation isomorphism
    ASSERT_FILTER_EQ(t, "not evt.type=mmap", "evt.type!=mmap");
    ASSERT_FILTER_EQ(t, "not proc.name=cat", "proc.name!=cat");

    // commutative property (and)
    ASSERT_FILTER_EQ(t, "evt.type=execve and evt.type=mmap", "evt.type=mmap and evt.type=execve");
    ASSERT_FILTER_EQ(t, "not (evt.type=execve and evt.type=mmap)", "not (evt.type=mmap and evt.type=execve)");
    ASSERT_FILTER_EQ(t, "not evt.type=execve and not evt.type=mmap", "not evt.type=mmap and not evt.type=execve");
    ASSERT_FILTER_EQ(t, "proc.name=cat and evt.type=mmap", "evt.type=mmap and proc.name=cat");
    ASSERT_FILTER_EQ(t, "not (proc.name=cat and evt.type=mmap)", "not (evt.type=mmap and proc.name=cat)");
    ASSERT_FILTER_EQ(t, "not proc.name=cat and not evt.type=mmap", "not evt.type=mmap and not proc.name=cat");
    ASSERT_FILTER_EQ(t, "proc.name=cat and fd.type=file", "fd.type=file and proc.name=cat");
    ASSERT_FILTER_EQ(t, "not (proc.name=cat and fd.type=file)", "not (fd.type=file and proc.name=cat)");
    ASSERT_FILTER_EQ(t, "not proc.name=cat and not fd.type=file", "not fd.type=file and not proc.name=cat");

    // commutative property (or)
    ASSERT_FILTER_EQ(t, "evt.type=execve or evt.type=mmap", "evt.type=mmap or evt.type=execve");
    ASSERT_FILTER_EQ(t, "not (evt.type=execve or evt.type=mmap)", "not (evt.type=mmap or evt.type=execve)");
    ASSERT_FILTER_EQ(t, "not evt.type=execve or not evt.type=mmap", "not evt.type=mmap or not evt.type=execve");
    ASSERT_FILTER_EQ(t, "proc.name=cat or evt.type=mmap", "evt.type=mmap or proc.name=cat");
    ASSERT_FILTER_EQ(t, "not (proc.name=cat or evt.type=mmap)", "not (evt.type=mmap or proc.name=cat)");
    ASSERT_FILTER_EQ(t, "not proc.name=cat or not evt.type=mmap", "not evt.type=mmap or not proc.name=cat");
    ASSERT_FILTER_EQ(t, "proc.name=cat or fd.type=file", "fd.type=file or proc.name=cat");
    ASSERT_FILTER_EQ(t, "not (proc.name=cat or fd.type=file)", "not (fd.type=file or proc.name=cat)");
    ASSERT_FILTER_EQ(t, "not proc.name=cat or not fd.type=file", "not fd.type=file or not proc.name=cat");
}
