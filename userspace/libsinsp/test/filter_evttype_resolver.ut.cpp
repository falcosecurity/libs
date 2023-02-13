#include <sinsp.h>
#include <filter.h>
#include <gtest/gtest.h>
#include <list>
#include "filter_evttype_resolver.h"

using namespace std;

set<uint16_t> openat_only{
	PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X};

set<uint16_t> close_only{
	PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X};

set<uint16_t> openat_close{
	PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
	PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X};

set<uint16_t> not_openat;
set<uint16_t> not_openat_close;
set<uint16_t> not_close;
set<uint16_t> all_events;
set<uint16_t> no_events;
std::unique_ptr<libsinsp::filter::ast::expr> f;

void compare_evttypes(std::unique_ptr<libsinsp::filter::ast::expr> f, set<uint16_t> &expected)
{
	set<uint16_t> actual;
	libsinsp::filter::evttype_resolver().evttypes(f.get(), actual);

	ASSERT_EQ(actual.size(), expected.size());

	auto final = actual.begin();
	auto matching = expected.begin();

	for(; final != actual.end(); final++, matching++)
	{
		ASSERT_EQ(*matching, *final);
	}
}

std::unique_ptr<libsinsp::filter::ast::expr> compile(const string &fltstr)
{
    return libsinsp::filter::parser(fltstr).parse();
}

static void compare_filters_evttypes(const std::string &a, const std::string &b)
{
	auto fa = compile(a);
	auto fb = compile(b);
	std::set<uint16_t> typesa;
	libsinsp::filter::evttype_resolver().evttypes(fa.get(), typesa);
	compare_evttypes(std::move(fb), typesa);
	}

static void fill_sets(set<uint16_t> &not_openat, set<uint16_t> &not_openat_close, set<uint16_t> &not_close, set<uint16_t> &all_events)
{
	for(uint32_t i = 2; i < PPM_EVENT_MAX; i++)
	{
		// Skip events that are unused.
		if(sinsp::is_unused_event(i))
		{
			continue;
		}

		all_events.insert(i);
		if(openat_only.find(i) == openat_only.end())
		{
			not_openat.insert(i);
		}
		if(openat_close.find(i) == openat_close.end())
		{
			not_openat_close.insert(i);
		}
		if (close_only.find(i) == close_only.end())
		{
			not_close.insert(i);
		}
	}
}


TEST(filter_evttype_resolver, simple_checks_evttype_resolver)
{
	fill_sets(not_openat, not_openat_close, not_close, all_events);

	// SECTION("evt_type_eq")

	f = compile("evt.type=openat");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("evt_type_in")

	f = compile("evt.type in (openat, close)");
	compare_evttypes(std::move(f), openat_close);

	// SECTION("evt_type_ne")

	f = compile("evt.type!=openat");
	compare_evttypes(std::move(f), not_openat);

	// SECTION("not_evt_type_eq")

	f = compile("not evt.type=openat");
	compare_evttypes(std::move(f), not_openat);

	// SECTION("not_evt_type_in")

	f = compile("not evt.type in (openat, close)");
	compare_evttypes(std::move(f), not_openat_close);

	// SECTION("not_evt_type_ne")

	f = compile("not evt.type != openat");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("evt_type_or")

	f = compile("evt.type=openat or evt.type=close");
	compare_evttypes(std::move(f), openat_close);

	// SECTION("not_evt_type_or")

	f = compile("evt.type!=openat or evt.type!=close");
	compare_evttypes(std::move(f), all_events);

	// SECTION("evt_type_or_ne")

	f = compile("evt.type=close or evt.type!=openat");
	compare_evttypes(std::move(f), not_openat);

	// SECTION("evt_type_and")

	f = compile("evt.type=close and evt.type=openat");
	compare_evttypes(std::move(f), no_events);

	// SECTION("evt_type_and_non_evt_type")

	f = compile("evt.type=openat and proc.name=nginx");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("evt_type_and_non_evt_type_not")

	f = compile("evt.type=openat and not proc.name=nginx");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("evt_type_and_nested")

	f = compile("evt.type=openat and (proc.name=nginx)");
	compare_evttypes(std::move(f), openat_only);
}

TEST(filter_evttype_resolver, nested_multi_checks_evttype_resolver)
{
	// SECTION("evt_type_and_nested_multi")

	f = compile("evt.type=openat and (evt.type=close and proc.name=nginx)");
	compare_evttypes(std::move(f), no_events);

	// SECTION("non_evt_type")

	f = compile("proc.name=nginx");
	compare_evttypes(std::move(f), all_events);

	// SECTION("non_evt_type_or")

	f = compile("evt.type=openat or proc.name=nginx");
	compare_evttypes(std::move(f), all_events);

	// SECTION("non_evt_type_or_nested_first")

	f = compile("(evt.type=openat) or proc.name=nginx");
	compare_evttypes(std::move(f), all_events);

	// SECTION("non_evt_type_or_nested_second")

	f = compile("evt.type=openat or (proc.name=nginx)");
	compare_evttypes(std::move(f), all_events);

	// SECTION("non_evt_type_or_nested_multi")

	f = compile("evt.type=openat or (evt.type=close and proc.name=nginx)");
	compare_evttypes(std::move(f), openat_close);

	// SECTION("non_evt_type_or_nested_multi_not")

	f = compile("evt.type=openat or not (evt.type=close and proc.name=nginx)");
	compare_evttypes(std::move(f), all_events);

	// SECTION("non_evt_type_and_nested_multi_not")

	f = compile("evt.type=openat and not (evt.type=close and proc.name=nginx)");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("ne_and_and")

	f = compile("evt.type!=openat and evt.type!=close");
	compare_evttypes(std::move(f), not_openat_close);

	// SECTION("not_not")

	f = compile("not (not evt.type=openat)");
	compare_evttypes(std::move(f), openat_only);

	// SECTION("not_ne_equivalence")

	compare_filters_evttypes("not evt.type=mmap", "evt.type!=mmap");
	compare_filters_evttypes("not proc.name=cat", "proc.name!=cat");

	// see: https://github.com/falcosecurity/libs/pull/854#issuecomment-1411151732
	// SECTION("libs #854")

	compare_filters_evttypes(
		"evt.type in (connect, execve, accept, mmap, container) and not (proc.name=cat and evt.type=mmap)",
		"evt.type in (accept, connect, container, execve, mmap)");
	compare_evttypes(compile("(evt.type=mmap and not evt.type=mmap)"), no_events);
}

TEST(filter_evttype_resolver, sanity_checks_evttype_resolver)
{
	// SECTION("boolean algebra")

	// "zero"-set: no evt type should matches the filter
	std::string zerof = "(evt.type in ())";
	// "one"-set: all evt types should match the filter
	std::string onef = "(evt.type exists)";
	// "neutral"-sets: evt types are not checked in the filter
	std::string neutral1 = "(proc.name=cat)";
	std::string neutral2 = "(not proc.name=cat)";

	// SECTION("sanity checks")

	compare_filters_evttypes(onef, neutral1);
	compare_filters_evttypes(onef, neutral2);

	// SECTION("1' = 0")

	compare_filters_evttypes("not " + onef, zerof);

	// SECTION("0' = 1")

	compare_filters_evttypes("not " + zerof, onef);

	// SECTION("(A')' = A")

	compare_filters_evttypes("evt.type=mmap", "not (not evt.type=mmap)");

	// SECTION("A * A' = 0")

	compare_evttypes(compile(zerof), no_events);

	// SECTION("A + A' = 1")

	compare_filters_evttypes("evt.type=mmap or not evt.type=mmap", onef);
	compare_filters_evttypes("evt.type=mmap or not evt.type=mmap", neutral1);
	compare_filters_evttypes("evt.type=mmap or not evt.type=mmap", neutral2);

	// SECTION("0 * 1 = 0")

	compare_filters_evttypes(zerof + " and " + onef, zerof);
	compare_filters_evttypes(zerof + " and " + neutral1, zerof);
	compare_filters_evttypes(zerof + " and " + neutral2, zerof);

	// SECTION("0 + 1 = 1")

	compare_filters_evttypes(zerof + " or " + onef, onef);
	compare_filters_evttypes(zerof + " or " + neutral1, onef);
	compare_filters_evttypes(zerof + " or " + neutral2, onef);

	// SECTION("A * 0 = 0")

	compare_filters_evttypes("evt.type=mmap and " + zerof, zerof);

	// SECTION("A * 1 = A")

	compare_filters_evttypes("evt.type=mmap and " + onef, "evt.type=mmap");
	compare_filters_evttypes("evt.type=mmap and " + neutral1, "evt.type=mmap");
	compare_filters_evttypes("evt.type=mmap and " + neutral2, "evt.type=mmap");

	// SECTION("A + 0 = A")

	compare_filters_evttypes("evt.type=mmap or " + zerof, "evt.type=mmap");

	// SECTION("A + 1 = 1")

	compare_filters_evttypes("evt.type=mmap or " + onef, onef);
	compare_filters_evttypes("evt.type=mmap or " + neutral1, onef);
	compare_filters_evttypes("evt.type=mmap or " + neutral2, onef);

	// SECTION("A + A = A")

	compare_filters_evttypes("evt.type=mmap or evt.type=mmap", "evt.type=mmap");

	// SECTION("A * A = A")

	compare_filters_evttypes("evt.type=mmap and evt.type=mmap", "evt.type=mmap");
}

TEST(filter_evttype_resolver, de_morgans_law_checks_evttype_resolver)
{
	compare_filters_evttypes(
		"not (proc.name=cat or evt.type=mmap)",
		"not proc.name=cat and not evt.type=mmap");
	compare_filters_evttypes(
		"not (proc.name=cat or fd.type=file)",
		"not proc.name=cat and not fd.type=file");
	compare_filters_evttypes(
		"not (evt.type=execve or evt.type=mmap)",
		"not evt.type=execve and not evt.type=mmap");
	compare_filters_evttypes(
		"not (evt.type=mmap or evt.type=mmap)",
		"not evt.type=mmap and not evt.type=mmap");
	compare_filters_evttypes(
		"not (proc.name=cat and evt.type=mmap)",
		"not proc.name=cat or not evt.type=mmap");
	compare_filters_evttypes(
		"not (proc.name=cat and fd.type=file)",
		"not proc.name=cat or not fd.type=file");
	compare_filters_evttypes(
		"not (evt.type=execve and evt.type=mmap)",
		"not evt.type=execve or not evt.type=mmap");
	compare_filters_evttypes(
		"not (evt.type=mmap and evt.type=mmap)",
		"not evt.type=mmap or not evt.type=mmap");
}
