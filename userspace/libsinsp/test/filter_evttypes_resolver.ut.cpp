#include <sinsp.h>
#include <filter.h>
#include <gtest/gtest.h>
#include <list>
#include "filter_evttype_resolver.h"

using namespace std;


void compare_evttypes(std::unique_ptr<libsinsp::filter::ast::expr> f, set<uint16_t> &expected)
{
    set<uint16_t> actual;
    filter_evttype_resolver().evttypes(f.get(), actual);

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

set<uint16_t> openat_only{
	PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X };

set<uint16_t> close_only{
	PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X };

set<uint16_t> openat_close{
	PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
	PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X };

set<uint16_t> open_openat{
	PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
	PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
	PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X };

set<uint16_t> empty{};
set<uint16_t> not_openat;
set<uint16_t> not_openat_close;
set<uint16_t> not_close;
set<uint16_t> all_events;
set<uint16_t> no_events;


TEST(filter_evttype_resolver, simple_evttypes_evaluation)
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

	std::unique_ptr<libsinsp::filter::ast::expr> f;

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
	compare_evttypes(std::move(f), not_close);


	// SECTION("non_evt_type_and_nested_multi_not")

	f = compile("evt.type=openat and not (evt.type=close and proc.name=nginx)");
	compare_evttypes(std::move(f), openat_only);


	// SECTION("ne_and_and")

	f = compile("evt.type!=openat and evt.type!=close");
	compare_evttypes(std::move(f), not_openat_close);


	// SECTION("not_not")

	f = compile("not (not evt.type=openat)");
	compare_evttypes(std::move(f), openat_only);


	// SECTION("evt_type_not_nested_sub_event_type_unrealistic_1")

	f = compile("evt.type in (open, openat) and proc.name=cat and not (evt.type=openat and proc.cmdline contains not-exist and evt.type=unshare)");
	compare_evttypes(std::move(f), open_openat);


	// SECTION("evt_type_not_nested_sub_event_type_unrealistic_2")

	f = compile("evt.type in (open, openat) and not evt.type in (open, openat)");
	compare_evttypes(std::move(f), empty);


	// SECTION("evt_type_not_nested_sub_event_type_tricky")

	// TODO fix as this condition breaks evttype_resolver
	// f = compile("evt.type in (open, openat) and proc.name=cat and not (evt.type=openat and proc.cmdline contains not-exist)");
	// compare_evttypes(std::move(f), open_openat);

}
