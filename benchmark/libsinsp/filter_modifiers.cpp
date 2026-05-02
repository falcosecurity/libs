// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

// Benchmark: new modifier syntax vs equivalent chained-OR expression.
//
// New syntax:  proc.name startswith oneof (svc0, svc1, ..., svcN)
// Old syntax:  proc.name startswith svc0 or proc.name startswith svc1 or ...
//
// KEY DIFFERENCE
//   The modifier form extracts the field value exactly once and then loops
//   over the N RHS terms inside a single filter-check node.
//   The chained-OR form creates N independent filter-check nodes, each of
//   which calls extract() on the field, making extraction cost O(N).
//
// TWO MATCH SCENARIOS (tested for every operator × list-size combination)
//   no_match    — proc.name = "bash"; no term ever matches.
//                 Both variants must evaluate every term (worst case).
//                 The modifier wins because field extraction happens once;
//                 the chained form pays it N times.
//   first_match — proc.name = "svc-prefix-000"; the first term always hits.
//                 Both variants exit on the first comparison (early-exit).
//
// OPERATORS COVERED
//   ==         plain equality  (hash-set fast path kicks in for large N)
//   startswith prefix check
//   contains   substring search
//   regex      RE2 match  (most expensive per-term cost)
//
// LIST SIZES: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <libsinsp/filter_check_list.h>
#include <libscap/scap.h>
#include <libscap/strl.h>
#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

// ─── minimal sinsp fixture ────────────────────────────────────────────────────

// Wraps sinsp in test mode with one thread whose comm equals `comm_name`.
// A single PPME_GENERIC_E event is pushed through the inspector once so we
// hold a valid sinsp_evt* that can be repeatedly fed to filter->run().
struct SinspFilterFixture {
	sinsp inspector{true};
	scap_test_input_data test_data{};
	scap_threadinfo tinfo{};
	scap_test_fdinfo_data fdinfo_data{};
	sinsp_filter_check_list filterlist;
	scap_evt* raw_event = nullptr;
	sinsp_evt* evt = nullptr;

	explicit SinspFilterFixture(const char* comm_name) {
		tinfo.tid = 1;
		tinfo.pid = 1;
		tinfo.ptid = 0;
		tinfo.sid = 1;
		tinfo.vpgid = 1;
		tinfo.vtid = 1;
		tinfo.vpid = 1;
		tinfo.fdlimit = static_cast<uint64_t>(-1);
		tinfo.clone_ts = 1566230400000000000ULL;
		strlcpy(tinfo.comm, comm_name, sizeof(tinfo.comm));
		strlcpy(tinfo.exe, "/usr/bin/sh", sizeof(tinfo.exe));
		strlcpy(tinfo.exepath, "/usr/bin/sh", sizeof(tinfo.exepath));
		strlcpy(tinfo.cwd, "/", sizeof(tinfo.cwd));
		strlcpy(tinfo.root, "/", sizeof(tinfo.root));

		fdinfo_data = {nullptr, 0};
		test_data.threads = &tinfo;
		test_data.thread_count = 1;
		test_data.fdinfo_data = &fdinfo_data;

		// PPME_GENERIC_E: PT_SYSCALLID (uint16) + PT_UINT16.
		char error[SCAP_LASTERR_SIZE] = {};
		const uint16_t sid = 1, nid = 1;
		raw_event =
		        scap_create_event(error, 1566230400000000000ULL, 1, PPME_GENERIC_E, 2, sid, nid);

		// raw_event is a member so &raw_event is a stable scap_evt** for test_data.events.
		test_data.events = &raw_event;
		test_data.event_count = 1;

		inspector.open_test_input(&test_data, SINSP_MODE_TEST);

		sinsp_evt* e = nullptr;
		int32_t res;
		do {
			res = inspector.next(&e);
		} while(res == SCAP_FILTERED_EVENT);
		if(res == SCAP_SUCCESS) {
			evt = e;
		}

		// Verify proc.name is actually extractable and returns the expected value.
		// If this throws, the benchmark results would be meaningless.
		auto fac = std::make_shared<sinsp_filter_factory>(&inspector, filterlist);
		auto nc = std::make_shared<sinsp_filter_cache_factory>();
		sinsp_filter_compiler cc(fac, std::string("proc.name == ") + comm_name, nc);
		auto check_filter = cc.compile();
		if(!evt || !check_filter->run(evt)) {
			throw std::runtime_error(
			        std::string("SinspFilterFixture: proc.name != '") + comm_name +
			        "' — fixture not set up correctly (evt=" + (evt ? "non-null" : "null") + ")");
		}
	}

	~SinspFilterFixture() {
		if(raw_event) {
			free(raw_event);
		}
	}

	// with_cache=false (default): passes the no-op base sinsp_filter_cache_factory so
	// both new_extract_cache() and new_compare_cache() return nullptr.  Every run()
	// call does the full extraction + comparison work — correct for benchmarking.
	//
	// with_cache=true: passes no explicit factory so the compiler installs the default
	// exprstr_sinsp_filter_cache_factory, which caches results keyed by event number.
	// Because the benchmark reuses the same sinsp_evt*, every hot-loop call after the
	// first is a cache hit (~9 ns).  This variant measures cache-lookup overhead and
	// represents steady-state in a production pipeline where the same event is
	// evaluated many times (e.g., multiple rules over a shared field).
	std::unique_ptr<sinsp_filter> compile(const std::string& filter_str, bool with_cache = false) {
		auto factory = std::make_shared<sinsp_filter_factory>(&inspector, filterlist);
		if(with_cache) {
			sinsp_filter_compiler compiler(factory, filter_str);
			return compiler.compile();
		}
		auto no_cache = std::make_shared<sinsp_filter_cache_factory>();
		sinsp_filter_compiler compiler(factory, filter_str, no_cache);
		return compiler.compile();
	}
};

// ─── term / filter builders ───────────────────────────────────────────────────

// N string terms for plain operators: "svc-prefix-000", "svc-prefix-001", ...
static std::vector<std::string> make_terms(int n) {
	std::vector<std::string> terms;
	terms.reserve(n);
	char buf[32];
	for(int i = 0; i < n; ++i) {
		snprintf(buf, sizeof(buf), "svc-prefix-%03d", i);
		terms.emplace_back(buf);
	}
	return terms;
}

// N regex terms: anchored full-match patterns "^svc-prefix-000$", ...
// Anchoring prevents trivial early exits in RE2 and mimics real alert rules.
static std::vector<std::string> make_regex_terms(int n) {
	std::vector<std::string> terms;
	terms.reserve(n);
	char buf[40];
	for(int i = 0; i < n; ++i) {
		snprintf(buf, sizeof(buf), "^svc-prefix-%03d$", i);
		terms.emplace_back(buf);
	}
	return terms;
}

// "proc.name OP oneof (t0, t1, ...)"
static std::string modifier_filter(const std::string& op, const std::vector<std::string>& terms) {
	std::string s = "proc.name " + op + " oneof (";
	for(size_t i = 0; i < terms.size(); ++i) {
		if(i) {
			s += ", ";
		}
		s += terms[i];
	}
	return s + ")";
}

// "proc.name OP t0 or proc.name OP t1 or ..."
static std::string chained_filter(const std::string& op, const std::vector<std::string>& terms) {
	std::string s;
	for(size_t i = 0; i < terms.size(); ++i) {
		if(i) {
			s += " or ";
		}
		s += "proc.name " + op + " " + terms[i];
	}
	return s;
}

// ─── benchmark helpers ────────────────────────────────────────────────────────

// COMM_TOKEN  : C identifier used in the function name (no dashes)
// COMM_STR    : actual comm string passed to SinspFilterFixture
// OP_TOKEN    : C identifier for the operator
// OP_STR      : operator string used in filter expressions
// TERM_FN     : function that produces the RHS term vector
// CACHE       : boolean — true = exprstr cache on, false = no cache

#define DEFINE_BENCH_PAIR_VARIANT(COMM_TOKEN, COMM_STR, OP_TOKEN, OP_STR, TERM_FN, CACHE, SUFFIX) \
	static void BM_##OP_TOKEN##_modifier_##COMM_TOKEN##_##SUFFIX(benchmark::State& state) {       \
		const auto terms = TERM_FN(static_cast<int>(state.range(0)));                             \
		SinspFilterFixture fixture(COMM_STR);                                                     \
		auto filter = fixture.compile(modifier_filter(OP_STR, terms), CACHE);                     \
		for(auto _ : state) {                                                                     \
			benchmark::DoNotOptimize(filter->run(fixture.evt));                                   \
		}                                                                                         \
	}                                                                                             \
	BENCHMARK(BM_##OP_TOKEN##_modifier_##COMM_TOKEN##_##SUFFIX)                                   \
	        ->RangeMultiplier(2)                                                                  \
	        ->Range(1, 512);                                                                      \
	static void BM_##OP_TOKEN##_chained_##COMM_TOKEN##_##SUFFIX(benchmark::State& state) {        \
		const auto terms = TERM_FN(static_cast<int>(state.range(0)));                             \
		SinspFilterFixture fixture(COMM_STR);                                                     \
		auto filter = fixture.compile(chained_filter(OP_STR, terms), CACHE);                      \
		for(auto _ : state) {                                                                     \
			benchmark::DoNotOptimize(filter->run(fixture.evt));                                   \
		}                                                                                         \
	}                                                                                             \
	BENCHMARK(BM_##OP_TOKEN##_chained_##COMM_TOKEN##_##SUFFIX)->RangeMultiplier(2)->Range(1, 512)

// Both cache variants for a given benchmark group.
#define DEFINE_BENCH_PAIR(COMM_TOKEN, COMM_STR, OP_TOKEN, OP_STR, TERM_FN)                      \
	DEFINE_BENCH_PAIR_VARIANT(COMM_TOKEN, COMM_STR, OP_TOKEN, OP_STR, TERM_FN, false, nocache); \
	DEFINE_BENCH_PAIR_VARIANT(COMM_TOKEN, COMM_STR, OP_TOKEN, OP_STR, TERM_FN, true, cached)

// ─── no-match scenario ────────────────────────────────────────────────────────
// proc.name = "bash" never matches any "svc-prefix-*" term.
// Both variants evaluate every term → worst-case O(N) comparisons.
// The modifier pays field-extraction once; chained pays it N times.

DEFINE_BENCH_PAIR(no_match, "bash", startswith, "startswith", make_terms);

DEFINE_BENCH_PAIR(no_match, "bash", contains, "contains", make_terms);

DEFINE_BENCH_PAIR(no_match, "bash", eq, "==", make_terms);

DEFINE_BENCH_PAIR(no_match, "bash", regex, "regex", make_regex_terms);

// ─── first-match scenario ─────────────────────────────────────────────────────
// proc.name = "svc-prefix-000" matches the very first term.
// Both variants short-circuit after one comparison.
// This isolates compilation overhead: modifier builds 1 node, chained builds N.

DEFINE_BENCH_PAIR(first_match, "svc-prefix-000", startswith, "startswith", make_terms);

DEFINE_BENCH_PAIR(first_match, "svc-prefix-000", contains, "contains", make_terms);

DEFINE_BENCH_PAIR(first_match, "svc-prefix-000", eq, "==", make_terms);

DEFINE_BENCH_PAIR(first_match, "svc-prefix-000", regex, "regex", make_regex_terms);
