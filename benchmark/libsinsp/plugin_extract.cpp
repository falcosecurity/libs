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

// What a plugin's field costs per event, against the same value fetched without one.
//
// Nothing else measures this. The state-table benchmarks price the table code from inside
// the library, with no plugin and no ABI in the way, so the two costs a plugin author
// actually pays -- the marshalling the framework does before the plugin sees an event, and
// the table traffic the plugin does once it has one -- were invisible.
//
// THE ARMS, all over one stream of 131072 open events across 512 pre-created processes
//   floor         no filter, nothing fetched: what every consumer pays to parse the event.
//   raw pid       no filter either; the drain loop reads the value straight off the event's
//   raw name      thread (evt->get_tinfo()), which is the cheapest way to get it and the
//                 lower bound for everything below.
//   proc.pid      the library's own filterchecks, as the reference and the overhead floor
//   proc.name     of the filter path -- not the system under test.
//   pluginv3.pid  the same two values out of a v3 plugin, whose filtercheck the inspector's
//   pluginv3.name check list carries: the v3 table ABI spends three calls per read
//                 (get_table_entry hands out a borrowed entry, read_entry_field reads one
//                 field, release_table_entry gives it back).
//
// ⚠️ EVERY FILTER IS WRITTEN TO BE TRUE FOR EVERY EVENT
//   `field != <a value nothing has>`: the field is extracted and compared, exactly as a rule
//   would, and then every event is returned -- so each arm does the same work per event as
//   the empty-filter baseline plus one extraction and one comparison, and nothing else. Two
//   shapes were considered and rejected: `field exists` never compares at all (it returns
//   true the moment extraction succeeds, sinsp_filter_check::compare_rhs), which would hide
//   that a plugin's result arrives as a list of values and takes the list-shaped comparison
//   path; and an equality that matches one process would filter 511 of 512 events out, which
//   makes the arms and the baseline stop doing comparable work.
//
// ⚠️ THE VALIDITY GATE
//   Three counters, because an arm that quietly fetches nothing would otherwise report the
//   baseline as a spectacular win. passed_filter must be the whole stream (a field that does
//   not resolve, an event type the plugin does not claim, or a lookup that misses makes the
//   filter false and drops events); a plugin arm's extract_calls must equal the whole stream,
//   which the plugin counts itself; and a raw arm's fetches must too.
//
// HOW TO COMPARE TWO BUILDS
//   build/release/benchmark/bench --benchmark_filter='BM_plugin'
//       --benchmark_min_time=2s --benchmark_repetitions=5
//       --benchmark_report_aggregates_only=true
// events/s is the figure to compare; ns/event is the same number inverted. For a delta
// smaller than the wall-clock spread, take instructions:u at two iteration counts and use the
// slope -- the stream is deterministic, so insn/ev reproduces bit for bit.

#include <benchmark/benchmark.h>

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <libsinsp/filter_check_list.h>
#include <libsinsp/plugin.h>
#include <libscap/engine/test_input/test_input_public.h>

// For the v3 API shapes only -- no sample plugin is registered here. This header is the one
// place in the tree that keeps naming them correctly, so including it costs a line and saves
// a fixup every time the plugin headers move.
#include <libsinsp/test/plugins/test_plugins.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------------------
// The stream
// ---------------------------------------------------------------------------------------

// One event type over processes that already exist: the measured work is a table lookup and
// a field fetch per event, not first-sight thread creation. Every process reopens the same fd
// number, so its fd table stays one entry deep and no arm can drift into measuring fd-table
// growth.
class open_stream {
public:
	static const open_stream &get() {
		static const open_stream s;
		return s;
	}

	size_t size() const { return m_index.size(); }

	scap_test_input_data input() const {
		scap_test_input_data d = {};
		d.events = const_cast<ppm_evt_hdr **>(m_index.data());
		d.event_count = m_index.size();
		d.threads = const_cast<scap_threadinfo *>(m_threads.data());
		d.thread_count = m_threads.size();
		// One empty entry per thread. NOT optional: the test-input platform's get_fdinfos
		// indexes this array for every scanned thread without checking it, so a null here with
		// threads present is a null dereference at open.
		d.fdinfo_data = const_cast<scap_test_fdinfo_data *>(m_fdinfo_data.data());
		return d;
	}

private:
	static constexpr size_t kProcs = 512;
	static constexpr size_t kEventsPerProc = 256;
	// Pids start well above the values the filters compare against, and every comm is
	// "bench<n>", so every filter below is true for every event.
	static constexpr int64_t kFirstTid = 1000;

	// Two passes because that is the encoder's contract: the first reports the size it needs,
	// the second fills a buffer of that size.
	template<typename... Args>
	void emit(const uint64_t ts, const uint64_t tid, const ppm_event_code type, Args... args) {
		scap_sized_buffer probe = {nullptr, 0};
		size_t needed = 0;
		char err[SCAP_LASTERR_SIZE] = {};
		const uint32_t n = sizeof...(Args);
		if(scap_event_encode_params(probe, &needed, err, type, n, args...) !=
		   SCAP_INPUT_TOO_SMALL) {
			throw std::runtime_error(std::string("cannot size event: ") + err);
		}
		std::vector<uint8_t> buf(needed);
		scap_sized_buffer out = {buf.data(), buf.size()};
		if(scap_event_encode_params(out, &needed, err, type, n, args...) != SCAP_SUCCESS) {
			throw std::runtime_error(std::string("cannot encode event: ") + err);
		}
		auto *e = reinterpret_cast<scap_evt *>(buf.data());
		e->ts = ts;
		e->tid = tid;
		m_owned.push_back(std::move(buf));
		m_index.push_back(reinterpret_cast<ppm_evt_hdr *>(m_owned.back().data()));
	}

	open_stream() {
		m_threads.resize(kProcs);
		for(size_t i = 0; i < kProcs; i++) {
			scap_threadinfo &t = m_threads[i];
			t = {};
			const int64_t tid = kFirstTid + static_cast<int64_t>(i);
			// One thread per process, so a tid is a process.
			t.tid = static_cast<uint64_t>(tid);
			t.pid = static_cast<uint64_t>(tid);
			t.ptid = 1;
			t.fdlimit = 1024;
			snprintf(t.comm, sizeof(t.comm), "bench%zu", i);
			snprintf(t.exe, sizeof(t.exe), "/usr/bin/bench%zu", i);
			snprintf(t.exepath, sizeof(t.exepath), "/usr/bin/bench%zu", i);
			snprintf(t.cwd, sizeof(t.cwd), "/");
		}

		m_fdinfo_data.resize(kProcs);
		for(auto &f : m_fdinfo_data) {
			f = {};
		}

		const size_t total = kProcs * kEventsPerProc;
		m_owned.reserve(total);
		m_index.reserve(total);
		uint64_t ts = 1;
		const int64_t fd = 7;
		for(size_t round = 0; round < kEventsPerProc; round++) {
			for(size_t i = 0; i < kProcs; i++) {
				// Round-robin across processes rather than one process at a time, so no arm gets
				// a lookup pattern that a one-entry cache would flatter.
				emit(ts++,
				     static_cast<uint64_t>(kFirstTid + static_cast<int64_t>(i)),
				     PPME_SYSCALL_OPEN_X,
				     fd,
				     "/tmp/bench",
				     static_cast<uint32_t>(0),
				     static_cast<uint32_t>(0),
				     static_cast<uint32_t>(0),
				     static_cast<uint64_t>(0));
			}
		}
	}

	std::vector<scap_threadinfo> m_threads;
	std::vector<scap_test_fdinfo_data> m_fdinfo_data;
	std::vector<std::vector<uint8_t>> m_owned;
	std::vector<ppm_evt_hdr *> m_index;
};

// The one event type the plugins below claim, and the only type the stream carries.
const uint16_t kExtractedType = PPME_SYSCALL_OPEN_X;

// ---------------------------------------------------------------------------------------
// The v3 plugin
// ---------------------------------------------------------------------------------------

// Written here rather than reusing a sample plugin from the test tree, because the point is
// to price the ABI: it exposes the same fields the library's own filterchecks do, and does the
// least work each ABI allows, so a difference between them is the ABI's and not one plugin's
// idea of how to keep its state.

enum v3_field : uint32_t {
	kV3Name = 0,
	kV3Pid = 1,
	// Touches no table at all: what the framework spends to ask a v3 plugin for a value and
	// compare what comes back, with the table work subtracted out.
	kV3Const = 2,
	// The address comparison shapes: a plugin field can be an ipaddr or an ipnet, which is the only
	// way to price those here -- this stream carries no socket events, so fd.ip is never
	// resolvable. Appended, because a field id is its position in get_fields().
	kV3Ip = 3,
	kV3Net = 4,
};

struct v3_state {
	ss_plugin_table_t *threads = nullptr;
	ss_plugin_table_field_t *f_comm = nullptr;
	ss_plugin_table_field_t *f_pid = nullptr;
	uint64_t calls = 0;
	// Result storage the framework may read after extract_fields returns. A comm is short
	// enough to live in the string's own buffer, so the happy path allocates nothing.
	std::string str;
	const char *strptr = nullptr;
	uint64_t u64 = 0;
	// 10.1.2.3, in network order, which is how a filter's own address value is stored.
	uint8_t ip[4] = {10, 1, 2, 3};
	ss_plugin_byte_buffer buf = {};
	std::string lasterr;
};

// Only one inspector at a time exists here, but an arm needs the plugin's call count after
// the plugin has been destroyed with its inspector, so the live state is published.
v3_state *g_v3 = nullptr;

const char *v3_get_required_api_version() {
	// The macro was renamed when the v4 header arrived; both spellings mean "the v3 API
	// version this tree implements", and a benchmark that has to build at every commit of a
	// series cannot pick one.
#ifdef PLUGIN_API_VERSION_V3_STR
	return PLUGIN_API_VERSION_V3_STR;
#else
	return PLUGIN_API_VERSION_STR;
#endif
}
const char *v3_get_version() {
	return "0.1.0";
}
const char *v3_get_name() {
	return "bench_plugin_v3";
}
const char *v3_get_description() {
	return "the v3 arms of the plugin field benchmark";
}
const char *v3_get_contact() {
	return "github.com/falcosecurity/libs";
}
const char *v3_get_fields() {
	return R"([
		{"type":"string","name":"pluginv3.name","desc":"the event thread's comm, over the v3 table ABI"},
		{"type":"uint64","name":"pluginv3.pid","desc":"the event thread's pid, over the v3 table ABI"},
		{"type":"uint64","name":"pluginv3.const","desc":"a constant: the call path with no table work in it"},
		{"type":"ipaddr","name":"pluginv3.ip","desc":"a fixed IPv4 address, compared as an address"},
		{"type":"ipnet","name":"pluginv3.net","desc":"the same address, compared against a network"}
	])";
}
const char *v3_get_extract_event_sources() {
	return R"(["syscall"])";
}
uint16_t *v3_get_extract_event_types(uint32_t *num_types, ss_plugin_t *) {
	static uint16_t types[] = {kExtractedType};
	*num_types = sizeof(types) / sizeof(types[0]);
	return &types[0];
}
const char *v3_get_last_error(ss_plugin_t *s) {
	return reinterpret_cast<v3_state *>(s)->lasterr.c_str();
}

// Everything is looked up at init and checked, so an arm cannot silently measure a plugin
// that gave up on its field.
ss_plugin_t *v3_init(const ss_plugin_init_input *in, ss_plugin_rc *rc) {
	auto *st = new v3_state();
	*rc = SS_PLUGIN_FAILURE;
	if(in == nullptr || in->tables == nullptr) {
		st->lasterr = "no table service: extraction capability not seen";
		return st;
	}
	st->threads =
	        in->tables->get_table(in->owner, "threads", ss_plugin_state_type::SS_PLUGIN_ST_INT64);
	if(st->threads == nullptr) {
		st->lasterr = "cannot access the thread table";
		return st;
	}
	st->f_comm = in->tables->fields.get_table_field(st->threads,
	                                                "comm",
	                                                ss_plugin_state_type::SS_PLUGIN_ST_STRING);
	st->f_pid = in->tables->fields.get_table_field(st->threads,
	                                               "pid",
	                                               ss_plugin_state_type::SS_PLUGIN_ST_INT64);
	if(st->f_comm == nullptr || st->f_pid == nullptr) {
		st->lasterr = "cannot access comm or pid in the thread table";
		return st;
	}
	*rc = SS_PLUGIN_SUCCESS;
	g_v3 = st;
	return reinterpret_cast<ss_plugin_t *>(st);
}

void v3_destroy(ss_plugin_t *s) {
	auto *st = reinterpret_cast<v3_state *>(s);
	if(st == g_v3) {
		g_v3 = nullptr;
	}
	delete st;
}

ss_plugin_rc v3_extract_fields(ss_plugin_t *s,
                               const ss_plugin_event_input *ev,
                               const ss_plugin_field_extract_input *in) {
	auto *st = reinterpret_cast<v3_state *>(s);
	for(uint32_t i = 0; i < in->num_fields; i++) {
		auto &f = in->fields[i];
		st->calls++;
		if(f.field_id == kV3Ip || f.field_id == kV3Net) {
			// An address is a fixed four bytes: no table work, so what an arm on it shows over
			// the constant arm is the comparison shape and nothing else.
			st->buf.ptr = st->ip;
			st->buf.len = sizeof(st->ip);
			f.res.buf = &st->buf;
			f.res_len = 1;
			continue;
		}
		if(f.field_id == kV3Const) {
			// Returns before touching a table: everything left is the framework's.
			st->u64 = 42;
			f.res.u64 = &st->u64;
			f.res_len = 1;
			continue;
		}
		// The thread table is keyed by tid and an event names its own thread: this lookup is
		// what every table-using plugin does, once per event.
		ss_plugin_state_data key;
		key.s64 = ev->evt->tid;
		auto *entry = in->table_reader.get_table_entry(st->threads, &key);
		if(entry == nullptr) {
			st->lasterr = "no thread entry for the event's tid";
			return SS_PLUGIN_FAILURE;
		}
		ss_plugin_state_data got;
		auto *field = (f.field_id == kV3Name) ? st->f_comm : st->f_pid;
		const auto rc = in->table_reader.read_entry_field(st->threads, entry, field, &got);
		if(rc != SS_PLUGIN_SUCCESS) {
			st->lasterr = "cannot read the field out of the thread entry";
			in->table_reader_ext->release_table_entry(st->threads, entry);
			return rc;
		}
		switch(f.field_id) {
		case kV3Name:
			st->str.assign(got.str != nullptr ? got.str : "");
			st->strptr = st->str.c_str();
			f.res.str = &st->strptr;
			break;
		case kV3Pid:
			st->u64 = static_cast<uint64_t>(got.s64);
			f.res.u64 = &st->u64;
			break;
		default:
			in->table_reader_ext->release_table_entry(st->threads, entry);
			st->lasterr = "unknown field id";
			return SS_PLUGIN_FAILURE;
		}
		f.res_len = 1;
		in->table_reader_ext->release_table_entry(st->threads, entry);
	}
	return SS_PLUGIN_SUCCESS;
}

plugin_api v3_api() {
	plugin_api api = {};
	api.get_required_api_version = &v3_get_required_api_version;
	api.get_version = &v3_get_version;
	api.get_name = &v3_get_name;
	api.get_description = &v3_get_description;
	api.get_contact = &v3_get_contact;
	api.get_last_error = &v3_get_last_error;
	api.init = &v3_init;
	api.destroy = &v3_destroy;
	api.get_fields = &v3_get_fields;
	api.get_extract_event_sources = &v3_get_extract_event_sources;
	api.get_extract_event_types = &v3_get_extract_event_types;
	api.extract_fields = &v3_extract_fields;
	return api;
}

// ---------------------------------------------------------------------------------------
// The arms
// ---------------------------------------------------------------------------------------

enum class arm {
	floor,
	raw_pid,
	raw_name,
	evtnum,
	proc_pid,
	proc_name,
	proc_uid,
	proc_bool,
	proc_fspath,
	rawarg_int,
	proc_glob,
	proc_icontains,
	proc_in,
	proc_pid_x2,
	proc_pid_x4,
	proc_pid_x8,
	proc_pid_ors_x8,
	proc_pid_deep_x6,
	proc_pid_nots_x4,
	proc_pid_group_x4,
	proc_mixed_x4,
	v3_pid,
	v3_name,
	v3_const,
	v3_ip,
	v3_net,
};

// Every one of these is true for every event of the stream: no pid is 1 and no comm is
// "nosuchproc". The field is extracted and compared, and then the event is returned, so an
// arm differs from the empty-filter baseline by one extraction and one comparison.
const char *filter_of(const arm a) {
	switch(a) {
	// The cheapest built-in field there is: evt.num is a counter the event already carries, so
	// this arm is very nearly the filter machinery on its own.
	case arm::evtnum:
		return "evt.num != 0";
	case arm::proc_pid:
		return "proc.pid != 1";
	case arm::proc_name:
		return "proc.name != nosuchproc";
	// A boolean field, which flt_compare compares as a widened word.
	case arm::proc_bool:
		return "proc.is_exe_writable = false";
	// A path-typed syscall parameter: open's name is PT_FSPATH, not a plain string.
	case arm::proc_fspath:
		return "evt.rawarg.name != /nosuchpath";
	// An integer syscall parameter: open's ino is a uint64, and the raw-argument check compares it
	// through its own path rather than the one every other field takes.
	case arm::rawarg_int:
		return "evt.rawarg.ino != 999999";
	// Two operators no resolved shape covers, so these measure what an uncovered comparison pays
	// for the shape machinery being there at all.
	case arm::proc_glob:
		return "proc.name glob \"bench*\"";
	case arm::proc_icontains:
		return "proc.name icontains ench";
	// The operator a real rule opens with: `evt.type in (...)` is in nearly every one. A set
	// membership test resolves to no comparison shape at all, so this arm is where anything that
	// speeds up resolved comparisons has to be shown not to cost.
	case arm::proc_in:
		return "not proc.name in (nosuchproc, alsonosuchproc)";
	// A narrow integer field (uid is uint32), where a 64-bit-only fast comparison does not apply.
	case arm::proc_uid:
		return "user.uid != 4294967295";
	// The same field twice, then four times: what a rule pays for a repeated reference, which is
	// the case the shared extraction cache exists for -- the second reference reads the cache
	// rather than the field.
	case arm::proc_pid_x2:
		return "proc.pid != 1 and proc.pid != 2";
	case arm::proc_pid_x4:
		return "proc.pid != 1 and proc.pid != 2 and proc.pid != 3 and proc.pid != 4";
	case arm::proc_pid_x8:
		return "proc.pid != 1 and proc.pid != 2 and proc.pid != 3 and proc.pid != 4 and "
		       "proc.pid != 5 and proc.pid != 6 and proc.pid != 7 and proc.pid != 8";
	// The same eight comparisons, but as four bracketed alternatives under one and: the shape a
	// rule takes once it names more than one way of being interesting. The compiler flattens
	// same-operator nesting, so it is the alternation that makes the tree a tree -- four nested
	// expressions here against none in the arm above. Every leading disjunct is false (no process
	// in the stream has a pid below 500), so nothing short-circuits and every leaf is compared,
	// which is also how an or group in a real rule usually goes.
	case arm::proc_pid_ors_x8:
		return "(proc.pid < 500 or proc.pid != 1) and (proc.pid < 600 or proc.pid != 2) and "
		       "(proc.pid < 700 or proc.pid != 3) and (proc.pid < 800 or proc.pid != 4)";
	// Six comparisons at six levels of nesting, alternating and/or all the way down: what a rule
	// assembled out of macros looks like by the time each one has brought its own brackets. Every
	// level is walked -- the or levels because their first disjunct is false, the and levels
	// because their first conjunct is true.
	case arm::proc_pid_deep_x6:
		return "proc.pid != 1 and (proc.pid < 500 or (proc.pid != 2 and (proc.pid < 600 or "
		       "(proc.pid != 3 and proc.pid != 4))))";
	// Four comparisons again, three of them negated: "and not" is how a rule says which of the
	// things it just matched it does not mean, and it is everywhere in a real ruleset. Against
	// the four-times arm above, which has the same four leaves and no negation, this is what a
	// not costs -- the operator itself is free, so anything it costs is the tree.
	case arm::proc_pid_nots_x4:
		return "proc.pid != 1 and not proc.pid = 2 and not proc.pid = 3 and not proc.pid = 4";
	// The same four conditions as the four-times arm, with the first two bracketed: the shape a
	// rule takes when it opens with a macro, since a macro arrives as a group of its own. The
	// bracket says nothing that the and around it does not, so this arm and that one should cost
	// the same -- what the difference measures is what the bracket is charged for.
	case arm::proc_pid_group_x4:
		return "(proc.pid != 1 and proc.pid != 2) and proc.pid != 3 and proc.pid != 4";
	// Four DIFFERENT fields, so nothing can be reused: what a rule pays per distinct condition.
	case arm::proc_mixed_x4:
		return "proc.pid != 1 and proc.name != nosuchproc and thread.tid != 1 and fd.num != 999999";
	case arm::v3_pid:
		return "pluginv3.pid != 1";
	case arm::v3_name:
		return "pluginv3.name != nosuchproc";
	case arm::v3_const:
		return "pluginv3.const != 1";
	// An address compared with an address, and the same address compared against a network:
	// 10.1.2.3 is neither of these, so both hold for every event.
	case arm::v3_ip:
		return "pluginv3.ip != 1.2.3.4";
	case arm::v3_net:
		return "pluginv3.net != 192.168.0.0/16";
	case arm::floor:
	case arm::raw_pid:
	case arm::raw_name:
		break;
	}
	return nullptr;
}

bool wants_v3(const arm a) {
	return a == arm::v3_pid || a == arm::v3_name || a == arm::v3_const || a == arm::v3_ip ||
	       a == arm::v3_net;
}

bool is_raw(const arm a) {
	return a == arm::raw_pid || a == arm::raw_name;
}

// BENCH_SETUP_ONLY=1 runs every arm's setup and consumes no events, so the two-point slope
// prices the setup an arm pays per pass instead of its per-event work. Read once: it decides what
// a whole run measures, and the arm gates have to stand down for it.
bool setup_only() {
	// Set but empty means off, so BENCH_SETUP_ONLY= in a script does not silently turn a whole
	// sweep into a setup measurement -- and neither does =0.
	static const bool v = [] {
		const char *e = getenv("BENCH_SETUP_ONLY");
		return e != nullptr && e[0] != '\0' && strcmp(e, "0") != 0;
	}();
	return v;
}

struct replay_result {
	size_t passed = 0;    // events the filter returned to the caller
	size_t consumed = 0;  // next() calls, so a short pass cannot masquerade as a fast one
	size_t fetched = 0;   // values a raw arm read off the event's thread
	uint64_t calls = 0;   // extractions the plugin counted itself
};

replay_result replay(const open_stream &stream, const arm a) {
	scap_test_input_data data = stream.input();
	sinsp inspector;

	// Registered and initialized before the capture opens, as a consumer would.
	//
	// This setup is INSIDE the timed region, and cannot be hoisted out of it: close() tears the
	// plugin down, so one inspector cannot serve a second capture, and hoisting it for the
	// plugin-less arms alone would put the plugin arms' setup into their figure over the floor.
	// So every arm's number carries its own setup, divided by the events of one pass. That is
	// what the floor arm is for: it pays the same inspector construction, capture open and close,
	// so a figure over the floor is free of them. What it does NOT cancel is the part specific to
	// an arm -- compiling a longer filter, registering a plugin. Set BENCH_SETUP_ONLY=1 to price
	// exactly that: the same setup, zero events consumed.
	std::shared_ptr<sinsp_plugin> pl;
	plugin_api v3 = {};
	std::string err;
	if(wants_v3(a)) {
		v3 = v3_api();
		pl = inspector.register_plugin(&v3);
		if(pl == nullptr || !pl->init("", err)) {
			throw std::runtime_error("v3 bench plugin init failed: " + err);
		}
	}

	// Registering a plugin and registering its filterchecks are separate steps: the check list
	// the filter compiles against is the consumer's, so a plugin field is only visible to a
	// filter once the plugin's own check is added to it. The list carries the built-in checks
	// too, so every arm is compiled and evaluated by the same machinery and differs only in
	// which field it names. It must outlive the filter, so it lives here.
	sinsp_filter_check_list flist;
	if(pl != nullptr) {
		flist.add_filter_check(inspector.new_generic_filtercheck());
		flist.add_filter_check(sinsp_plugin::new_filtercheck(pl));
	}
	if(const char *fltstr = filter_of(a); fltstr != nullptr) {
		auto factory = std::make_shared<sinsp_filter_factory>(&inspector, flist);
		inspector.set_filter(sinsp_filter_compiler(factory, fltstr).compile(), fltstr);
	}

	inspector.open_test_input(&data);

	// The test_input engine signals "no more events" with SCAP_TIMEOUT, not EOF, so the loop
	// needs a hard call cap: treating TIMEOUT as "try again" here is an infinite loop.
	const size_t cap = setup_only() ? 0 : stream.size() * 2 + 1024;
	replay_result r;
	sinsp_evt *evt = nullptr;
	for(; r.consumed < cap; r.consumed++) {
		int32_t rc;
		try {
			rc = inspector.next(&evt);
		} catch(...) {
			break;
		}
		if(rc == SCAP_TIMEOUT) {
			break;
		}
		if(rc == SCAP_FILTERED_EVENT) {
			continue;
		}
		if(rc != SCAP_SUCCESS) {
			break;
		}
		benchmark::DoNotOptimize(evt);
		// The unstructured lower bound: the value straight off the event's own thread, with
		// nothing between the loop and the field. get_tinfo() is the plain accessor -- unlike
		// get_thread_info(true) it never falls back to a lookup.
		if(is_raw(a)) {
			auto *ti = evt->get_tinfo();
			if(ti != nullptr) {
				if(a == arm::raw_pid) {
					int64_t pid = ti->m_pid;
					benchmark::DoNotOptimize(pid);
				} else {
					std::string comm = ti->get_comm();
					benchmark::DoNotOptimize(comm);
				}
				r.fetched++;
			}
		}
		r.passed++;
	}
	if(g_v3 != nullptr) {
		r.calls = g_v3->calls;
	}
	inspector.close();
	return r;
}

void run_arm(benchmark::State &state, const arm a) {
	const auto &stream = open_stream::get();
	replay_result r;
	for(auto _ : state) {
		r = replay(stream, a);
	}

	state.counters["events/s"] =
	        benchmark::Counter(static_cast<double>(state.iterations() * stream.size()),
	                           benchmark::Counter::kIsRate);
	state.counters["ns/event"] =
	        benchmark::Counter(static_cast<double>(state.iterations() * stream.size()),
	                           benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
	state.counters["in_dump"] = static_cast<double>(stream.size());
	state.counters["passed_filter"] = static_cast<double>(r.passed);
	state.counters["consumed"] = static_cast<double>(r.consumed);
	if(r.calls > 0) {
		state.counters["extract_calls_per_ev"] =
		        static_cast<double>(r.calls) / static_cast<double>(stream.size());
	}

	// The gate. Every filter here is true for every event -- except the no-value arm, whose
	// whole point is that the comparison cannot succeed -- so a filter that dropped an event
	// means the field did not resolve, or the plugin was not asked, or a lookup missed. An arm
	// that fetched nothing would otherwise report the baseline as a spectacular win.
	if(setup_only()) {
		return;  // no events by design: the gates below all count them
	}
	if(r.passed != stream.size()) {
		state.SkipWithError(
		        "the filter did not return every event: the field did not resolve, "
		        "or was not extracted as intended");
	}
	if(wants_v3(a) && r.calls != stream.size()) {
		state.SkipWithError("the plugin was not asked to extract once per event");
	}
	if(is_raw(a) && r.fetched != stream.size()) {
		state.SkipWithError("the loop did not read the value for every event");
	}
}

void BM_plugin_field_floor(benchmark::State &state) {
	run_arm(state, arm::floor);
}
void BM_plugin_field_raw_pid(benchmark::State &state) {
	run_arm(state, arm::raw_pid);
}
void BM_plugin_field_raw_name(benchmark::State &state) {
	run_arm(state, arm::raw_name);
}
void BM_plugin_field_evtnum(benchmark::State &state) {
	run_arm(state, arm::evtnum);
}
void BM_plugin_field_proc_pid(benchmark::State &state) {
	run_arm(state, arm::proc_pid);
}
void BM_plugin_field_proc_name(benchmark::State &state) {
	run_arm(state, arm::proc_name);
}
void BM_plugin_field_proc_bool(benchmark::State &state) {
	run_arm(state, arm::proc_bool);
}
void BM_plugin_field_proc_fspath(benchmark::State &state) {
	run_arm(state, arm::proc_fspath);
}
void BM_plugin_field_rawarg_int(benchmark::State &state) {
	run_arm(state, arm::rawarg_int);
}
void BM_plugin_field_proc_glob(benchmark::State &state) {
	run_arm(state, arm::proc_glob);
}
void BM_plugin_field_proc_icontains(benchmark::State &state) {
	run_arm(state, arm::proc_icontains);
}
void BM_plugin_field_proc_in(benchmark::State &state) {
	run_arm(state, arm::proc_in);
}
void BM_plugin_field_proc_uid(benchmark::State &state) {
	run_arm(state, arm::proc_uid);
}
void BM_plugin_field_proc_pid_x2(benchmark::State &state) {
	run_arm(state, arm::proc_pid_x2);
}
void BM_plugin_field_proc_pid_x4(benchmark::State &state) {
	run_arm(state, arm::proc_pid_x4);
}
void BM_plugin_field_proc_pid_x8(benchmark::State &state) {
	run_arm(state, arm::proc_pid_x8);
}
void BM_plugin_field_proc_pid_ors_x8(benchmark::State &state) {
	run_arm(state, arm::proc_pid_ors_x8);
}
void BM_plugin_field_proc_pid_deep_x6(benchmark::State &state) {
	run_arm(state, arm::proc_pid_deep_x6);
}
void BM_plugin_field_proc_pid_nots_x4(benchmark::State &state) {
	run_arm(state, arm::proc_pid_nots_x4);
}
void BM_plugin_field_proc_pid_group_x4(benchmark::State &state) {
	run_arm(state, arm::proc_pid_group_x4);
}
void BM_plugin_field_proc_mixed_x4(benchmark::State &state) {
	run_arm(state, arm::proc_mixed_x4);
}
void BM_plugin_field_v3_pid(benchmark::State &state) {
	run_arm(state, arm::v3_pid);
}
void BM_plugin_field_v3_name(benchmark::State &state) {
	run_arm(state, arm::v3_name);
}
void BM_plugin_field_v3_const(benchmark::State &state) {
	run_arm(state, arm::v3_const);
}
void BM_plugin_field_v3_ip(benchmark::State &state) {
	run_arm(state, arm::v3_ip);
}
void BM_plugin_field_v3_net(benchmark::State &state) {
	run_arm(state, arm::v3_net);
}

}  // namespace

BENCHMARK(BM_plugin_field_floor)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_raw_pid)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_raw_name)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_evtnum)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_name)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_bool)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_fspath)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_rawarg_int)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_glob)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_icontains)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_in)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_uid)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_x2)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_x4)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_x8)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_ors_x8)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_deep_x6)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_nots_x4)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_pid_group_x4)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_proc_mixed_x4)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_v3_pid)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_v3_name)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_v3_const)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_v3_ip)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_plugin_field_v3_net)->Unit(benchmark::kMillisecond);
