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

// The process tree: what an ancestor walk and a process exit cost.
//
// A user-space instruction counter runs only around each measured operation, so the counts do
// not include setup. With PROCESS_TREE_COUNTER=cycles, it counts cycles. Ignore the wall time.
//
// BM_walk_full/D        traverse_parent_state() up a chain D deep
// BM_walk_nth/N         get_ancestor_process(n) on a chain 16 deep
// BM_walk_dead/K        a walk up a chain 16 deep after K ancestors died, with known reapers
// BM_walk_dead_lazy/K   the same with unknown reapers, and every ancestor is a subreaper
// BM_exit/C             remove_thread() on a process with C live children. insn_child_exit is
//                       the exit of each child after it
// BM_{clone,execve}_after_dead_ancestors/K/R
//                       a clone or execve through sinsp::next() by the leaf of a 16-deep chain,
//                       after K ancestors died from the bottom up (R=1: the reaper is known).
//                       insn_walk is the walk from the leaf after it
// BM_{clone,execve}_after_fork_exit_chain/K/R
//                       the same after K processes each forked the next and exited

#include <benchmark/benchmark.h>

#include <libsinsp/sinsp.h>
#include <libscap/engine/test_input/test_input_public.h>
#include <libscap/scap.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

/* PROCESS_TREE_COUNTER=cycles counts cycles instead of instructions */
bool counting_cycles() {
	const char* env = getenv("PROCESS_TREE_COUNTER");
	return env != nullptr && strcmp(env, "cycles") == 0;
}

const char* counter_name() {
	return counting_cycles() ? "cycles" : "insn";
}

class insn_counter {
public:
	insn_counter() {
		perf_event_attr attr;
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_HARDWARE;
		attr.config = counting_cycles() ? PERF_COUNT_HW_CPU_CYCLES : PERF_COUNT_HW_INSTRUCTIONS;
		attr.disabled = 1;
		attr.exclude_kernel = 1;
		attr.exclude_hv = 1;
		m_fd = static_cast<int>(syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0));
	}
	~insn_counter() {
		if(m_fd >= 0) {
			close(m_fd);
		}
	}
	bool ok() const { return m_fd >= 0; }
	void start() { ioctl(m_fd, PERF_EVENT_IOC_ENABLE, 0); }
	void stop() { ioctl(m_fd, PERF_EVENT_IOC_DISABLE, 0); }
	uint64_t read_total() const {
		uint64_t v = 0;
		if(::read(m_fd, &v, sizeof(v)) != sizeof(v)) {
			return 0;
		}
		return v;
	}

private:
	int m_fd = -1;
};

struct tree {
	tree() {
		m_data.event_count = 0;
		m_data.thread_count = 0;
		m_inspector.open_test_input(&m_data, SINSP_MODE_TEST);
		add(1, 1, 0);
	}

	sinsp_threadinfo* add(int64_t tid, int64_t pid, int64_t ptid) {
		auto t = m_inspector.get_threadinfo_factory().create();
		t->m_tid = tid;
		t->m_pid = pid;
		t->set_ptid(ptid);
		t->m_vtid = tid;
		t->m_vpid = pid;
		t->m_comm = "proc";
		return m_inspector.m_thread_manager->add_thread(std::move(t), true).get();
	}

	sinsp_threadinfo* find(int64_t tid) {
		return m_inspector.m_thread_manager->find_thread(tid, true).get();
	}

	/* What the parser does on a procexit, then what sinsp does on the next event. */
	void exit(int64_t tid, int64_t reaper_tid) {
		auto t = find(tid);
		if(t->m_tginfo != nullptr && !t->is_dead()) {
			t->m_tginfo->decrement_thread_count();
		}
		t->set_dead();
		t->m_reaper_tid = reaper_tid;
		m_inspector.m_thread_manager->remove_thread(tid);
	}

	/* init(1) <- 2 <- 3 <- ... <- depth+1. Returns the leaf. */
	sinsp_threadinfo* chain(int64_t depth, bool subreapers = false) {
		for(int64_t tid = 2; tid <= depth + 1; tid++) {
			add(tid, tid, tid - 1);
			if(subreapers) {
				find(tid)->m_tginfo->set_reaper(true);
			}
		}
		return find(depth + 1);
	}

	/* Feed one event. The test input engine reads `m_data` on next(). */
	void feed(std::vector<uint8_t>& event) {
		m_event = reinterpret_cast<ppm_evt_hdr*>(event.data());
		m_data.events = &m_event;
		m_data.event_count = 1;
	}

	scap_test_input_data m_data{};
	ppm_evt_hdr* m_event = nullptr;
	sinsp m_inspector;
};

/* The first pass gets the size of the event. The second pass fills it. */
template<typename... Args>
std::vector<uint8_t> encode(uint64_t ts, int64_t tid, ppm_event_code type, Args... args) {
	scap_sized_buffer probe = {nullptr, 0};
	size_t needed = 0;
	char err[SCAP_LASTERR_SIZE] = {};
	const uint32_t n = sizeof...(Args);
	if(scap_event_encode_params(probe, &needed, err, type, n, args...) != SCAP_INPUT_TOO_SMALL) {
		throw std::runtime_error(std::string("cannot size event: ") + err);
	}
	std::vector<uint8_t> buf(needed);
	scap_sized_buffer out = {buf.data(), buf.size()};
	if(scap_event_encode_params(out, &needed, err, type, n, args...) != SCAP_SUCCESS) {
		throw std::runtime_error(std::string("cannot encode event: ") + err);
	}
	auto e = reinterpret_cast<scap_evt*>(buf.data());
	e->ts = ts;
	e->tid = static_cast<uint64_t>(tid);
	return buf;
}

/* The parent side of a fork by `tid`, whose new child is `child` */
std::vector<uint8_t> clone_event(int64_t tid, int64_t ptid, int64_t child) {
	const scap_const_sized_buffer empty = {nullptr, 0};
	const uint64_t u64 = 0;
	const uint32_t u32 = 0;
	return encode(1000000000,
	              tid,
	              PPME_SYSCALL_CLONE_20_X,
	              child,
	              "/bin/proc",
	              empty,
	              tid,
	              tid,
	              ptid,
	              "",
	              u64,
	              u64,
	              u64,
	              u32,
	              u32,
	              u32,
	              "proc",
	              empty,
	              u32,
	              u32,
	              u32,
	              tid,
	              tid,
	              u64);
}

/* A successful execve by `tid` */
std::vector<uint8_t> execve_event(int64_t tid, int64_t ptid) {
	const scap_const_sized_buffer empty = {nullptr, 0};
	const uint64_t u64 = 0;
	const uint32_t u32 = 0;
	const int64_t success = 0;
	const int64_t pgid = 0;
	return encode(1000000000,
	              tid,
	              PPME_SYSCALL_EXECVE_19_X,
	              success,
	              "/bin/exe",
	              empty,
	              tid,
	              tid,
	              ptid,
	              "",
	              u64,
	              u64,
	              u64,
	              u32,
	              u32,
	              u32,
	              "exe",
	              empty,
	              empty,
	              u32,
	              u64,
	              u32,
	              u32,
	              u64,
	              u64,
	              u64,
	              u64,
	              u64,
	              u64,
	              u32,
	              "/bin/exe",
	              pgid,
	              u32,
	              "/bin/exe");
}

void report(benchmark::State& state, insn_counter& counter, uint64_t ops) {
	state.counters[counter_name()] = benchmark::Counter(static_cast<double>(counter.read_total()) /
	                                                    static_cast<double>(ops));
}

void walk(benchmark::State& state, tree& t, sinsp_threadinfo* leaf) {
	insn_counter counter;
	if(!counter.ok()) {
		state.SkipWithError("perf_event_open failed");
		return;
	}
	uint64_t visited = 0;
	sinsp_thread_manager::visitor_func_t visitor = [&visited](sinsp_threadinfo* pt) {
		visited++;
		return true;
	};
	uint64_t ops = 0;
	for(auto _ : state) {
		counter.start();
		t.m_inspector.m_thread_manager->traverse_parent_state(*leaf, visitor);
		counter.stop();
		ops++;
	}
	report(state, counter, ops);
	state.counters["visited"] =
	        benchmark::Counter(static_cast<double>(visited) / static_cast<double>(ops));
}

static void BM_walk_full(benchmark::State& state) {
	tree t;
	auto leaf = t.chain(state.range(0));
	walk(state, t, leaf);
}
BENCHMARK(BM_walk_full)->Arg(1)->Arg(4)->Arg(16)->Arg(64);

static void BM_walk_nth(benchmark::State& state) {
	tree t;
	auto leaf = t.chain(16);
	insn_counter counter;
	if(!counter.ok()) {
		state.SkipWithError("perf_event_open failed");
		return;
	}
	const auto n = static_cast<uint32_t>(state.range(0));
	uint64_t ops = 0;
	for(auto _ : state) {
		counter.start();
		auto a = t.m_inspector.m_thread_manager->get_ancestor_process(*leaf, n);
		counter.stop();
		benchmark::DoNotOptimize(a);
		ops++;
	}
	report(state, counter, ops);
}
BENCHMARK(BM_walk_nth)->Arg(1)->Arg(2)->Arg(4)->Arg(8);

/* Kill K ancestors of the leaf of a 16-deep chain. Start at the parent of the leaf and kill
 * every second ancestor, so that no two dead ancestors are adjacent unless K > 8.
 */
static void kill_ancestors(tree& t, int64_t dead, bool kernel_reaper) {
	const int64_t leaf = 17;
	int64_t killed = 0;
	for(int64_t tid = leaf - 1; tid >= 2 && killed < dead; tid -= (dead > 8 ? 1 : 2)) {
		/* The kernel gives the nearest live ancestor as the reaper (when lazy, all are
		 * subreapers) */
		int64_t reaper = tid - 1;
		while(reaper > 1 && t.find(reaper) == nullptr) {
			reaper--;
		}
		t.exit(tid, kernel_reaper ? reaper : -1);
		killed++;
	}
}

static void BM_walk_dead(benchmark::State& state) {
	tree t;
	auto leaf = t.chain(16, true);
	kill_ancestors(t, state.range(0), true);
	walk(state, t, leaf);
}
BENCHMARK(BM_walk_dead)->Arg(0)->Arg(1)->Arg(4)->Arg(8)->Arg(15);

static void BM_walk_dead_lazy(benchmark::State& state) {
	tree t;
	auto leaf = t.chain(16, true);
	kill_ancestors(t, state.range(0), false);
	walk(state, t, leaf);
}
BENCHMARK(BM_walk_dead_lazy)->Arg(0)->Arg(1)->Arg(4)->Arg(8)->Arg(15);

/* Under init, K processes each fork the next one and exit at once. Returns the leaf. */
static sinsp_threadinfo* fork_exit_chain(tree& t, int64_t dead, bool kernel_reaper) {
	t.add(2, 2, 1);
	for(int64_t tid = 3; tid <= dead + 2; tid++) {
		t.add(tid, tid, tid - 1);
		t.exit(tid - 1, kernel_reaper ? 1 : -1);
	}
	return t.find(dead + 2);
}

/* Each iteration builds a new tree, because the event changes it. The counts include only the
 * event and the walk. */
template<bool execve, bool fork_exit>
static void BM_after_chain(benchmark::State& state) {
	const int64_t dead = state.range(0);
	const bool kernel_reaper = state.range(1) != 0;
	insn_counter counter;
	insn_counter walk_counter;
	if(!counter.ok() || !walk_counter.ok()) {
		state.SkipWithError("perf_event_open failed");
		return;
	}
	uint64_t visited = 0;
	sinsp_thread_manager::visitor_func_t visitor = [&visited](sinsp_threadinfo*) {
		visited++;
		return true;
	};
	uint64_t ops = 0;
	for(auto _ : state) {
		state.PauseTiming();
		tree t;
		sinsp_threadinfo* leaf;
		if(fork_exit) {
			leaf = fork_exit_chain(t, dead, kernel_reaper);
		} else {
			leaf = t.chain(16, true);
			kill_ancestors(t, dead, kernel_reaper);
		}
		const int64_t tid = leaf->m_tid;
		const int64_t ptid = leaf->get_ptid();
		auto event = execve ? execve_event(tid, ptid) : clone_event(tid, ptid, 100000);
		t.feed(event);
		sinsp_evt* evt = nullptr;
		state.ResumeTiming();

		counter.start();
		const int32_t rc = t.m_inspector.next(&evt);
		counter.stop();
		if(rc != SCAP_SUCCESS) {
			state.SkipWithError("the event was not processed");
			return;
		}

		walk_counter.start();
		t.m_inspector.m_thread_manager->traverse_parent_state(*t.find(tid), visitor);
		walk_counter.stop();
		ops++;
	}
	report(state, counter, ops);
	state.counters[std::string(counter_name()) + "_walk"] = benchmark::Counter(
	        static_cast<double>(walk_counter.read_total()) / static_cast<double>(ops));
	state.counters["visited"] =
	        benchmark::Counter(static_cast<double>(visited) / static_cast<double>(ops));
}

#define AFTER_CHAIN_ARGS(dead_max)                          \
	ArgNames({"dead", "kernel_reaper"})                     \
	        ->ArgsProduct({{0, 1, 4, 8, dead_max}, {0, 1}}) \
	        ->Iterations(300)
BENCHMARK(BM_after_chain<false, false>)
        ->Name("BM_clone_after_dead_ancestors")
        ->AFTER_CHAIN_ARGS(15);
BENCHMARK(BM_after_chain<true, false>)
        ->Name("BM_execve_after_dead_ancestors")
        ->AFTER_CHAIN_ARGS(15);
BENCHMARK(BM_after_chain<false, true>)
        ->Name("BM_clone_after_fork_exit_chain")
        ->AFTER_CHAIN_ARGS(64);
BENCHMARK(BM_after_chain<true, true>)
        ->Name("BM_execve_after_fork_exit_chain")
        ->AFTER_CHAIN_ARGS(64);

static void BM_exit(benchmark::State& state) {
	const int64_t children = state.range(0);
	insn_counter counter;
	insn_counter cleanup_counter;
	if(!counter.ok() || !cleanup_counter.ok()) {
		state.SkipWithError("perf_event_open failed");
		return;
	}
	tree t;
	uint64_t ops = 0;
	int64_t next_tid = 1000;
	for(auto _ : state) {
		state.PauseTiming();
		const int64_t parent = next_tid++;
		t.add(parent, parent, 1);
		const int64_t first_child = next_tid;
		for(int64_t i = 0; i < children; i++) {
			t.add(next_tid, next_tid, parent);
			next_tid++;
		}
		state.ResumeTiming();

		counter.start();
		t.exit(parent, 1);
		counter.stop();
		ops++;

		state.PauseTiming();
		cleanup_counter.start();
		for(int64_t tid = first_child; tid < first_child + children; tid++) {
			t.exit(tid, 0);
		}
		cleanup_counter.stop();
		state.ResumeTiming();
	}
	report(state, counter, ops);
	/* The exits of the children, per child */
	state.counters[std::string(counter_name()) + "_child_exit"] = benchmark::Counter(
	        static_cast<double>(cleanup_counter.read_total()) /
	        static_cast<double>(ops * static_cast<uint64_t>(children > 0 ? children : 1)));
}
BENCHMARK(BM_exit)->Arg(0)->Arg(1)->Arg(10)->Arg(100)->Arg(1000)->Iterations(2000);

}  // namespace
