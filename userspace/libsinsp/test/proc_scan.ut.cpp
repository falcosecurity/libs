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

// Tests of the /proc scan against real processes: each test forks a process in a known state and
// opens a nodriver inspector with a full scan.

#include <gtest/gtest.h>
#include <test/gtest_compat.h>

#include <libscap/scap_config.h>
#include <libsinsp/sinsp.h>

#if defined(__linux__) && defined(HAS_ENGINE_NODRIVER)

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

// Open on /dev/null in every scan target, in the table of the process.
constexpr int s_process_fd = 345;
// Open on /dev/zero by a thread after it unshares its files, in its own table only.
constexpr int s_thread_fd = 346;

int s_report_fd = -1;

// Reported instead of a tid by a thread that unshare() refused, for example by a seccomp profile.
constexpr pid_t s_unshare_refused = -1;

[[noreturn]] void report_and_wait(const pid_t tid) {
	if(write(s_report_fd, &tid, sizeof(tid)) != sizeof(tid)) {
		_exit(1);
	}
	for(;;) {
		pause();
	}
}

void* report_tid_and_wait(void*) {
	report_and_wait(static_cast<pid_t>(syscall(SYS_gettid)));
}

void* unshare_open_report_tid_and_wait(void* arg) {
	if(unshare(CLONE_FILES) != 0) {
		report_and_wait(s_unshare_refused);
	}
	const int fd = open("/dev/zero", O_RDONLY);
	if(fd < 0 || dup2(fd, s_thread_fd) < 0) {
		_exit(1);
	}
	return report_tid_and_wait(arg);
}

// A process for the scan to find, with `threads` threads besides the leader. The first
// `unsharing_threads` of them unshare their files. If `leader_exits`, the leader exits once the
// threads run, and stays a zombie until they exit.
class scan_target {
public:
	scan_target(int threads, bool leader_exits, int unsharing_threads = 0) {
		int report[2];
		if(pipe(report) != 0) {
			throw std::runtime_error("pipe failed");
		}
		m_pid = fork();
		if(m_pid < 0) {
			throw std::runtime_error("fork failed");
		}
		if(m_pid == 0) {
			close(report[0]);
			run(report[1], threads, leader_exits, unsharing_threads);
		}
		close(report[1]);
		for(int i = 0; i < threads; i++) {
			pid_t tid;
			if(read(report[0], &tid, sizeof(tid)) != sizeof(tid)) {
				break;
			}
			if(tid == s_unshare_refused) {
				m_unshare_refused = true;
				continue;
			}
			m_tids.push_back(tid);
		}
		close(report[0]);
		if(leader_exits) {
			wait_for_zombie_leader();
		}
	}

	~scan_target() {
		kill(m_pid, SIGKILL);
		waitpid(m_pid, nullptr, 0);
	}

	scan_target(const scan_target&) = delete;
	scan_target& operator=(const scan_target&) = delete;

	pid_t pid() const { return m_pid; }
	const std::vector<pid_t>& tids() const { return m_tids; }
	// Whether unshare(CLONE_FILES) failed in a thread. That thread is not in tids().
	bool unshare_refused() const { return m_unshare_refused; }

private:
	[[noreturn]] static void run(int report_fd,
	                             int threads,
	                             bool leader_exits,
	                             int unsharing_threads) {
		const int fd = open("/dev/null", O_RDONLY);
		if(fd < 0 || dup2(fd, s_process_fd) < 0) {
			_exit(1);
		}
		s_report_fd = report_fd;
		for(int i = 0; i < threads; i++) {
			pthread_t thread;
			const auto start =
			        i < unsharing_threads ? unshare_open_report_tid_and_wait : report_tid_and_wait;
			if(pthread_create(&thread, nullptr, start, nullptr) != 0) {
				_exit(1);
			}
		}
		if(leader_exits) {
			syscall(SYS_exit, 0);
		}
		for(;;) {
			pause();
		}
	}

	void wait_for_zombie_leader() const {
		const std::string stat = "/proc/" + std::to_string(m_pid) + "/stat";
		for(int i = 0; i < 5000; i++) {
			std::ifstream in(stat);
			std::string line;
			std::getline(in, line);
			const auto comm_end = line.rfind(')');
			if(comm_end != std::string::npos && comm_end + 2 < line.size() &&
			   line[comm_end + 2] == 'Z') {
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		throw std::runtime_error("the leader did not exit");
	}

	pid_t m_pid;
	std::vector<pid_t> m_tids;
	bool m_unshare_refused = false;
};

// Opens a nodriver inspector with a full scan. The scan rejects a process whose cgroup files it
// cannot read, and as non-root that is every process: then it returns false.
bool open_full_scan(sinsp& inspector) {
	inspector.open_nodriver(true);
	return inspector.m_thread_manager->find_thread(getpid(), true) != nullptr;
}

// Whether kcmp() can compare the files of `pid` with the files of each of `tids`. When it cannot
// (no syscall, or a seccomp profile or a missing capability refuses it), the scan assumes that
// the threads share the files of their process.
bool kcmp_compares_files(pid_t pid, const std::vector<pid_t>& tids) {
#ifdef SYS_kcmp
	constexpr int kcmp_files = 2;  // KCMP_FILES of enum kcmp_type in linux/kcmp.h
	for(const pid_t tid : tids) {
		if(syscall(SYS_kcmp, pid, tid, kcmp_files, 0, 0) < 0) {
			return false;
		}
	}
	return true;
#else
	return false;
#endif
}

}  // namespace

// The scan finds a process whose leader exited, with the fds that its threads still hold.
TEST(proc_scan, finds_a_process_whose_leader_exited) {
	scan_target target(2, true);
	ASSERT_EQ(target.tids().size(), 2);

	sinsp inspector;
	if(!open_full_scan(inspector)) {
		SCAP_GTEST_SKIP("the /proc scan cannot read this process (it needs root)");
	}

	auto leader = inspector.m_thread_manager->find_thread(target.pid(), true);
	ASSERT_NE(leader, nullptr);
	// The leader exited: it is dead, and only its threads are alive.
	EXPECT_TRUE(leader->is_dead());
	EXPECT_EQ(leader->m_tginfo->get_thread_count(), target.tids().size());
	// Read through a live thread: the zombie leader has no exe link.
	EXPECT_FALSE(leader->m_exepath.empty());
	const sinsp_fdinfo* fdinfo = leader->get_fdtable().find(s_process_fd);
	ASSERT_NE(fdinfo, nullptr);
	EXPECT_EQ(fdinfo->m_name, "/dev/null");

	for(const pid_t tid : target.tids()) {
		auto thread = inspector.m_thread_manager->find_thread(tid, true);
		ASSERT_NE(thread, nullptr) << "tid " << tid;
		EXPECT_EQ(thread->get_fd_table(), leader->get_fd_table()) << "tid " << tid;
	}
}

// Skips the test if the threads of `target` cannot have fds of their own, or if kcmp() cannot tell.
#define SKIP_IF_THREADS_CANNOT_UNSHARE_FILES(target)                           \
	do {                                                                       \
		if((target).unshare_refused()) {                                       \
			SCAP_GTEST_SKIP("unshare(CLONE_FILES) is refused here");           \
		}                                                                      \
		ASSERT_EQ((target).tids().size(), 2);                                  \
		if(!kcmp_compares_files((target).pid(), (target).tids())) {            \
			SCAP_GTEST_SKIP("kcmp() cannot compare the files of the threads"); \
		}                                                                      \
	} while(0)

// A thread that unshared its files keeps its own fd table, read from its own fd directory. The
// other threads share the table of the process.
TEST(proc_scan, a_thread_that_unshared_its_files_has_its_own_fd_table) {
	scan_target target(2, false, 1);
	SKIP_IF_THREADS_CANNOT_UNSHARE_FILES(target);

	sinsp inspector;
	if(!open_full_scan(inspector)) {
		SCAP_GTEST_SKIP("the /proc scan cannot read this process (it needs root)");
	}

	auto leader = inspector.m_thread_manager->find_thread(target.pid(), true);
	ASSERT_NE(leader, nullptr);
	ASSERT_NE(leader->get_fdtable().find(s_process_fd), nullptr);
	EXPECT_EQ(leader->get_fdtable().find(s_thread_fd), nullptr);

	// The report order of the threads is not known: one has its own table, one shares.
	int own_tables = 0;
	for(const pid_t tid : target.tids()) {
		auto thread = inspector.m_thread_manager->find_thread(tid, true);
		ASSERT_NE(thread, nullptr) << "tid " << tid;
		if(thread->get_fd_table() == leader->get_fd_table()) {
			EXPECT_TRUE(thread->m_flags & PPM_CL_CLONE_FILES) << "tid " << tid;
			continue;
		}
		own_tables++;
		EXPECT_FALSE(thread->m_flags & PPM_CL_CLONE_FILES) << "tid " << tid;
		const sinsp_fdinfo* fdinfo = thread->get_fdtable().find(s_thread_fd);
		ASSERT_NE(fdinfo, nullptr) << "tid " << tid;
		EXPECT_EQ(fdinfo->m_name, "/dev/zero");
		// The fds before the unshare are in the copy too.
		EXPECT_NE(thread->get_fdtable().find(s_process_fd), nullptr) << "tid " << tid;
	}
	EXPECT_EQ(own_tables, 1);
}

// A thread with its own fd table looks up a single fd (for example, one that it received with
// SCM_RIGHTS) in its own fd directory, and the fd goes to its own table.
TEST(proc_scan, a_thread_with_its_own_fd_table_looks_up_its_own_fd) {
	scan_target target(2, false, 1);
	SKIP_IF_THREADS_CANNOT_UNSHARE_FILES(target);

	sinsp inspector;
	if(!open_full_scan(inspector)) {
		SCAP_GTEST_SKIP("the /proc scan cannot read this process (it needs root)");
	}

	auto leader = inspector.m_thread_manager->find_thread(target.pid(), true);
	ASSERT_NE(leader, nullptr);
	std::shared_ptr<sinsp_threadinfo> thread;
	for(const pid_t tid : target.tids()) {
		auto candidate = inspector.m_thread_manager->find_thread(tid, true);
		ASSERT_NE(candidate, nullptr) << "tid " << tid;
		if(candidate->get_fd_table() != leader->get_fd_table()) {
			thread = candidate;
		}
	}
	ASSERT_NE(thread, nullptr);

	// Forget the fd that only the thread holds, then look it up as the parser does.
	thread->get_fdtable().erase(s_thread_fd);
	ASSERT_EQ(thread->get_fdtable().find(s_thread_fd), nullptr);
	scap_threadinfo scap_tinfo{};
	inspector.m_thread_manager->thread_to_scap(*thread, &scap_tinfo);
	char error[SCAP_LASTERR_SIZE] = {};
	ASSERT_EQ(scap_get_fdinfo(inspector.get_scap_platform(), &scap_tinfo, s_thread_fd, error),
	          SCAP_SUCCESS)
	        << error;

	const sinsp_fdinfo* fdinfo = thread->get_fdtable().find(s_thread_fd);
	ASSERT_NE(fdinfo, nullptr);
	EXPECT_EQ(fdinfo->m_name, "/dev/zero");
	EXPECT_EQ(leader->get_fdtable().find(s_thread_fd), nullptr);
}

// A nodriver refresh keeps the entry of a known thread. A thread that started since the last
// scan shares the table of its process, which the kept entry of the main thread holds.
TEST(proc_scan, a_thread_that_started_since_the_last_scan_shares_the_table_of_its_process) {
	const int fd = open("/dev/null", O_RDONLY);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(dup2(fd, s_process_fd), s_process_fd);
	close(fd);

	sinsp inspector;
	if(!open_full_scan(inspector)) {
		close(s_process_fd);
		SCAP_GTEST_SKIP("the /proc scan cannot read this process (it needs root)");
	}
	auto leader = inspector.m_thread_manager->find_thread(getpid(), true);
	ASSERT_NE(leader, nullptr);
	ASSERT_NE(leader->get_fdtable().find(s_process_fd), nullptr);

	std::atomic<pid_t> tid{0};
	std::atomic<bool> done{false};
	std::thread thread([&] {
		tid = static_cast<pid_t>(syscall(SYS_gettid));
		while(!done) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	});
	while(tid == 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	inspector.refresh_proc_list();
	auto worker = inspector.m_thread_manager->find_thread(tid, true);
	done = true;
	thread.join();
	close(s_process_fd);

	EXPECT_EQ(inspector.m_thread_manager->find_thread(getpid(), true), leader);
	ASSERT_NE(worker, nullptr);
	EXPECT_EQ(worker->get_fd_table(), leader->get_fd_table());
	EXPECT_NE(worker->get_fdtable().find(s_process_fd), nullptr);
}

// A nodriver refresh replaces the entry of a thread that unshared its files since the last scan.
// The fds of its own table do not go to the table of its process.
TEST(proc_scan, a_thread_that_unshared_its_files_since_the_last_scan_gets_its_own_table) {
	const int fd = open("/dev/null", O_RDONLY);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(dup2(fd, s_process_fd), s_process_fd);
	close(fd);

	std::atomic<pid_t> tid{0};
	std::atomic<bool> unshare_now{false};
	std::atomic<int> unshared{0};  // 1: own table, -1: unshare() was refused
	std::atomic<bool> done{false};
	std::thread thread([&] {
		tid = static_cast<pid_t>(syscall(SYS_gettid));
		while(!unshare_now && !done) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		if(done) {
			return;
		}
		// The same fd number names another file in the own table of the thread.
		if(unshare(CLONE_FILES) != 0) {
			unshared = -1;
		} else {
			const int zero = open("/dev/zero", O_RDONLY);
			if(zero < 0 || dup2(zero, s_process_fd) < 0) {
				_exit(1);
			}
			close(zero);
			unshared = 1;
		}
		while(!done) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	});
	while(tid == 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	// Stops the thread on every way out of the test: a failed assertion returns early.
	struct stopper {
		std::atomic<bool>& m_done;
		std::thread& m_thread;
		void operator()() {
			m_done = true;
			if(m_thread.joinable()) {
				m_thread.join();
				close(s_process_fd);
			}
		}
		~stopper() { (*this)(); }
	} stop{done, thread};

	sinsp inspector;
	if(!open_full_scan(inspector)) {
		stop();
		SCAP_GTEST_SKIP("the /proc scan cannot read this process (it needs root)");
	}
	if(!kcmp_compares_files(getpid(), {tid.load()})) {
		stop();
		SCAP_GTEST_SKIP("kcmp() cannot compare the files of the threads");
	}
	auto leader = inspector.m_thread_manager->find_thread(getpid(), true);
	ASSERT_NE(leader, nullptr);
	auto worker = inspector.m_thread_manager->find_thread(tid, true);
	ASSERT_NE(worker, nullptr);
	ASSERT_EQ(worker->get_fd_table(), leader->get_fd_table());

	unshare_now = true;
	while(unshared == 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	if(unshared < 0) {
		stop();
		SCAP_GTEST_SKIP("unshare(CLONE_FILES) is refused here");
	}

	inspector.refresh_proc_list();
	worker = inspector.m_thread_manager->find_thread(tid, true);
	stop();

	EXPECT_EQ(inspector.m_thread_manager->find_thread(getpid(), true), leader);
	const sinsp_fdinfo* fdinfo = leader->get_fdtable().find(s_process_fd);
	ASSERT_NE(fdinfo, nullptr);
	EXPECT_EQ(fdinfo->m_name, "/dev/null");
	ASSERT_NE(worker, nullptr);
	EXPECT_FALSE(worker->m_flags & PPM_CL_CLONE_FILES);
	EXPECT_NE(worker->get_fd_table(), leader->get_fd_table());
	fdinfo = worker->get_fdtable().find(s_process_fd);
	ASSERT_NE(fdinfo, nullptr);
	EXPECT_EQ(fdinfo->m_name, "/dev/zero");
}

#endif
