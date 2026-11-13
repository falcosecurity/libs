#include "../../event_class/event_class.h"

#ifdef __NR_openat
#include <sched.h>
#include <string>
#include <vector>

TEST(SyscallEnter, openatE) {
	auto evt_test = get_syscall_event_test(__NR_openat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * With `O_TMPFILE` flag the pathname must be a directory
	 * but here it is a filename so the call will fail!
	 */

	int dirfd = AT_FDCWD;
	const char* pathname = "mock_path";
	int flags = O_RDWR | O_TMPFILE | O_DIRECTORY;
	mode_t mode = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "openat",
	                     syscall(__NR_openat, dirfd, pathname, flags, mode));

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)PPM_AT_FDCWD);

	/* Parameter 2: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, pathname);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDWR | PPM_O_TMPFILE | PPM_O_DIRECTORY);

	/* Parameter 4: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)mode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}

namespace {
// Restores the CPU affinity of the calling thread on scope exit.
class affinity_guard {
public:
	explicit affinity_guard(const cpu_set_t& set): m_set(set) {}
	~affinity_guard() { sched_setaffinity(0, sizeof(m_set), &m_set); }

private:
	cpu_set_t m_set;
};
}  // namespace

// On some kernels, a BPF program on a syscall tracepoint that reads user memory runs only on the
// CPUs with an active perf event of the tracepoint. libbpf opens one on CPU 0 only, and libpman
// opens one on each CPU. Make one call on each CPU the test can use.
TEST(SyscallEnter, openatE_every_cpu) {
	auto evt_test = get_syscall_event_test(__NR_openat, ENTER_EVENT);

	cpu_set_t allowed;
	ASSERT_EQ(sched_getaffinity(0, sizeof(allowed), &allowed), 0);
	affinity_guard guard(allowed);
	std::vector<std::string> pathnames;

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	for(int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if(!CPU_ISSET(cpu, &allowed)) {
			continue;
		}
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(cpu, &one);
		ASSERT_EQ(sched_setaffinity(0, sizeof(one), &one), 0) << "cannot move to CPU " << cpu;

		pathnames.push_back("mock_path_cpu_" + std::to_string(cpu));
		assert_syscall_state(SYSCALL_FAILURE,
		                     "openat",
		                     syscall(__NR_openat,
		                             AT_FDCWD,
		                             pathnames.back().c_str(),
		                             O_RDWR | O_TMPFILE | O_DIRECTORY,
		                             0));
	}

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	for(const auto& pathname : pathnames) {
		evt_test->assert_event_presence();

		if(HasFatalFailure()) {
			return;
		}

		evt_test->parse_event();

		/* Parameter 2: name (type: PT_FSPATH) */
		evt_test->assert_charbuf_param(2, pathname.c_str());
	}
}

TEST(SyscallEnter, openatE_max_path) {
	auto evt_test = get_syscall_event_test(__NR_openat, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* Syscall special notes:
	 * With `O_TMPFILE` flag the pathname must be a directory
	 * but here it is a filename so the call will fail!
	 */

	int dirfd = AT_FDCWD;
	std::string pathname("");
	pathname.insert(0, PPM_MAX_PATH_SIZE - 1, 'A');
	int flags = O_RDWR | O_TMPFILE | O_DIRECTORY;
	mode_t mode = 0;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "openat",
	                     syscall(__NR_openat, dirfd, pathname.c_str(), flags, mode));

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)PPM_AT_FDCWD);

	/* Parameter 2: name (type: PT_FSPATH) */
	evt_test->assert_charbuf_param(2, pathname.c_str());

	/* Parameter 3: flags (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_O_RDWR | PPM_O_TMPFILE | PPM_O_DIRECTORY);

	/* Parameter 4: mode (type: PT_UINT32) */
	evt_test->assert_numeric_param(4, (uint32_t)mode);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
