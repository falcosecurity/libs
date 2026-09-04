#include <gtest/gtest.h>
#include <libscap/scap_log.h>
#include <cerrno>
#include <string>

// These are internal libpman symbols (declared in libpman's private `state.h`, which we can't
// include here because it drags in the generated BPF skeleton header). They are exported by the
// `scap` library that this test binary links against, so we declare them directly.
extern "C" {
void log_errorf(const char* fmt, ...);
void log_msgf(enum falcosecurity_log_severity level, const char* fmt, ...);
int pman_init_state(falcosecurity_log_fn log_fn,
                    unsigned long buf_bytes_dim,
                    uint16_t cpus_for_each_buffer,
                    bool allocate_online_only,
                    bool disable_iterators);
}

namespace {
std::string g_last_msg;

void capture_log_fn(const char* /*component*/, const char* msg, falcosecurity_log_severity /*sev*/) {
	g_last_msg = msg != nullptr ? msg : "";
}

// Installs `capture_log_fn` as libpman's log callback. `pman_init_state()` sets the log callback
// before any of its own failure paths, so this works without root and regardless of its return
// value (which we intentionally ignore).
void install_capture_log_fn() {
	pman_init_state(capture_log_fn, 4 * 4096, 1, true, false);
}
}  // namespace

// A stale errno (as libbpf feature probes leave behind, e.g. EACCES from the verifier) must NOT
// leak into non-error log lines: those results are signalled via return values, not errno.
TEST(libpman_log, no_errno_appended_to_debug_log) {
	install_capture_log_fn();
	g_last_msg.clear();
	errno = EACCES;
	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "BPF program 'foo' satisfied required feature [1]");
	EXPECT_EQ(g_last_msg.find("errno:"), std::string::npos)
	        << "stale errno leaked into a debug log: " << g_last_msg;
}

TEST(libpman_log, no_errno_appended_to_info_or_warning_log) {
	install_capture_log_fn();
	errno = EACCES;
	log_msgf(FALCOSECURITY_LOG_SEV_INFO, "info line");
	EXPECT_EQ(g_last_msg.find("errno:"), std::string::npos)
	        << "stale errno leaked into an info log: " << g_last_msg;

	errno = EACCES;
	log_msgf(FALCOSECURITY_LOG_SEV_WARNING, "warning line");
	EXPECT_EQ(g_last_msg.find("errno:"), std::string::npos)
	        << "stale errno leaked into a warning log: " << g_last_msg;
}

// Error logs, where errno is meaningful, must still carry the errno detail.
TEST(libpman_log, errno_appended_to_error_log) {
	install_capture_log_fn();
	g_last_msg.clear();
	errno = EACCES;
	log_errorf("something failed");
	EXPECT_NE(g_last_msg.find("errno: 13"), std::string::npos)
	        << "error log should carry the errno detail: " << g_last_msg;
}

// With errno cleared, even an error log must not append a bogus errno detail.
TEST(libpman_log, no_errno_appended_when_errno_is_zero) {
	install_capture_log_fn();
	g_last_msg.clear();
	errno = 0;
	log_errorf("something failed");
	EXPECT_EQ(g_last_msg.find("errno:"), std::string::npos)
	        << "no errno detail expected when errno is 0: " << g_last_msg;
}
