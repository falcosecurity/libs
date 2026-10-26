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

#include <gtest/gtest.h>

#include <libscap/scap.h>
#include <libscap/linux/scap_linux_platform.h>
extern "C" {
#include <libscap/linux/scap_linux_int.h>

// Not exposed by any header, but has external linkage (defined in linux/scap_procs.c).
int32_t scap_proc_read_thread(struct scap_linux_platform* linux_platform,
                              struct scap_proclist* proclist,
                              char* procdirname,
                              uint64_t tid,
                              char* error,
                              bool scan_sockets);
}

#include <fcntl.h>
#include <linux/capability.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

namespace {

// Environment written to the fake environ file (NUL-separated, NUL-terminated).
constexpr char k_fake_environ[] = "FOO=bar\0BAZ=qux";

// Captures the thread info reported by the /proc scan through the proc entry callback.
struct captured_proc {
	int calls = 0;
	scap_threadinfo tinfo{};
};

int32_t capture_proc_entry_cb(void* context,
                              char* error,
                              int64_t tid,
                              scap_threadinfo* tinfo,
                              scap_fdinfo* fdinfo,
                              scap_threadinfo** new_tinfo) {
	auto* captured = static_cast<captured_proc*>(context);
	if(fdinfo == nullptr && tinfo != nullptr) {
		captured->calls++;
		captured->tinfo = *tinfo;
	}
	return SCAP_SUCCESS;
}

// Temporarily removes CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH from the effective set of the
// calling thread, so that file permission checks apply even when the test runs as root. The
// capabilities stay in the permitted set and are restored on destruction.
class scoped_drop_dac_caps {
public:
	scoped_drop_dac_caps() {
		if(syscall(SYS_capget, &m_hdr, m_saved) != 0) {
			return;
		}
		__user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
		memcpy(data, m_saved, sizeof(data));
		for(const int cap : {CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH}) {
			data[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
		}
		m_active = syscall(SYS_capset, &m_hdr, data) == 0;
	}

	~scoped_drop_dac_caps() {
		if(m_active) {
			syscall(SYS_capset, &m_hdr, m_saved);
		}
	}

	scoped_drop_dac_caps(const scoped_drop_dac_caps&) = delete;
	scoped_drop_dac_caps& operator=(const scoped_drop_dac_caps&) = delete;

private:
	__user_cap_header_struct m_hdr{_LINUX_CAPABILITY_VERSION_3, 0};
	__user_cap_data_struct m_saved[_LINUX_CAPABILITY_U32S_3]{};
	bool m_active = false;
};

std::string readlink_str(const std::string& path) {
	char buf[PATH_MAX];
	const ssize_t len = readlink(path.c_str(), buf, sizeof(buf) - 1);
	if(len <= 0) {
		return "";
	}
	return std::string(buf, len);
}

}  // namespace

// Builds a fake procfs directory `<tmp>/<pid>/` describing the current process. All entries
// point to the real `/proc/<pid>/` ones except `environ`, which is a regular file whose
// permissions are controlled by the test. This allows triggering EACCES deterministically
// when opening the environ file, as happens for containerized processes when the scanner
// lacks CAP_DAC_READ_SEARCH.
class scap_procs_environ : public testing::Test {
protected:
	void SetUp() override {
		char tmpl[] = "/tmp/scap_procs_environ_XXXXXX";
		ASSERT_NE(mkdtemp(tmpl), nullptr) << strerror(errno);
		m_proc_root = tmpl;

		m_pid = getpid();
		const std::string real_dir = "/proc/" + std::to_string(m_pid) + "/";
		m_fake_dir = m_proc_root + "/" + std::to_string(m_pid) + "/";
		ASSERT_EQ(mkdir(m_fake_dir.c_str(), 0700), 0) << strerror(errno);

		// Regular files: link to the real procfs entries.
		for(const char* entry : {"cmdline", "comm", "status", "stat"}) {
			const std::string target = real_dir + entry;
			const std::string link = m_fake_dir + entry;
			ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0) << link << ": " << strerror(errno);
		}

		// Symlinks read with readlink(): link directly to the resolved targets.
		for(const char* entry : {"exe", "cwd", "root"}) {
			const std::string target = readlink_str(real_dir + entry);
			ASSERT_FALSE(target.empty()) << "cannot resolve " << real_dir << entry;
			const std::string link = m_fake_dir + entry;
			ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0) << link << ": " << strerror(errno);
		}

		// Empty fd directory, so the fd scan succeeds without finding anything.
		ASSERT_EQ(mkdir((m_fake_dir + "fd").c_str(), 0700), 0) << strerror(errno);

		m_environ_path = m_fake_dir + "environ";
		const int fd = open(m_environ_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
		ASSERT_NE(fd, -1) << strerror(errno);
		ASSERT_EQ(write(fd, k_fake_environ, sizeof(k_fake_environ)),
		          (ssize_t)sizeof(k_fake_environ));
		close(fd);

		m_platform.m_lasterr = m_lasterr;
		m_proclist.m_callbacks.m_proc_entry_cb = capture_proc_entry_cb;
		m_proclist.m_callbacks.m_callback_context = &m_captured;
	}

	void TearDown() override {
		if(!m_proc_root.empty()) {
			std::error_code ec;
			std::filesystem::remove_all(m_proc_root, ec);
		}
	}

	// Makes the environ file unreadable. Returns true if opening it now fails with EACCES
	// (must be checked while `scoped_drop_dac_caps` is active).
	bool make_environ_unreadable() {
		if(chmod(m_environ_path.c_str(), 0000) != 0) {
			return false;
		}
		const int fd = open(m_environ_path.c_str(), O_RDONLY);
		if(fd != -1) {
			close(fd);
			return false;
		}
		return errno == EACCES;
	}

	int32_t read_thread() {
		std::string procdir = m_proc_root;
		return scap_proc_read_thread(&m_platform,
		                             &m_proclist,
		                             procdir.data(),
		                             m_pid,
		                             m_error,
		                             false);
	}

	std::string m_proc_root;
	std::string m_fake_dir;
	std::string m_environ_path;
	pid_t m_pid = 0;

	char m_lasterr[SCAP_LASTERR_SIZE]{};
	char m_error[SCAP_LASTERR_SIZE]{};
	scap_linux_platform m_platform{};
	scap_proclist m_proclist{};
	captured_proc m_captured;
};

// EACCES on environ yields an empty environment and the retrieval continues.
TEST_F(scap_procs_environ, eacces_yields_empty_environ) {
	scoped_drop_dac_caps drop_caps;
	if(!make_environ_unreadable()) {
		GTEST_SKIP() << "cannot make " << m_environ_path << " fail with EACCES";
	}

	ASSERT_EQ(read_thread(), SCAP_SUCCESS) << m_error;
	ASSERT_EQ(m_captured.calls, 1);
	EXPECT_EQ(m_captured.tinfo.env_len, 0);
	EXPECT_EQ(m_captured.tinfo.env[0], '\0');

	// The rest of the information has still been collected.
	EXPECT_EQ(m_captured.tinfo.tid, m_pid);
	EXPECT_EQ(m_captured.tinfo.pid, m_pid);
	EXPECT_NE(m_captured.tinfo.comm[0], '\0');
	EXPECT_NE(m_captured.tinfo.exepath[0], '\0');
}

// Errors other than EACCES (here ENOENT) still fail the thread retrieval.
TEST_F(scap_procs_environ, other_open_errors_fail) {
	ASSERT_EQ(unlink(m_environ_path.c_str()), 0) << strerror(errno);

	ASSERT_EQ(read_thread(), SCAP_FAILURE);
	EXPECT_NE(strstr(m_error, "can't open environ file"), nullptr) << m_error;
	EXPECT_NE(strstr(m_error, m_environ_path.c_str()), nullptr) << m_error;
	EXPECT_EQ(m_captured.calls, 0);
}

// Readable environ: the environment is read as usual.
TEST_F(scap_procs_environ, readable_environ) {
	ASSERT_EQ(read_thread(), SCAP_SUCCESS) << m_error;
	ASSERT_EQ(m_captured.calls, 1);
	ASSERT_EQ(m_captured.tinfo.env_len, sizeof(k_fake_environ));
	EXPECT_EQ(memcmp(m_captured.tinfo.env, k_fake_environ, sizeof(k_fake_environ)), 0);
}
