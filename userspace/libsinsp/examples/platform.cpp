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

#include "platform.h"

#ifdef __linux__

#include <iostream>

#include <libscap/linux/scap_linux_platform.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_print.h>
#include <libscap/scap_const.h>

// fetch_* API testing options.
#define FETCH_OPT_FETCH_SILENTLY "fetch-silently"
#define FETCH_OPT_FETCH_THREAD "fetch-thread"
#define FETCH_OPT_FETCH_THREADS "fetch-threads"
#define FETCH_OPT_FETCH_PROC_FILE "fetch-proc-file"
#define FETCH_OPT_FETCH_PROC_FILES "fetch-proc-files"
#define FETCH_OPT_FETCH_PROC_FILES_SOCKETS "fetch-proc-files-sockets"
#define FETCH_OPT_FETCH_PROCS_FILES "fetch-procs-files"

// fetch_* API testing state.
static bool do_fetch_silently = false;
static bool do_fetch_thread = false;
static int64_t fetch_thread_tid = -1;
static bool do_fetch_threads = false;
static bool do_fetch_proc_file = false;
static uint32_t fetch_proc_file_pid = 0;
static uint32_t fetch_proc_file_fd = 0;
static bool do_fetch_proc_files = false;
static uint64_t fetch_proc_files_pid = 0;
static bool fetch_proc_files_with_sockets = false;
static bool do_fetch_procs_files = false;

static int32_t on_fetch_entry(void* /*context*/,
                              char* /*error*/,
                              int64_t /*tid*/,
                              scap_threadinfo* tinfo,
                              scap_fdinfo* fdinfo,
                              scap_threadinfo** new_tinfo) {
	if(!do_fetch_silently) {
		// `tinfo` and `fdinfo` are mutually exclusive: if one is NULL, the other is not.
		if(tinfo != nullptr) {
			scap_print_threadinfo(tinfo);
		} else {
			scap_print_fdinfo(fdinfo);
		}
	}

	if(new_tinfo != nullptr) {
		*new_tinfo = tinfo;
	}
	return SCAP_SUCCESS;
}

static int linux_fetch_thread(const scap_linux_platform* platform,
                              const scap_fetch_callbacks& callbacks,
                              char* error) {
	if(platform->m_linux_vtable->fetch_thread == nullptr) {
		std::cerr << "fetch_thread() not supported\n";
		return -1;
	}

	std::cout << "Calling fetch_thread(tid=" << fetch_thread_tid << ")...\n";
	scap_threadinfo* tinfo = nullptr;
	const auto rc = platform->m_linux_vtable->fetch_thread(platform->m_engine,
	                                                       &callbacks,
	                                                       fetch_thread_tid,
	                                                       &tinfo,
	                                                       error);
	if(rc == SCAP_NOT_SUPPORTED) {
		std::cerr << "fetch_thread() not supported\n";
		return -1;
	}
	if(rc != SCAP_SUCCESS) {
		std::cerr << "fetch_thread() failed (rc=" << rc << "): " << error << '\n';
		return -1;
	}
	return 0;
}

static int linux_fetch_threads(const scap_linux_platform* platform,
                               const scap_fetch_callbacks& callbacks,
                               char* error) {
	if(platform->m_linux_vtable->fetch_threads == nullptr) {
		std::cerr << "fetch_threads() not supported\n";
		return -1;
	}

	std::cout << "Calling fetch_threads()...\n";
	const auto rc = platform->m_linux_vtable->fetch_threads(platform->m_engine, &callbacks, error);
	if(rc == SCAP_NOT_SUPPORTED) {
		std::cerr << "fetch_threads() not supported\n";
		return -1;
	}
	if(rc != SCAP_SUCCESS) {
		std::cerr << "fetch_threads() failed (rc=" << rc << "): " << error << '\n';
		return -1;
	}
	return 0;
}

static int linux_fetch_proc_file(const scap_linux_platform* platform,
                                 const scap_fetch_callbacks& callbacks,
                                 char* error) {
	if(platform->m_linux_vtable->fetch_proc_file == nullptr) {
		std::cerr << "fetch_proc_file() not supported\n";
		return -1;
	}

	std::cout << "Calling fetch_proc_file(pid=" << fetch_proc_file_pid
	          << ", fd=" << fetch_proc_file_fd << ")...\n";
	const auto rc = platform->m_linux_vtable->fetch_proc_file(platform->m_engine,
	                                                          &callbacks,
	                                                          fetch_proc_file_pid,
	                                                          fetch_proc_file_fd,
	                                                          error);
	if(rc == SCAP_NOT_SUPPORTED) {
		std::cerr << "fetch_proc_file() not supported\n";
		return -1;
	}
	if(rc != SCAP_SUCCESS) {
		std::cerr << "fetch_proc_file() failed (rc=" << rc << "): " << error << '\n';
		return -1;
	}
	return 0;
}

static int linux_fetch_proc_files(const scap_linux_platform* platform,
                                  const scap_fetch_callbacks& callbacks,
                                  char* error) {
	if(platform->m_linux_vtable->fetch_proc_files == nullptr) {
		std::cerr << "fetch_proc_files() not supported\n";
		return -1;
	}

	auto* with_socket_str = fetch_proc_files_with_sockets ? "yes" : "no";
	std::cout << "Calling fetch_proc_files(pid=" << fetch_proc_files_pid
	          << ", sockets=" << with_socket_str << ")...\n";
	uint64_t num_files_fetched = 0;
	const auto rc =
	        platform->m_linux_vtable->fetch_proc_files(platform->m_engine,
	                                                   &callbacks,
	                                                   static_cast<uint32_t>(fetch_proc_files_pid),
	                                                   fetch_proc_files_with_sockets,
	                                                   &num_files_fetched,
	                                                   error);
	if(rc == SCAP_NOT_SUPPORTED) {
		std::cerr << "fetch_proc_files() not supported\n";
		return -1;
	}
	if(rc != SCAP_SUCCESS) {
		std::cerr << "fetch_proc_files() failed (rc=" << rc << "): " << error << '\n';
		return -1;
	}
	std::cout << "fetch_proc_files(...): fetched " << num_files_fetched << " file(s)\n";
	return 0;
}

static int linux_fetch_procs_files(const scap_linux_platform* platform,
                                   const scap_fetch_callbacks& callbacks,
                                   char* error) {
	if(platform->m_linux_vtable->fetch_procs_files == nullptr) {
		std::cerr << "fetch_procs_files() not supported\n";
		return -1;
	}

	std::cout << "Calling fetch_procs_files()...\n";
	const auto rc =
	        platform->m_linux_vtable->fetch_procs_files(platform->m_engine, &callbacks, error);
	if(rc == SCAP_NOT_SUPPORTED) {
		std::cerr << "fetch_procs_files() not supported\n";
		return -1;
	}
	if(rc != SCAP_SUCCESS) {
		std::cerr << "fetch_procs_files() failed (rc=" << rc << "): " << error << '\n';
		return -1;
	}
	return 0;
}

#endif  // __linux__

void add_platform_test_options(cxxopts::Options& options) {
#ifdef __linux__
	options.add_options()(
	        FETCH_OPT_FETCH_SILENTLY,
	        "(modern eBPF only) Do not print fetched resources when using --fetch-* options.")(
	        FETCH_OPT_FETCH_THREAD,
	        "(modern eBPF only) Fetch a single thread by TID via fetch_thread().",
	        cxxopts::value<int64_t>())(FETCH_OPT_FETCH_THREADS,
	                                   "(modern eBPF only) Fetch all threads via fetch_threads().")(
	        FETCH_OPT_FETCH_PROC_FILE,
	        "(modern eBPF only) Fetch a single file descriptor via fetch_proc_file() (arg: "
	        "<pid>:<fd>).",
	        cxxopts::value<std::string>())(
	        FETCH_OPT_FETCH_PROC_FILES,
	        "(modern eBPF only) Fetch all file descriptors for a process via "
	        "fetch_proc_files() (arg: <pid>).",
	        cxxopts::value<uint64_t>())(
	        FETCH_OPT_FETCH_PROC_FILES_SOCKETS,
	        "(modern eBPF only) Include sockets when using " FETCH_OPT_FETCH_PROC_FILES
	        ".")(FETCH_OPT_FETCH_PROCS_FILES,
	             "(modern eBPF only) Fetch all file descriptors for all processes via "
	             "fetch_procs_files().");
#endif  // __linux__
}

void parse_platform_test_options(const cxxopts::ParseResult& result) {
#ifdef __linux__
	if(result.count(FETCH_OPT_FETCH_SILENTLY)) {
		do_fetch_silently = true;
	}

	if(result.count(FETCH_OPT_FETCH_THREAD)) {
		fetch_thread_tid = result[FETCH_OPT_FETCH_THREAD].as<int64_t>();
		do_fetch_thread = true;
	}

	if(result.count(FETCH_OPT_FETCH_THREADS)) {
		do_fetch_threads = true;
	}

	if(result.count(FETCH_OPT_FETCH_PROC_FILE)) {
		const auto val = result[FETCH_OPT_FETCH_PROC_FILE].as<std::string>();
		const auto colon_pos = val.find(':');
		if(colon_pos == std::string::npos) {
			std::cerr << "Invalid --" FETCH_OPT_FETCH_PROC_FILE " format, expected <pid>:<fd>\n";
			exit(EXIT_FAILURE);
		}
		fetch_proc_file_pid = std::stoul(val.substr(0, colon_pos));
		fetch_proc_file_fd = std::stoul(val.substr(colon_pos + 1));
		do_fetch_proc_file = true;
	}

	if(result.count(FETCH_OPT_FETCH_PROC_FILES)) {
		fetch_proc_files_pid = result[FETCH_OPT_FETCH_PROC_FILES].as<uint64_t>();
		do_fetch_proc_files = true;
	}

	if(result.count(FETCH_OPT_FETCH_PROC_FILES_SOCKETS)) {
		fetch_proc_files_with_sockets = true;
	}

	if(result.count(FETCH_OPT_FETCH_PROCS_FILES)) {
		do_fetch_procs_files = true;
	}

	const int fetch_count = do_fetch_thread + do_fetch_threads + do_fetch_proc_file +
	                        do_fetch_proc_files + do_fetch_procs_files;
	if(fetch_count > 1) {
		std::cerr << "--" FETCH_OPT_FETCH_THREAD ", --" FETCH_OPT_FETCH_THREADS
		             ", --" FETCH_OPT_FETCH_PROC_FILE ", --" FETCH_OPT_FETCH_PROC_FILES
		             ", and --" FETCH_OPT_FETCH_PROCS_FILES " are mutually exclusive\n";
		exit(EXIT_FAILURE);
	}
#endif  // __linux__
}

#ifdef __linux__

bool should_run_linux_platform_fetch_api_tests() {
	return do_fetch_thread || do_fetch_threads || do_fetch_proc_file || do_fetch_proc_files ||
	       do_fetch_procs_files;
}

int run_linux_platform_fetch_api_tests(sinsp& inspector) {
	// TODO(ekoops): scap_platform should implement a way of determining the platform type,
	//   so that we can safely cast to the correct platform struct instead of checking that we are
	//   using the modern BPF probe.
	if(!inspector.check_current_engine(MODERN_BPF_ENGINE)) {
		std::cerr << "fetch_*() APIs are only supported with the modern BPF engine\n";
		return -1;
	}

	const auto* platform = reinterpret_cast<scap_linux_platform*>(inspector.get_scap_platform());
	if(platform == nullptr || platform->m_linux_vtable == nullptr) {
		std::cerr << "bug: Linux vtable is unexpectedly not available, something went wrong\n";
		return -1;
	}

	char error[SCAP_LASTERR_SIZE] = {};
	constexpr scap_fetch_callbacks callbacks = {on_fetch_entry, nullptr};

	if(do_fetch_thread) {
		return linux_fetch_thread(platform, callbacks, error);
	}
	if(do_fetch_threads) {
		return linux_fetch_threads(platform, callbacks, error);
	}
	if(do_fetch_proc_file) {
		return linux_fetch_proc_file(platform, callbacks, error);
	}
	if(do_fetch_proc_files) {
		return linux_fetch_proc_files(platform, callbacks, error);
	}
	if(do_fetch_procs_files) {
		return linux_fetch_procs_files(platform, callbacks, error);
	}

	return 0;
}

#endif  // __linux__
