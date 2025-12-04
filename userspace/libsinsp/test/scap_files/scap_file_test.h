// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#pragma once

#include <libscap/scap.h>
#include <gtest/gtest.h>
#include <sinsp.h>
#include <libsinsp_test_var.h>

typedef std::unique_ptr<scap_evt, decltype(free)*> safe_scap_evt_t;

#define ASSERT_EVENT_PRESENCE(expected_evt) assert_event_presence(__FILE__, __LINE__, expected_evt)

class scap_file_test : public testing::Test {
private:
	static safe_scap_evt_t create_safe_scap_evt(scap_evt* evt) {
		return safe_scap_evt_t{evt, free};
	}

protected:
	void open_filename(const std::string& file_name) {
		std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + file_name;
		m_inspector = std::make_unique<sinsp>();
		m_inspector->open_savefile(path);
	}

	void assert_num_event_types(
	        const std::vector<std::pair<ppm_event_code, uint64_t>>& events_expected_counts) const {
		// Initialize the actual counters for all the expected event types to 0.
		std::unordered_map<uint16_t, uint64_t> events_actual_counts;
		events_actual_counts.reserve(events_expected_counts.size());
		for(auto& [event_type, _] : events_expected_counts) {
			events_actual_counts[event_type] = 0;
		}

		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		while(true) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret == SCAP_FILTERED_EVENT) {
				continue;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event. scap_code: " + std::to_string(ret) +
				                         ", " + m_inspector->getlasterr());
			}
			auto event_type = evt->get_type();
			if(auto it = events_actual_counts.find(event_type); it != events_actual_counts.end()) {
				it->second++;
			}
		}

		for(auto& [event_type, expected_count] : events_expected_counts) {
			ASSERT_EQ(events_actual_counts[event_type], expected_count)
			        << "Mismatching number of events for event type " << event_type;
		}
	}

	void assert_no_event_type(ppm_event_code event_type) {
		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		while(1) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret == SCAP_FILTERED_EVENT) {
				continue;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event. scap_code: " + std::to_string(ret) +
				                         ", " + m_inspector->getlasterr());
			}
			if(evt->get_type() == event_type) {
				FAIL();
			}
		}
	}

	static safe_scap_evt_t create_safe_scap_event(uint64_t ts,
	                                              uint64_t tid,
	                                              ppm_event_code event_type,
	                                              uint32_t n,
	                                              ...) {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args;
		va_start(args, n);
		scap_evt* evt = scap_create_event_v(error, ts, tid, event_type, nullptr, n, args);
		va_end(args);
		if(evt == NULL) {
			throw std::runtime_error("Error creating event: " + std::string(error));
		}
		return create_safe_scap_evt(evt);
	}

	safe_scap_evt_t create_safe_scap_event_with_empty_params(
	        uint64_t ts,
	        uint64_t tid,
	        ppm_event_code event_type,
	        scap_empty_params_set* empty_params_set,
	        uint32_t n,
	        ...) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args;
		va_start(args, n);
		scap_evt* evt = scap_create_event_v(error, ts, tid, event_type, empty_params_set, n, args);
		va_end(args);
		if(evt == NULL) {
			throw std::runtime_error("Error creating event: " + std::string(error));
		}
		return create_safe_scap_evt(evt);
	}

	void assert_event_presence(const std::string& filename,
	                           const int line_num,
	                           const safe_scap_evt_t& expected_evt) const {
		const auto prefix = filename + ':' + std::to_string(line_num) + " | ";
		sinsp_evt* evt = nullptr;
		char error[SCAP_LASTERR_SIZE]{};
		int ret = SCAP_SUCCESS;
		while(true) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret == SCAP_FILTERED_EVENT) {
				continue;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error(prefix + "Error reading event. scap_code: " +
				                         std::to_string(ret) + ", " + m_inspector->getlasterr());
			}
			if(evt->get_scap_evt()->ts == expected_evt->ts &&
			   evt->get_scap_evt()->tid == expected_evt->tid) {
				if(!scap_compare_events(evt->get_scap_evt(), expected_evt.get(), error)) {
					printf("\n%sExpected event:\n", prefix.c_str());
					scap_print_event(expected_evt.get(), PRINT_FULL);
					printf("\n%sConverted event:\n", prefix.c_str());
					scap_print_event(evt->get_scap_evt(), PRINT_FULL);
					FAIL() << prefix + error;
				}
				return;
			}
		}
		FAIL() << prefix + "There is no an event with ts: " << expected_evt->ts
		       << " and tid: " << expected_evt->tid;
	}

	sinsp_evt* capture_search_evt_by_type_and_tid(uint64_t type, int64_t tid) {
		sinsp_evt* evt;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_SUCCESS && evt->get_type() == type && evt->get_tid() == tid) {
				return evt;
			}
		}
		return NULL;
	}

	void read_until_EOF() {
		sinsp_evt* evt;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
		}
	}

	void reopen() const {
		const auto open_file_path = m_inspector->get_input_filename();
		m_inspector->close();
		m_inspector->open_savefile(open_file_path);
	}

	void kexec_arm64_assert_generic_x_final_converted_event() const;
	void kexec_arm64_assert_close_x_final_converted_event() const;
	void kexec_arm64_assert_pread_x_final_converted_event() const;
	void kexec_arm64_assert_kill_x_final_converted_event() const;
	void kexec_arm64_assert_tgkill_x_final_converted_event() const;
	void kexec_arm64_assert_getrlimit_x_final_converted_event() const;
	void kexec_arm64_assert_fcntl_x_final_converted_event() const;
	void kexec_arm64_assert_brk_x_final_converted_event() const;
	void kexec_arm64_assert_execve_x_final_converted_event() const;
	void kexec_arm64_assert_listen_x_final_converted_event() const;
	void kexec_arm64_assert_writev_x_final_converted_event() const;
	void kexec_arm64_assert_setuid_x_final_converted_event() const;
	void kexec_arm64_assert_sendto_x_final_converted_event() const;
	void kexec_arm64_assert_shutdown_x_final_converted_event() const;
	void kexec_arm64_assert_socketpair_x_final_converted_event() const;
	void kexec_arm64_assert_unshare_x_final_converted_event() const;
	void kexec_arm64_assert_fstat_x_final_converted_event() const;
	void kexec_arm64_assert_lseek_x_final_converted_event() const;
	void kexec_arm64_assert_ioctl_x_final_converted_event() const;
	void kexec_arm64_assert_munmap_x_final_converted_event() const;
	void kexec_arm64_assert_splice_x_final_converted_event() const;
	void kexec_arm64_assert_getdents64_x_final_converted_event() const;
	void kexec_arm64_assert_ppoll_x_final_converted_event() const;
	void kexec_arm64_assert_seccomp_x_final_converted_event() const;
	void kexec_arm64_assert_epoll_create1_x_final_converted_event() const;
	void kexec_arm64_assert_accept4_x_final_converted_event() const;
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
	void kexec_arm64_assert_recvfrom_x_final_converted_event() const;
	void kexec_arm64_assert_sendmsg_x_final_converted_event() const;
	void kexec_arm64_assert_recvmsg_x_final_converted_event() const;
	void kexec_arm64_assert_connect_x_final_converted_event() const;
#endif

	void kexec_x86_assert_inotify_init_x_final_converted_event() const;
	void kexec_x86_assert_setrlimit_x_final_converted_event() const;
	void kexec_x86_assert_prlimit_x_final_converted_event() const;
	void kexec_x86_assert_setresuid_x_final_converted_event() const;
	void kexec_x86_assert_epoll_wait_x_final_converted_event() const;
	void kexec_x86_assert_poll_x_final_converted_event() const;
	void kexec_x86_assert_mmap_x_final_converted_event() const;
	void kexec_x86_assert_setns_x_final_converted_event() const;
	void kexec_x86_assert_mount_x_final_converted_event() const;
	void kexec_x86_assert_access_x_final_converted_event() const;
	void kexec_x86_assert_setpgid_x_final_converted_event() const;
	void kexec_x86_assert_mprotect_x_final_converted_event() const;
	void kexec_x86_assert_setgid_x_final_converted_event() const;
	void kexec_x86_assert_setresgid_x_final_converted_event() const;
	void kexec_x86_assert_umount2_x_final_converted_event() const;

	void scap_2013_read_x_final_converted_event() const;
	void scap_2013_socket_x_final_converted_event() const;
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
	void scap_2013_accept_x_final_converted_event() const;
#endif

	void scap_2013_write_x_final_converted_event() const;

	void sample_nanosleep_x_final_converted_event() const;
	void sample_futex_x_final_converted_event() const;

	void mkdir_mkdir_x_final_converted_event() const;

	void ptrace_ptrace_x_final_converted_event() const;

	void fchdir_fchdir_x_final_converted_event() const;

	std::unique_ptr<sinsp> m_inspector;
};
