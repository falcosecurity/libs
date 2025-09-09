// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <sinsp_with_test_input.h>
#include "sinsp_observer.h"

class test_observer : public sinsp_observer {
public:
	test_observer():
	        m_clone_ctr(0),
	        m_execve_ctr(0),
	        m_open_ctr(0),
	        m_read_ctr(0),
	        m_close_ctr(0) {}

	void on_read(sinsp_evt* evt,
	             int64_t tid,
	             int64_t fd,
	             sinsp_fdinfo* fdinfo,
	             const char* data,
	             uint32_t original_len,
	             uint32_t len) override {
		ASSERT_EQ(evt->get_num(), 5);
		ASSERT_EQ(fdinfo->m_fd, 4);
		ASSERT_STREQ(data, "hello");
		m_read_ctr++;
	}

	void on_write(sinsp_evt* evt,
	              int64_t tid,
	              int64_t fd,
	              sinsp_fdinfo* fdinfo,
	              const char* data,
	              uint32_t original_len,
	              uint32_t len) override {}

	void on_sendfile(sinsp_evt* evt, int64_t fdin, uint32_t len) override {}
	void on_connect(sinsp_evt* evt, uint8_t* packed_data) override {}

	void on_accept(sinsp_evt* evt,
	               int64_t newfd,
	               uint8_t* packed_data,
	               sinsp_fdinfo* new_fdinfo) override {}

	void on_file_open(sinsp_evt* evt, const std::string& fullpath, uint32_t flags) override {
		ASSERT_EQ(evt->get_num(), 4);
		ASSERT_EQ(fullpath, "/home/file.txt");
		m_open_ctr++;
	}
	void on_error(sinsp_evt* evt) override {}
	void on_erase_fd(erase_fd_params* params) override {
		ASSERT_EQ(params->m_fd, 4);
		ASSERT_EQ(params->m_tinfo->m_tid, 1);
		m_close_ctr++;
	}
	void on_socket_shutdown(sinsp_evt* evt) override {}
	void on_execve(sinsp_evt* evt) override {
		ASSERT_EQ(evt->get_num(),
		          3);  // (we create both execve enter and exit; the callback is called on the exit)
		m_execve_ctr++;
	}

	void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo, int64_t tid_collision) override {
		ASSERT_EQ(evt->get_num(), 1);  // first event created
		ASSERT_EQ(newtinfo->m_tid, 22);
		m_clone_ctr++;
	}

	void on_bind(sinsp_evt* evt) override {}

	void on_socket_status_changed(sinsp_evt* evt) override {}

	int get_clone_counter() const { return m_clone_ctr; }
	int get_execve_counter() const { return m_execve_ctr; };
	int get_open_counter() const { return m_open_ctr; }
	int get_read_counter() const { return m_read_ctr; }
	int get_close_ctr() const { return m_close_ctr; }

private:
	int m_clone_ctr;
	int m_execve_ctr;
	int m_open_ctr;
	int m_read_ctr;
	int m_close_ctr;
};

TEST_F(sinsp_with_test_input, sinsp_observer) {
	add_default_init_thread();
	open_inspector();

	test_observer observer;

	m_inspector.set_observer(&observer);

	/* clone exit event */
	generate_clone_x_event(22, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 0);
	ASSERT_EQ(observer.get_open_counter(), 0);
	ASSERT_EQ(observer.get_read_counter(), 0);
	ASSERT_EQ(observer.get_close_ctr(), 0);

	/* execve exit event */
	generate_execve_enter_and_exit_event(0, 11, 11, 11, 11);
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 1);
	ASSERT_EQ(observer.get_open_counter(), 0);
	ASSERT_EQ(observer.get_read_counter(), 0);
	ASSERT_EQ(observer.get_close_ctr(), 0);

	generate_open_x_event();
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 1);
	ASSERT_EQ(observer.get_open_counter(), 1);
	ASSERT_EQ(observer.get_read_counter(), 0);
	ASSERT_EQ(observer.get_close_ctr(), 0);

	std::string data = "hello";
	uint32_t size = data.size() + 1;  // null terminator
	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_SYSCALL_READ_X,
	                     4,
	                     (int64_t)size,
	                     scap_const_sized_buffer{data.c_str(), size},
	                     sinsp_test_input::open_params::default_fd,
	                     size);
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 1);
	ASSERT_EQ(observer.get_open_counter(), 1);
	ASSERT_EQ(observer.get_read_counter(), 1);
	ASSERT_EQ(observer.get_close_ctr(), 0);

	// Close the opened FD
	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_SYSCALL_CLOSE_X,
	                     2,
	                     (int64_t)0,
	                     sinsp_test_input::open_params::default_fd);
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 1);
	ASSERT_EQ(observer.get_open_counter(), 1);
	ASSERT_EQ(observer.get_read_counter(), 1);
	ASSERT_EQ(observer.get_close_ctr(), 1);
}
