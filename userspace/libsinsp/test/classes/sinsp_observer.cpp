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
	test_observer(): clone_counter(0), execve_counter(0) {}

	void on_read(sinsp_evt* evt,
	             int64_t tid,
	             int64_t fd,
	             sinsp_fdinfo* fdinfo,
	             const char* data,
	             uint32_t original_len,
	             uint32_t len) override {}

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

	void on_file_open(sinsp_evt* evt, const std::string& fullpath, uint32_t flags) override {}
	void on_error(sinsp_evt* evt) override {}
	void on_erase_fd(erase_fd_params* params) override {}
	void on_socket_shutdown(sinsp_evt* evt) override {}
	void on_execve(sinsp_evt* evt) override { execve_counter++; }

	void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo, int64_t tid_collision) override {
		clone_counter++;
	}

	void on_bind(sinsp_evt* evt) override {}

	bool on_resolve_container(sinsp_container_manager* manager,
	                          sinsp_threadinfo* tinfo,
	                          bool query_os_for_missing_info) override {
		return true;
	}

	void on_socket_status_changed(sinsp_evt* evt) override {}

	int get_clone_counter() const { return clone_counter; }

	int get_execve_counter() const { return execve_counter; };

private:
	int clone_counter;
	int execve_counter;
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

	/* execve exit event */
	generate_execve_enter_and_exit_event(0, 11, 11, 11, 11);
	ASSERT_EQ(observer.get_clone_counter(), 1);
	ASSERT_EQ(observer.get_execve_counter(), 1);
}
