// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libsinsp/sinsp_int.h>

class sinsp_observer
{
public:
	virtual ~sinsp_observer() {}

	virtual void on_read(sinsp_evt* evt, int64_t tid, int64_t fd, sinsp_fdinfo* fdinfo, const char *data, uint32_t original_len, uint32_t len) = 0;
	virtual void on_write(sinsp_evt* evt, int64_t tid, int64_t fd, sinsp_fdinfo* fdinfo, const char *data, uint32_t original_len, uint32_t len) = 0;
	virtual void on_sendfile(sinsp_evt* evt, int64_t fdin, uint32_t len) = 0;
	virtual void on_connect(sinsp_evt* evt, uint8_t* packed_data) = 0;
	virtual void on_accept(sinsp_evt* evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo* new_fdinfo) = 0;
	virtual void on_file_open(sinsp_evt* evt, const std::string& fullpath, uint32_t flags) = 0;
	virtual void on_error(sinsp_evt* evt) = 0;
	virtual void on_erase_fd(erase_fd_params* params) = 0;
	virtual void on_socket_shutdown(sinsp_evt *evt) = 0;
	virtual void on_execve(sinsp_evt* evt) = 0;
	virtual void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo, int64_t tid_collision) = 0;
	virtual void on_bind(sinsp_evt* evt) = 0;
	virtual bool on_resolve_container(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info) = 0;
	virtual void on_socket_status_changed(sinsp_evt *evt) = 0;
};

