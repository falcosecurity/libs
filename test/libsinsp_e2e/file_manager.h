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

#pragma once

#include <unordered_map>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <cstdio>
#include <gtest/gtest.h>

#include <libsinsp/fdinfo.h>

struct file_spec {
	scap_fd_type fd_type;

	bool matches(const sinsp_fdinfo& fdinfo) const { return fdinfo.get_type() == fd_type; }
};

class file_counters {
	int num_files = 0;
	int num_sockets = 0;

public:
	int get_num_files() const { return num_files; }
	void add_files(const int v) { num_files += v; }
	int get_num_sockets() const { return num_sockets; }
	void add_sockets(const int v) { num_sockets += v; }
};

/**
 * @brief Opens and tracks file descriptors of various types (regular files, directories, pipes,
 * sockets, etc.), maintaining counters for files and sockets so tests can assert on the expected
 * counts.
 */
class file_manager {
	std::unordered_map<int, file_spec> files;

	file_counters counters{};
	inline static int m_name_counter = 0;

public:
	file_manager() = default;
	~file_manager() { clear(); }
	file_manager(const file_manager&) = delete;
	file_manager& operator=(const file_manager&) = delete;
	file_manager(file_manager&&) = delete;
	file_manager& operator=(file_manager&&) = delete;

	void clear() {
		for(const auto& [fd, spec] : files) {
			close(fd);
		}
		files.clear();
		counters = {};
	}

	int get_num_files() const { return counters.get_num_files(); }
	int get_num_sockets() const { return counters.get_num_sockets(); }

	const file_spec* get_file_spec(const int fd) const {
		if(const auto it = files.find(fd); it != files.cend()) {
			return &it->second;
		}
		return nullptr;
	}

	bool add_regular_file() {
		const int fd = open("/dev/null", O_RDONLY);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_FILE_V2};
		counters.add_files(1);
		return true;
	}

	bool add_directory() {
		const int fd = open("/", O_RDONLY | O_DIRECTORY);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_DIRECTORY};
		counters.add_files(1);
		return true;
	}

	bool add_pipes() {
		int p[2];
		if(pipe(p) < 0) {
			return false;
		}

		files[p[0]] = {SCAP_FD_FIFO};
		files[p[1]] = {SCAP_FD_FIFO};
		counters.add_files(2);
		return true;
	}

	bool add_event_fd() {
		const int fd = eventfd(0, 0);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_EVENT};
		counters.add_files(1);
		return true;
	}

	bool add_epoll_fd() {
		const int fd = epoll_create(1);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_EVENTPOLL};
		counters.add_files(1);
		return true;
	}

	bool add_inotify_fd() {
		const int fd = inotify_init();
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_INOTIFY};
		counters.add_files(1);
		return true;
	}

	bool add_timer_fd() {
		const int fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_TIMERFD};
		counters.add_files(1);
		return true;
	}

	bool add_signal_fd() {
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGUSR1);
		const int fd = signalfd(-1, &mask, 0);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_SIGNALFD};
		counters.add_files(1);
		return true;
	}

	bool add_mem_fd() {
		char name[32];
		snprintf(name, sizeof(name), "test_memfd_%d", m_name_counter++);
		const int fd = syscall(SYS_memfd_create, name, 0);
		if(fd < 0) {
			return false;
		}

		files[fd] = {SCAP_FD_MEMFD};
		counters.add_files(1);
		return true;
	}

	bool add_inet_listening_socket() {
		const int fd = socket(AF_INET, SOCK_STREAM, 0);
		if(fd < 0) {
			return false;
		}

		sockaddr_in sa = {};
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sa.sin_port = 0;
		if(bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) < 0 || listen(fd, 1) < 0) {
			close(fd);
			return false;
		}

		files[fd] = {SCAP_FD_IPV4_SERVSOCK};
		counters.add_sockets(1);
		return true;
	}

	bool add_inet6_listening_socket() {
		const int fd = socket(AF_INET6, SOCK_STREAM, 0);
		if(fd < 0) {
			return false;
		}

		constexpr int opt = 1;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
			close(fd);
			return false;
		}

		sockaddr_in6 sa = {};
		sa.sin6_family = AF_INET6;
		sa.sin6_addr = in6addr_loopback;
		sa.sin6_port = 0;
		if(bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) < 0 || listen(fd, 1) < 0) {
			close(fd);
			return false;
		}

		files[fd] = {SCAP_FD_IPV6_SERVSOCK};
		counters.add_sockets(1);
		return true;
	}

	bool add_unix_listening_socket() {
		const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if(fd < 0) {
			return false;
		}

		sockaddr_un sa = {};
		sa.sun_family = AF_UNIX;
		snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "test_scap_unix_%d", m_name_counter++);
		if(bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) < 0 || listen(fd, 1) < 0) {
			close(fd);
			return false;
		}

		files[fd] = {SCAP_FD_UNIX_SOCK};
		counters.add_sockets(1);
		return true;
	}

	bool add_netlink_listening_socket() {
		const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if(fd < 0) {
			return false;
		}

		sockaddr_nl sa = {};
		sa.nl_family = AF_NETLINK;
		if(bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) < 0) {
			close(fd);
			return false;
		}

		files[fd] = {SCAP_FD_NETLINK};
		counters.add_sockets(1);
		return true;
	}
};
