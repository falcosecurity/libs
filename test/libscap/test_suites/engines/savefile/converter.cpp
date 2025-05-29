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
#include "convert_event_test.h"
#include <sys/socket.h>
#include <netinet/in.h>

TEST_F(convert_event_test, conversion_not_needed) {
	uint64_t ts = 12;
	int64_t tid = 25;
	constexpr char data[] = "hello";

	auto evt = create_safe_scap_event(ts,
	                                  tid,
	                                  PPME_CONTAINER_JSON_2_E,
	                                  1,
	                                  scap_const_sized_buffer{data, sizeof(data)});
	assert_single_conversion_failure(evt);
}

////////////////////////////
// READ
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_READ_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 89;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_READ_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_READ_X_to_4_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char read_buf[] = "hello";

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               4,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               fd,
	                               size));
}

TEST_F(convert_event_test, PPME_SYSCALL_READ_X_to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char read_buf[] = "hello";
	int64_t fd = 25;
	uint32_t size = 36;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_READ_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               4,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               fd,
	                               size));
}

////////////////////////////
// PREAD
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_PREAD_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 89;
	uint64_t pos = 7;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PREAD_E, 3, fd, size, pos);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_PREAD_X_to_4_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char read_buf[] = "hello";

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t size = 0;
	int64_t pos = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PREAD_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PREAD_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               fd,
	                               size,
	                               pos));
}

TEST_F(convert_event_test, PPME_SYSCALL_PREAD_X_to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char read_buf[] = "hello";
	int64_t fd = 25;
	uint32_t size = 36;
	uint64_t pos = 7;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PREAD_E, 3, fd, size, pos);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PREAD_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PREAD_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               fd,
	                               size,
	                               pos));
}

////////////////////////////
// BIND
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_BIND_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_BIND_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_BIND_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	struct sockaddr_in sockaddr = {};
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(1234);
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Defaulted to 0
	int64_t fd = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_BIND_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{&sockaddr, sizeof(sockaddr)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_BIND_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{&sockaddr, sizeof(sockaddr)},
	                               fd));
}

TEST_F(convert_event_test, PPME_SOCKET_BIND_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	struct sockaddr_in sockaddr = {};
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(1234);
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	int64_t fd = 100;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_BIND_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_BIND_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{&sockaddr, sizeof(sockaddr)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_BIND_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{&sockaddr, sizeof(sockaddr)},
	                               fd));
}

////////////////////////////
// SOCKET
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SOCKET_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;
	uint32_t domain = 89;
	uint32_t type = 89;
	uint32_t proto = 89;

	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_E, 3, domain, type, proto);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SOCKET_X_to_4_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 23;
	uint32_t domain = 0;
	uint32_t type = 0;
	uint32_t proto = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_X, 1, fd),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_X, 4, fd, domain, type, proto));
}

TEST_F(convert_event_test, PPME_SOCKET_SOCKET_X_to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 23;
	uint32_t domain = 89;
	uint32_t type = 87;
	uint32_t proto = 86;

	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_E, 3, domain, type, proto);
	assert_single_conversion_skip(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_X, 1, fd),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_X, 4, fd, domain, type, proto));
}

////////////////////////////
// LISTEN
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_LISTEN_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	int32_t backlog = 5;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_E, 2, fd, backlog);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_LISTEN_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;

	// Defaulted to 0
	int64_t fd = 0;
	int32_t backlog = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_X, 3, res, fd, backlog));
}

TEST_F(convert_event_test, PPME_SOCKET_LISTEN_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	int32_t backlog = 5;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_E, 2, fd, backlog);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_X, 3, res, fd, backlog));
}

////////////////////////////
// ACCEPT
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_ACCEPT_E_skip) {
	uint64_t ts = 12;
	int64_t tid = 25;

	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_ACCEPT_E, 0);
	assert_single_conversion_skip(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_ACCEPT_X_to_PPME_SOCKET_ACCEPT_5_X) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	constexpr char tuple[] = "tuple";
	uint8_t queuepct = 3;

	// Defaulted to 0
	uint32_t queuelen = 0;
	uint32_t queuemax = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_ACCEPT_X,
	                               3,
	                               fd,
	                               scap_const_sized_buffer{tuple, sizeof(tuple)},
	                               queuepct),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_ACCEPT_5_X,
	                               5,
	                               fd,
	                               scap_const_sized_buffer{tuple, sizeof(tuple)},
	                               queuepct,
	                               queuelen,
	                               queuemax));
}

TEST_F(convert_event_test, PPME_SOCKET_ACCEPT_5_E_skip) {
	uint64_t ts = 12;
	int64_t tid = 25;

	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_ACCEPT_5_E, 0);
	assert_single_conversion_skip(evt);
}

////////////////////////////
// WRITE
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_WRITE_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 89;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_WRITE_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_WRITE_X_to_4_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char buf[] = "hello";

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_WRITE_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_WRITE_X,
	                               4,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)},
	                               fd,
	                               size));
}

TEST_F(convert_event_test, PPME_SYSCALL_WRITE_X_to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char buf[] = "hello";
	int64_t fd = 25;
	uint32_t size = 36;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_WRITE_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_WRITE_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_WRITE_X,
	                               4,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)},
	                               fd,
	                               size));
}

////////////////////////////
// PWRITE
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_PWRITE_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 89;
	uint64_t pos = 7;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PWRITE_E, 3, fd, size, pos);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_PWRITE_X_to_4_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char buf[] = "hello";

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t size = 0;
	int64_t pos = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PWRITE_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PWRITE_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)},
	                               fd,
	                               size,
	                               pos));
}

TEST_F(convert_event_test, PPME_SYSCALL_PWRITE_X_to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char buf[] = "hello";
	int64_t fd = 25;
	uint32_t size = 36;
	uint64_t pos = 7;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PWRITE_E, 3, fd, size, pos);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PWRITE_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PWRITE_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{buf, sizeof(buf)},
	                               fd,
	                               size,
	                               pos));
}

////////////////////////////
// SETUID
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_SETUID_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int32_t uid = 25;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_E, 1, uid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_SETUID_X_to_2_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;

	// Defaulted to 0
	uint32_t uid = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_X, 2, res, uid));
}

TEST_F(convert_event_test, PPME_SYSCALL_SETUID_X_to_2_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint32_t uid = 42;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_E, 1, uid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_X, 2, res, uid));
}

////////////////////////////
// RECV
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_RECV_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 5;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECV_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_RECV_X_to_5_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char data[] = "hello";

	// Defaulted
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECV_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECV_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{nullptr, 0}));
}

TEST_F(convert_event_test, PPME_SOCKET_RECV_X_to_5_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	constexpr char data[] = "hello";
	constexpr int32_t size = sizeof(data);

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECV_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_RECV_X,
	                                                        2,
	                                                        res,
	                                                        scap_const_sized_buffer{data, size}),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_RECV_X,
	                                                        5,
	                                                        res,
	                                                        scap_const_sized_buffer{data, size},
	                                                        fd,
	                                                        size,
	                                                        scap_const_sized_buffer{nullptr, 0}));
}

////////////////////////////
// RECVFROM
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_RECVFROM_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr uint32_t size = 5;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECVFROM_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_RECVFROM_X_to_5_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);

	// Defaulted
	constexpr int64_t defaulted_fd = 0;
	constexpr uint32_t defaulted_size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVFROM_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVFROM_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               defaulted_fd,
	                               defaulted_size));
}

TEST_F(convert_event_test, PPME_SOCKET_RECVFROM_X_to_5_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t fd = 25;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECVFROM_E, 2, fd, data_size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVFROM_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVFROM_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               fd,
	                               data_size,
	                               scap_const_sized_buffer{nullptr, 0}));
}

////////////////////////////
// SEND
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SEND_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 5;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SEND_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SEND_X_to_5_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char data[] = "hello";

	// Defaulted
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SEND_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SEND_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{nullptr, 0}));
}

TEST_F(convert_event_test, PPME_SOCKET_SEND_X_to_5_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	constexpr char data[] = "hello";
	constexpr int32_t size = sizeof(data);

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SEND_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SEND_X,
	                                                        2,
	                                                        res,
	                                                        scap_const_sized_buffer{data, size}),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SEND_X,
	                                                        5,
	                                                        res,
	                                                        scap_const_sized_buffer{data, size},
	                                                        fd,
	                                                        size,
	                                                        scap_const_sized_buffer{nullptr, 0}));
}

////////////////////////////
// SENDTO
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SENDTO_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 5;
	constexpr char tuple[] = "tuple";
	auto evt = create_safe_scap_event(ts,
	                                  tid,
	                                  PPME_SOCKET_SENDTO_E,
	                                  3,
	                                  fd,
	                                  size,
	                                  scap_const_sized_buffer{tuple, sizeof(tuple)});
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SENDTO_X_to_5_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);

	// Defaulted
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDTO_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, data_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDTO_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{nullptr, 0}));
}

TEST_F(convert_event_test, PPME_SOCKET_SENDTO_X_to_5_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	constexpr char data[] = "hello";
	constexpr int32_t size = sizeof(data);
	char tuple[] = "tuple";

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts,
	                                  tid,
	                                  PPME_SOCKET_SENDTO_E,
	                                  3,
	                                  fd,
	                                  size,
	                                  scap_const_sized_buffer{tuple, sizeof(tuple)});
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDTO_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDTO_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, size},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{tuple, sizeof(tuple)}));
}

////////////////////////////
// SHUTDOWN
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SHUTDOWN_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint8_t how = 5;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_E, 2, fd, how);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SHUTDOWN_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;

	// Defaulted
	int64_t fd = 0;
	uint8_t how = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_X, 3, res, fd, how));
}

TEST_F(convert_event_test, PPME_SOCKET_SHUTDOWN_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	int8_t how = 5;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_E, 2, fd, how);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_X, 3, res, fd, how));
}

////////////////////////////
// SOCKETPAIR
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SOCKETPAIR_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint32_t domain = AF_INET;
	uint32_t type = SOCK_STREAM;
	uint32_t protocol = IPPROTO_TCP;
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKETPAIR_E, 3, domain, type, protocol);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SOCKETPAIR_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd1 = 50;
	int64_t fd2 = 51;
	uint64_t source = 1234;
	uint64_t peer = 5678;
	// Defaulted
	uint32_t domain = 0;
	uint32_t type = 0;
	uint32_t protocol = 0;

	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SOCKETPAIR_X,
	                                                        5,
	                                                        res,
	                                                        fd1,
	                                                        fd2,
	                                                        source,
	                                                        peer),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SOCKETPAIR_X,
	                                                        8,
	                                                        res,
	                                                        fd1,
	                                                        fd2,
	                                                        source,
	                                                        peer,
	                                                        domain,
	                                                        type,
	                                                        protocol));
}

TEST_F(convert_event_test, PPME_SOCKET_SOCKETPAIR_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint32_t domain = AF_INET;
	uint32_t type = SOCK_STREAM;
	uint32_t protocol = IPPROTO_TCP;

	int64_t res = 89;
	int64_t fd1 = 50;
	int64_t fd2 = 51;
	uint64_t source = 1234;
	uint64_t peer = 5678;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKETPAIR_E, 3, domain, type, protocol);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SOCKETPAIR_X,
	                                                        5,
	                                                        res,
	                                                        fd1,
	                                                        fd2,
	                                                        source,
	                                                        peer),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SOCKET_SOCKETPAIR_X,
	                                                        8,
	                                                        res,
	                                                        fd1,
	                                                        fd2,
	                                                        source,
	                                                        peer,
	                                                        domain,
	                                                        type,
	                                                        protocol));
}

////////////////////////////
// SENDMSG
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_SENDMSG_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr uint32_t size = 5;
	constexpr char tuple[] = "tuple";
	const auto evt = create_safe_scap_event(ts,
	                                        tid,
	                                        PPME_SOCKET_SENDMSG_E,
	                                        3,
	                                        fd,
	                                        size,
	                                        scap_const_sized_buffer{tuple, sizeof(tuple)});
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_SENDMSG_X_to_5_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);

	// Defaulted
	constexpr int64_t fd = 0;
	constexpr uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDMSG_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, data_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDMSG_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, data_size},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{nullptr, 0}));
}

TEST_F(convert_event_test, PPME_SOCKET_SENDMSG_X_to_5_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t fd = 25;
	constexpr char data[] = "hello";
	constexpr int32_t size = sizeof(data);
	constexpr char tuple[] = "tuple";

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts,
	                                        tid,
	                                        PPME_SOCKET_SENDMSG_E,
	                                        3,
	                                        fd,
	                                        size,
	                                        scap_const_sized_buffer{tuple, sizeof(tuple)});
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDMSG_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{data, size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDMSG_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, size},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{tuple, sizeof(tuple)}));
}

////////////////////////////
// PTRACE
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_PTRACE_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t pid = 66;
	uint16_t request = PPM_PTRACE_PEEKSIGINFO;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PTRACE_E, 2, request, pid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_PTRACE_X_to_5_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint8_t addr[] = {'h', 'e', 'l', 'l', 'o'};
	uint8_t data[] = {'w', 'o', 'r', 'l', 'd'};

	// Defaulted to 0
	int64_t pid = 0;
	uint16_t request = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PTRACE_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{addr, sizeof(addr)},
	                               scap_const_sized_buffer{data, sizeof(data)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PTRACE_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{addr, sizeof(addr)},
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               request,
	                               pid));
}

TEST_F(convert_event_test, PPME_SYSCALL_PTRACE_X_to_5_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t pid = 66;
	uint16_t request = PPM_PTRACE_PEEKSIGINFO;
	uint8_t addr[] = {'h', 'e', 'l', 'l', 'o'};
	uint8_t data[] = {'w', 'o', 'r', 'l', 'd'};

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_PTRACE_E, 2, request, pid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PTRACE_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{addr, sizeof(addr)},
	                               scap_const_sized_buffer{data, sizeof(data)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_PTRACE_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{addr, sizeof(addr)},
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               request,
	                               pid));
}
