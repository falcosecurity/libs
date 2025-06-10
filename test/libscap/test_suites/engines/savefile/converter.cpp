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
#include <driver/ppm_flag_helpers.h>

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

////////////////////////////
// LSEEK
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_LSEEK_E_store) {
	uint64_t ts = 15;
	int64_t tid = 30;

	int64_t fd = 3;
	uint64_t offset = 1024;
	uint8_t whence = SEEK_SET;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_LSEEK_E, 3, fd, offset, whence);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_LSEEK_X_to_4_params_no_enter) {
	uint64_t ts = 15;
	int64_t tid = 30;

	int64_t res = 1024;

	// Defaulted values if enter event is missing
	int64_t fd = 0;
	uint64_t offset = 0;
	uint8_t whence = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LSEEK_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LSEEK_X, 4, res, fd, offset, whence));
}

TEST_F(convert_event_test, PPME_SYSCALL_LSEEK_X_to_4_params_with_enter) {
	uint64_t ts = 15;
	int64_t tid = 30;

	int64_t res = 1024;
	int64_t fd = 3;
	uint64_t offset = 1024;
	uint8_t whence = SEEK_SET;

	// Store the enter event first
	auto evt_e = create_safe_scap_event(ts,
	                                    tid,
	                                    PPME_SYSCALL_LSEEK_E,
	                                    3,
	                                    fd,
	                                    offset,
	                                    lseek_whence_to_scap(whence));
	assert_single_conversion_skip(evt_e);
	assert_event_storage_presence(evt_e);

	// Then convert the exit event
	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts, tid, PPME_SYSCALL_LSEEK_X, 1, res),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SYSCALL_LSEEK_X,
	                                                        4,
	                                                        res,
	                                                        fd,
	                                                        offset,
	                                                        lseek_whence_to_scap(whence)));
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

TEST_F(convert_event_test, PPME_SOCKET_SOCKETPAIR_X_to_8_params_no_enter) {
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

TEST_F(convert_event_test, PPME_SOCKET_SOCKETPAIR_X_to_8_params_with_enter) {
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
// RECVMSG
////////////////////////////

TEST_F(convert_event_test, PPME_SOCKET_RECVMSG_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECVMSG_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SOCKET_RECVMSG_X_4_to_5_params) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint32_t size = res;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_CONTINUE,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               4,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               5,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               scap_const_sized_buffer{nullptr, 0}));
}

TEST_F(convert_event_test, PPME_SOCKET_RECVMSG_X_5_to_6_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint32_t size = res;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);
	constexpr uint8_t msgcontrol[] = {1, 2, 3, 4};
	constexpr int32_t msgcontrol_size = sizeof(msgcontrol);

	// Defaulted
	constexpr int64_t fd = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               5,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               scap_const_sized_buffer{msgcontrol, msgcontrol_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               6,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               scap_const_sized_buffer{msgcontrol, msgcontrol_size},
	                               fd));
}

TEST_F(convert_event_test, PPME_SOCKET_RECVMSG_X_5_to_6_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr int64_t res = 89;
	constexpr uint32_t size = res;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);
	constexpr uint8_t msgcontrol[] = {1, 2, 3, 4};
	constexpr int32_t msgcontrol_size = sizeof(msgcontrol);

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECVMSG_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               5,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               scap_const_sized_buffer{msgcontrol, msgcontrol_size}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               6,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, data_size},
	                               scap_const_sized_buffer{tuple, tuple_size},
	                               scap_const_sized_buffer{msgcontrol, msgcontrol_size},
	                               fd));
}

TEST_F(convert_event_test, PPME_SOCKET_RECVMSG_X_4_to_6_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr int64_t res = 89;
	constexpr uint32_t size = res;
	constexpr char data[] = "hello";
	constexpr int32_t data_size = sizeof(data);
	constexpr char tuple[] = "tuple";
	constexpr int32_t tuple_size = sizeof(tuple);

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SOCKET_RECVMSG_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_full_conversion(create_safe_scap_event(ts,
	                                              tid,
	                                              PPME_SOCKET_RECVMSG_X,
	                                              4,
	                                              res,
	                                              size,
	                                              scap_const_sized_buffer{data, data_size},
	                                              scap_const_sized_buffer{tuple, tuple_size}),
	                       create_safe_scap_event(ts,
	                                              tid,
	                                              PPME_SOCKET_RECVMSG_X,
	                                              6,
	                                              res,
	                                              size,
	                                              scap_const_sized_buffer{data, data_size},
	                                              scap_const_sized_buffer{tuple, tuple_size},
	                                              scap_const_sized_buffer{nullptr, 0},
	                                              fd));
}

////////////////////////////
// EVENTFD
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_EVENTFD_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr uint64_t initval = 10;
	constexpr uint32_t flags = 15;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_E, 2, initval, flags);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_EVENTFD_X_to_3_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr uint64_t initval = 0;
	constexpr uint32_t flags = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_X, 3, res, initval, flags));
}

TEST_F(convert_event_test, PPME_SYSCALL_EVENTFD_X_to_3_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint64_t initval = 10;
	constexpr uint32_t flags = 15;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_E, 2, initval, flags);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EVENTFD_X, 3, res, initval, flags));
}

////////////////////////////
// FUTEX
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_FUTEX_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr uint64_t addr = 10;
	constexpr uint16_t op = 15;
	constexpr uint64_t val = 20;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_E, 3, addr, op, val);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_FUTEX_X_to_4_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr uint64_t addr = 0;
	constexpr uint16_t op = 0;
	constexpr uint64_t val = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_X, 4, res, addr, op, val));
}

TEST_F(convert_event_test, PPME_SYSCALL_FUTEX_X_to_4_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint64_t addr = 10;
	constexpr uint16_t op = 15;
	constexpr uint64_t val = 20;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_E, 3, addr, op, val);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_X, 4, res, addr, op, val));
}

////////////////////////////
// FSTAT
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_FSTAT_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_FSTAT_X_to_2_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr int64_t fd = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_X, 4, res, fd));
}

TEST_F(convert_event_test, PPME_SYSCALL_FSTAT_X_to_2_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t fd = 25;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_E, 1, fd);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FSTAT_X, 4, res, fd));
}

////////////////////////////
// EPOLL_WAIT
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_EPOLLWAIT_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t maxevents = 10;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_E, 1, maxevents);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_EPOLLWAIT_X_to_2_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr int64_t maxevents = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_X, 2, res, maxevents));
}

TEST_F(convert_event_test, PPME_SYSCALL_EPOLLWAIT_X_to_2_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t maxevents = 10;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_E, 1, maxevents);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_X, 2, res, maxevents));
}

////////////////////////////
// POLL
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_POLL_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr uint8_t fds[] = {0x1, 0x0, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};
	constexpr int64_t timeout = 1000;
	const auto evt = create_safe_scap_event(ts,
	                                        tid,
	                                        PPME_SYSCALL_POLL_E,
	                                        2,
	                                        scap_const_sized_buffer{fds, sizeof(fds)},
	                                        timeout);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_POLL_X_to_3_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint8_t fds[] = {0x1, 0x0, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};

	// Defaulted
	constexpr int64_t timeout = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_POLL_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{fds, sizeof(fds)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_POLL_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{fds, sizeof(fds)},
	                               timeout));
}

TEST_F(convert_event_test, PPME_SYSCALL_POLL_X_to_3_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr uint8_t fds[] = {0x1, 0x0, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};
	constexpr int64_t timeout = 1000;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts,
	                                        tid,
	                                        PPME_SYSCALL_POLL_E,
	                                        2,
	                                        scap_const_sized_buffer{fds, sizeof(fds)},
	                                        timeout);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_POLL_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{fds, sizeof(fds)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_POLL_X,
	                               3,
	                               res,
	                               scap_const_sized_buffer{fds, sizeof(fds)},
	                               timeout));
}

////////////////////////////
// LLSEEK
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_LLSEEK_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr uint64_t offset = 1234;
	constexpr uint8_t whence = 100;
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_E, 3, fd, offset, whence);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_LLSEEK_X_to_4_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr int64_t fd = 0;
	constexpr uint64_t offset = 0;
	constexpr uint8_t whence = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_X, 4, res, fd, offset, whence));
}

TEST_F(convert_event_test, PPME_SYSCALL_LLSEEK_X_to_4_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t fd = 25;
	constexpr uint64_t offset = 1234;
	constexpr uint8_t whence = 100;

	// After the first conversion we should have the storage
	const auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_E, 3, fd, offset, whence);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_LLSEEK_X, 4, res, fd, offset, whence));
}

////////////////////////////
// IOCTL
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_IOCTL_3_E_store) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t fd = 25;
	constexpr uint64_t request = 1234;
	constexpr uint64_t argument = 100;
	const auto evt =
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_E, 3, fd, request, argument);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_IOCTL_3_X_to_4_params_no_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;

	// Defaulted
	constexpr int64_t fd = 0;
	constexpr uint64_t request = 0;
	constexpr uint64_t argument = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_X, 4, res, fd, request, argument));
}

TEST_F(convert_event_test, PPME_SYSCALL_IOCTL_3_X_to_4_params_with_enter) {
	constexpr uint64_t ts = 12;
	constexpr int64_t tid = 25;

	constexpr int64_t res = 89;
	constexpr int64_t fd = 25;
	constexpr uint64_t request = 1234;
	constexpr uint64_t argument = 100;

	// After the first conversion we should have the storage
	const auto evt =
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_E, 3, fd, request, argument);

	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_X, 4, res, fd, request, argument));
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

////////////////////////////
// MKDIR
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_MKDIR_2_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint32_t mode = 0755;  // Default mode for mkdir

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_E, 1, mode);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_MKDIR_2_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char path[] = "/hello";

	// Defaulted to 0
	uint32_t mode = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_X, 2, res, path),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_X, 3, res, path, mode));
}

TEST_F(convert_event_test, PPME_SYSCALL_MKDIR_2_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	constexpr char path[] = "/hello";
	uint32_t mode = 0755;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_E, 1, mode);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_X, 2, res, path),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_X, 3, res, path, mode));
}

////////////////////////////
// SETNS
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_SETNS_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t flags = CLONE_NEWNET;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_E, 2, fd, flags);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_SETNS_1_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t flags = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_X, 3, res, fd, flags));
}

TEST_F(convert_event_test, PPME_SYSCALL_SETNS_1_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t fd = 25;
	uint32_t flags = CLONE_NEWNET;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_E, 2, fd, flags);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_X, 3, res, fd, flags));
}

////////////////////////////
// FCHDIR
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_FCHDIR_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 66;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_FCHDIR_X_to_2_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = -1;

	// Defaulted to 0
	int64_t fd = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_X, 2, res, fd));
}

TEST_F(convert_event_test, PPME_SYSCALL_FCHDIR_X_to_2_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = -1;
	int64_t fd = 66;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_E, 1, fd);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_X, 2, res, fd));
}

////////////////////////////
// SETPGID
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_SETPGID_E_store) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t pid = 66;
	int64_t pgid = 100;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_E, 2, pid, pgid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);
}

TEST_F(convert_event_test, PPME_SYSCALL_SETPGID_X_to_3_params_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;

	// Defaulted to 0
	int64_t pid = 0;
	int64_t pgid = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_X, 3, res, pid, pgid));
}

TEST_F(convert_event_test, PPME_SYSCALL_SETPGID_X_to_3_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	int64_t pid = 66;
	int64_t pgid = 100;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_E, 2, pid, pgid);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(evt);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_X, 1, res),
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_X, 3, res, pid, pgid));
}
