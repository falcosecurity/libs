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
	const char data[] = "hello world";

	auto evt = create_safe_scap_event(ts,
	                                  tid,
	                                  PPME_CONTAINER_JSON_2_E,
	                                  1,
	                                  scap_const_sized_buffer{&data, strlen(data) + 1});
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
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};

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

TEST_F(convert_event_test, PPME_SYSCALL_READ_X__to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};
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
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};

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

TEST_F(convert_event_test, PPME_SYSCALL_PREAD_X__to_4_params_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};
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
	char tuple[] = {'h', 'e', 'l', 'l', 'o'};
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
