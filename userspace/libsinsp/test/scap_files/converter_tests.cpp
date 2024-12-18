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

#include <scap_files/scap_file_test.h>

// Use `sudo sysdig -r <scap-file> -S -q` to check the number of events in the scap file.
// When you find a specific event to assert use
// `sudo sysdig -r <> -d "evt.num =<>" -p "ts=%evt.rawtime,tid=%thread.tid,args=%evt.arg.args"`

////////////////////////////
// READ
////////////////////////////

TEST_F(scap_file_test, read_e_same_number_of_events) {
	open_filename("scap_2013.scap");
	assert_num_event_type(PPME_SYSCALL_READ_E, 24956);
}

TEST_F(scap_file_test, read_x_same_number_of_events) {
	open_filename("scap_2013.scap");
	assert_num_event_type(PPME_SYSCALL_READ_X, 24957);
}

TEST_F(scap_file_test, read_x_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `430682` is the following:
	// - type=PPME_SYSCALL_READ_X
	// - ts=1380933088076148247
	// - tid=44106
	// - args=res=270 data=HTTP/1.1 302 Found\0Date: Sat, 05 Oct 2013 00:31:28 GMT\0Server:
	// Apache/2.4.4 (U
	//
	// And its corresponding enter event `430681` is the following:
	// - type=PPME_SYSCALL_READ_E
	// - ts=1380933088076145348
	// - tid=44106,
	// - args=fd=33(<4t>127.0.0.1:38308->127.0.0.1:80) size=8192
	//
	// Let's see the new PPME_SYSCALL_READ_X event!
	uint64_t ts = 1380933088076148247;
	int64_t tid = 44106;
	int64_t res = 270;
	// this is NULL termiinated so we have 81 bytes but in the scap-file we want only 80 bytes
	// without the NULL terminator
	char read_buf[] = {
	        "HTTP/1.1 302 Found\r\nDate: Sat, 05 Oct 2013 00:31:28 GMT\r\nServer: Apache/2.4.4 "
	        "(U"};
	int64_t fd = 33;
	uint32_t size = 8192;
	assert_event_presence(
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               4,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf) - 1},
	                               fd,
	                               size));
}

////////////////////////////
// PREAD
////////////////////////////

TEST_F(scap_file_test, pread_e_same_number_of_events) {
	open_filename("kexec_arm64.scap");
	assert_num_event_type(PPME_SYSCALL_PREAD_E, 3216);
}

TEST_F(scap_file_test, pread_x_same_number_of_events) {
	open_filename("kexec_arm64.scap");
	assert_num_event_type(PPME_SYSCALL_PREAD_X, 3216);
}

TEST_F(scap_file_test, pread_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `862450` is the following:
	// - type=PPME_SYSCALL_PREAD_X,
	// - ts=1687966733234634809
	// - tid=552
	// - args=res=400
	// data=...._...tty1............................tty1LOGIN...............................
	//
	// And its corresponding enter event `862449` is the following:
	// - type=PPME_SYSCALL_PREAD_E
	// - ts=1687966733234634235
	// - tid=552
	// - args=fd=19(<f>/var/run/utmp) size=400 pos=800
	//
	// Let's see the new PPME_SYSCALL_PREAD_X event!
	uint64_t ts = 1687966733234634809;
	int64_t tid = 552;
	int64_t res = 400;
	uint8_t read_buf[] = {6,   0, 0, 0, '_', 2, 0, 0, 't', 't', 'y', '1', 0,   0,   0,   0,
	                      0,   0, 0, 0, 0,   0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0,
	                      0,   0, 0, 0, 0,   0, 0, 0, 't', 't', 'y', '1', 'L', 'O', 'G', 'I',
	                      'N', 0, 0, 0, 0,   0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0,
	                      0,   0, 0, 0, 0,   0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0};
	int64_t fd = 19;
	uint32_t size = 400;
	int64_t pos = 800;
	assert_event_presence(
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
// SOCKET
////////////////////////////

TEST_F(scap_file_test, socket_x_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `515881` is the following:
	// - type=PPME_SOCKET_SOCKET_E
	// - ts=1380933088295478275
	// - tid=44106
	// - args=domain=2(AF_INET) type=524289 proto=0
	//
	// And its corresponding enter event `511520` is the following:
	// - type=PPME_SOCKET_SOCKET_X
	// - ts=1380933088295552884
	// - tid=44106,
	// - args=fd=19(<4>)
	//
	uint64_t ts = 1380933088295552884;
	int64_t tid = 44106;
	int64_t fd = 19;
	uint32_t domain = 2;
	uint32_t type = 524289;
	uint32_t proto = 0;

	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SOCKET_SOCKET_X, 4, fd, domain, type, proto));
}

////////////////////////////
// LISTEN
////////////////////////////

TEST_F(scap_file_test, listen_e_same_number_of_events) {
	open_filename("kexec_arm64.scap");
	assert_num_event_type(PPME_SOCKET_LISTEN_E, 1);
}

TEST_F(scap_file_test, listen_x_same_number_of_events) {
	open_filename("kexec_arm64.scap");
	assert_num_event_type(PPME_SOCKET_LISTEN_X, 1);
}

TEST_F(scap_file_test, listen_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `57008` is the following:
	// - type=PPME_SOCKET_LISTEN_X,
	// - ts=1687966709944348874
	// - tid=141291
	// - args=res=0
	//
	// And its corresponding enter event `57007` is the following:
	// - type=PPME_SOCKET_LISTEN_E
	// - ts=1687966709944347577
	// - tid=141291
	// - args=fd=25(<u>/tmp/pty1908604488/pty.sock)
	// - backlog=4096
	//
	// Let's see the new PPME_SOCKET_LISTEN_X event!

	uint64_t ts = 1687966709944348874;
	int64_t tid = 141291;
	int64_t res = 0;
	int64_t fd = 25;
	int32_t backlog = 4096;
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SOCKET_LISTEN_X, 3, res, fd, backlog));
}
