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

#include <test_utils.h>
#include <scap_files/scap_file_test.h>

// Use `sudo sysdig -r <scap-file> -S -q` to check the number of events in the scap file.
// When you find a specific event to assert use
// `sudo sysdig -r <> -d "evt.num=<>" -p "ts=%evt.rawtime, tid=%thread.tid, args=%evt.args"`

TEST_F(scap_file_test, same_number_of_events) {
	open_filename("scap_2013.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_READ_E, 24956},
	        {PPME_SYSCALL_READ_X, 24957},
	        {PPME_SOCKET_ACCEPT_E, 3817},
	        {PPME_SOCKET_ACCEPT_5_X, 3816},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("kexec_arm64.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_PREAD_E, 3216},    {PPME_SYSCALL_PREAD_X, 3216},
	        {PPME_SOCKET_LISTEN_E, 1},       {PPME_SOCKET_LISTEN_X, 1},
	        {PPME_SYSCALL_SETUID_E, 2},      {PPME_SYSCALL_SETUID_X, 2},
	        {PPME_SOCKET_RECVFROM_E, 82},    {PPME_SOCKET_RECVFROM_X, 82},
	        {PPME_SOCKET_SENDTO_E, 162},     {PPME_SOCKET_SENDTO_X, 162},
	        {PPME_SOCKET_SHUTDOWN_E, 9},     {PPME_SOCKET_SHUTDOWN_X, 9},
	        {PPME_SOCKET_SOCKETPAIR_E, 114}, {PPME_SOCKET_SOCKETPAIR_X, 114},
	        {PPME_SOCKET_SENDMSG_E, 26},     {PPME_SOCKET_SENDMSG_X, 26},
	        {PPME_SOCKET_RECVMSG_E, 522},    {PPME_SOCKET_RECVMSG_X, 522},
	        {PPME_SYSCALL_IOCTL_3_E, 1164},  {PPME_SYSCALL_IOCTL_3_X, 1164},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("kexec_x86.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_EPOLLWAIT_E, 2051},
	        {PPME_SYSCALL_EPOLLWAIT_X, 2051},
	        {PPME_SYSCALL_POLL_E, 2682},
	        {PPME_SYSCALL_POLL_X, 2683},
	        {PPME_SYSCALL_SETNS_E, 5},
	        {PPME_SYSCALL_SETNS_X, 5},
	        {PPME_SYSCALL_SETPGID_E, 4},
	        {PPME_SYSCALL_SETPGID_X, 4},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("ptrace.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_PTRACE_E, 3},
	        {PPME_SYSCALL_PTRACE_X, 3},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("mkdir.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_MKDIR_2_E, 1},
	        {PPME_SYSCALL_MKDIR_2_X, 1},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("sample.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_FUTEX_E, 15},
	        {PPME_SYSCALL_FUTEX_X, 15},
	        // Add further checks regarding the expected number of events in this scap file here.
	});

	open_filename("fchdir.scap");
	assert_num_event_types({
	        {PPME_SYSCALL_FCHDIR_E, 1},
	        {PPME_SYSCALL_FCHDIR_X, 1},
	        // Add further checks regarding the expected number of events in this scap file here.
	});
	// Add further checks for the expected number of events in unhandled scap files here.
}

////////////////////////////
// READ
////////////////////////////

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
	// - args=fd=25(<u>/tmp/pty1908604488/pty.sock) backlog=4096
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

////////////////////////////
// ACCEPT
////////////////////////////

// Compile out this test if test_utils helpers are not defined.
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(scap_file_test, accept_x_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `519217` is the following:
	// - type=PPME_SOCKET_ACCEPT_X,
	// - ts=1380933088302022447
	// - tid=43625
	// - args=fd=13(<4t>127.0.0.1:38873->127.0.0.1:80) tuple=127.0.0.1:38873->127.0.0.1:80
	// queuepct=37 queuepct=37
	//
	// And its corresponding enter event `519211` is the following:
	// - type=PPME_SOCKET_ACCEPT_E
	// - ts=1380933088302013474
	// - tid=43625
	// - args=
	//
	// Let's see the new PPME_SOCKET_ACCEPT_5_X event!

	uint64_t ts = 1380933088302022447;
	int64_t tid = 43625;
	int64_t fd = 13;
	sockaddr_in client_sockaddr = test_utils::fill_sockaddr_in(38873, "127.0.0.1");
	sockaddr_in server_sockaddr = test_utils::fill_sockaddr_in(80, "127.0.0.1");
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	int32_t queuepct = 37;
	int32_t queuelen = 0;
	int32_t queuemax = 0;
	assert_event_presence(
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_ACCEPT_5_X,
	                               5,
	                               fd,
	                               scap_const_sized_buffer{tuple.data(), tuple.size()},
	                               queuepct,
	                               queuelen,
	                               queuemax));
}
#endif

////////////////////////////
// WRITE
////////////////////////////

TEST_F(scap_file_test, write_x_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `511534` is the following:
	// - type=PPME_SYSCALL_WRITE_X
	// - ts=1380933088286397273
	// - tid=44106
	// - args=res=77 data=GET / HTTP/1.0..Host: 127.0.0.1..User-Agent: ApacheBench/2.3..Accept:
	// */*...
	//
	// And its corresponding enter event `511520` is the following:
	// - type=PPME_SYSCALL_WRITE_E
	// - ts=1380933088286362703
	// - tid=44106,
	// - args=fd=13(<4t>127.0.0.1:38904->127.0.0.1:80) size=77
	//
	uint64_t ts = 1380933088286397273;
	int64_t tid = 44106;
	int64_t res = 77;
	// this is NULL termiinated so we have 81 bytes but in the scap-file we want only 80 bytes
	// without the NULL terminator
	char buf[] = {
	        "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: ApacheBench/2.3\r\nAccept: "
	        "*/*\r\n\r\n"};
	int64_t fd = 13;
	uint32_t size = 77;
	assert_event_presence(create_safe_scap_event(ts,
	                                             tid,
	                                             PPME_SYSCALL_WRITE_X,
	                                             4,
	                                             res,
	                                             scap_const_sized_buffer{buf, sizeof(buf) - 1},
	                                             fd,
	                                             size));
}

////////////////////////////
// PWRITE
////////////////////////////

// We don't have scap-files with PWRITE events. Add it if we face a failure.

////////////////////////////
// SETUID
////////////////////////////

TEST_F(scap_file_test, setuid_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `61288` is the following:
	// - type=PPME_SYSCALL_SETUID_X,
	// - ts=1687966709959025387
	// - tid=141446
	// - args=res=0
	//
	// And its corresponding enter event `61285` is the following:
	// - type=PPME_SYSCALL_SETUID_E
	// - ts=1687966709959015344
	// - tid=141446
	// - args=uid=0(<NA>)
	//
	// Let's see the new PPME_SYSCALL_SETUID_X event!

	uint64_t ts = 1687966709959025387;
	int64_t tid = 141446;
	int64_t res = 0;
	int32_t uid = 0;
	assert_event_presence(create_safe_scap_event(ts, tid, PPME_SYSCALL_SETUID_X, 2, res, uid));
}

////////////////////////////
// RECV
////////////////////////////

// We don't have scap-files with RECV events. Add it if we face a failure.

////////////////////////////
// RECVFROM
////////////////////////////

// Compile out this test if test_utils helpers are not defined.
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(scap_file_test, recvfrom_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `593051` is the following:
	// - type=PPME_SOCKET_RECVFROM_X,
	// - ts=1687966725502692767
	// - tid=141633
	// - args=res=89 data=.............ip-172-31-24-0.eu-central-1.compute.internal..............,..
	//   ...... tuple=127.0.0.53:53->127.0.0.1:47288
	//
	// And its corresponding enter event `593050` is the following:
	// - type=PPME_SOCKET_RECVFROM_E
	// - ts=1687966725502689763
	// - args=fd=6(<4u>127.0.0.1:47288->127.0.0.53:53) size=2048
	//
	// Let's see the new PPME_SOCKET_RECVFROM_X event!

	constexpr uint64_t ts = 1687966725502692767;
	constexpr int64_t tid = 141633;
	constexpr int64_t res = 89;
	constexpr uint8_t data[] = {
	        0xe5, 0xa9, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 'i',
	        'p',  '-',  '1',  '7',  '2',  '-',  '3',  '1',  '-',  '2',  '4',  '-',  '0',  0x0c,
	        'e',  'u',  '-',  'c',  'e',  'n',  't',  'r',  'a',  'l',  '-',  '1',  0x07, 'c',
	        'o',  'm',  'p',  'u',  't',  'e',  0x08, 'i',  'n',  't',  'e',  'r',  'n',  'a',
	        'l',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	        0x00, ',',  0x00, 0x04, 0xac, 0x1f, 0x18, 0x00, 0x00, 0x00};
	sockaddr_in client_sockaddr = test_utils::fill_sockaddr_in(53, "127.0.0.53");
	sockaddr_in server_sockaddr = test_utils::fill_sockaddr_in(47288, "127.0.0.1");
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	constexpr int64_t fd = 6;
	constexpr int32_t size = 2048;
	assert_event_presence(
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVFROM_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               scap_const_sized_buffer{tuple.data(), tuple.size()},
	                               fd,
	                               size));
}
#endif

////////////////////////////
// SEND
////////////////////////////

// We don't have scap-files with SEND events. Add it if we face a failure.

////////////////////////////
// SENDTO
////////////////////////////

TEST_F(scap_file_test, sendto_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `857231` is the following:
	// - type=PPME_SOCKET_SENDTO_X
	// - ts=1687966733172651252
	// - tid=114093
	// - args=res=17 data="\x11\x0\x0\x0\x16\x0\x1\x3\x1\x0\x0\x0\x0\x0\x0\x0"
	//
	// And its corresponding enter event `857230` is the following:
	// - type=PPME_SOCKET_SENDTO_E
	// - ts=1687966733172634128
	// - tid=114093
	// - args=fd=22(<n>) size=17 tuple=NULL
	//
	// Let's see the new PPME_SOCKET_SENDTO_X event!

	uint64_t ts = 1687966733172651252;
	int64_t tid = 114093;
	int64_t res = 17;
	constexpr char data[] = "\x11\x0\x0\x0\x16\x0\x1\x3\x1\x0\x0\x0\x0\x0\x0\x0";
	constexpr uint32_t size = sizeof(data);
	int64_t fd = 22;
	assert_event_presence(create_safe_scap_event(ts,
	                                             tid,
	                                             PPME_SOCKET_SENDTO_X,
	                                             5,
	                                             res,
	                                             scap_const_sized_buffer{data, size},
	                                             fd,
	                                             size,
	                                             scap_const_sized_buffer{nullptr, 0}));
}

////////////////////////////
// SHUTDOWN
////////////////////////////
TEST_F(scap_file_test, shutdown_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `861764` is the following:
	// - type=PPME_SOCKET_SHUTDOWN_X
	// - ts=1687966733231918487
	// - tid=112954
	// - args=res=-107(ENOTCONN)
	//
	// And its corresponding enter event `861763` is the following:
	// - type=PPME_SOCKET_SHUTDOWN_E
	// - ts=1687966733231918028
	// - tid=112954
	// - args=fd=13(<4t>127.0.0.1:33566->127.0.0.1:42891) how=1(SHUT_WR)
	//
	// Let's see the new PPME_SOCKET_SHUTDOWN_X event!

	uint64_t ts = 1687966733231918487;
	int64_t tid = 112954;
	int64_t res = -107;
	int64_t fd = 13;
	uint8_t how = 1;
	assert_event_presence(create_safe_scap_event(ts, tid, PPME_SOCKET_SHUTDOWN_X, 3, res, fd, how));
}

////////////////////////////
// SOCKETPAIR
////////////////////////////

TEST_F(scap_file_test, socketpair_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `839802` is the following:
	// - type=PPME_SOCKET_SOCKETPAIR_X
	// - ts=1687966732709347847
	// - tid=118552
	// - args=res=0 fd1=28(<u>) fd2=29(<u>) source=FFFF0003C2F15C00 peer=FFFF0003C2F16C00
	//
	// And its corresponding enter event `839801` is the following:
	// - type=PPME_SOCKET_SOCKETPAIR_E
	// - ts=1687966732709343195
	// - tid=118552
	// - args=domain=1(AF_LOCAL|AF_UNIX) type=524289 proto=0
	//
	// Let's see the new PPME_SOCKET_SOCKETPAIR_X event!

	constexpr uint64_t ts = 1687966732709347847;
	constexpr int64_t tid = 118552;
	constexpr int64_t res = 0;
	constexpr int64_t fd1 = 28;
	constexpr int64_t fd2 = 29;
	constexpr uint64_t source = 0xFFFF0003C2F15C00;
	constexpr uint64_t peer = 0xFFFF0003C2F16C00;
	constexpr uint32_t domain = AF_UNIX;
	constexpr uint32_t type = 524289;
	constexpr uint32_t proto = 0;
	assert_event_presence(create_safe_scap_event(ts,
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
	                                             proto));
}

////////////////////////////
// SENDMSG
////////////////////////////

// Compile out this test if test_utils helpers are not defined.
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(scap_file_test, sendmsg_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `593037` is the following:
	// - type=PPME_SOCKET_SENDMSG_X
	// - ts=1687966725502664007
	// - tid=493
	// - args=res=89
	// data=.............ip-172-31-24-0.eu-central-1.compute.internal..............,........
	//
	// And its corresponding enter event `593036` is the following:
	// - type=PPME_SOCKET_SENDMSG_E
	// - ts=1687966725502632237
	// - tid=493
	// - args=fd=13(<4u>127.0.0.1:47288->127.0.0.53:53) size=89 tuple=127.0.0.53:53->127.0.0.1:47288
	//
	// Let's see the new PPME_SOCKET_SENDMSG_X event!

	constexpr uint64_t ts = 1687966725502664007;
	constexpr int64_t tid = 493;

	constexpr int64_t res = 89;
	constexpr uint8_t data[] = {
	        0xe5, 0xa9, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 'i',
	        'p',  '-',  '1',  '7',  '2',  '-',  '3',  '1',  '-',  '2',  '4',  '-',  '0',  0x0c,
	        'e',  'u',  '-',  'c',  'e',  'n',  't',  'r',  'a',  'l',  '-',  '1',  0x07, 'c',
	        'o',  'm',  'p',  'u',  't',  'e',  0x08, 'i',  'n',  't',  'e',  'r',  'n',  'a',
	        'l',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	        0x00, ',',  0x00, 0x04, 0xac, 0x1f, 0x18, 0x00, 0x00, 0x00};
	constexpr int64_t fd = 13;
	constexpr int32_t size = 89;
	sockaddr_in client_sockaddr = test_utils::fill_sockaddr_in(53, "127.0.0.53");
	sockaddr_in server_sockaddr = test_utils::fill_sockaddr_in(47288, "127.0.0.1");
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	assert_event_presence(
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_SENDMSG_X,
	                               5,
	                               res,
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               fd,
	                               size,
	                               scap_const_sized_buffer{tuple.data(), tuple.size()}));
}
#endif

////////////////////////////
// RECVMSG
////////////////////////////

// Compile out this test if test_utils helpers are not defined.
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(scap_file_test, recvmsg_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `593019` is the following:
	// - type=PPME_SOCKET_RECVMSG_X
	// - ts=1687966725502520629
	// - tid=493
	// args=res=73 size=73 data=...
	// .........ip-172-31-24-0.eu-central-1.compute.internal.......)........
	// tuple=127.0.0.1:47288->127.0.0.53:53
	//
	// And its corresponding enter event `593018` is the following:
	// - type=PPME_SOCKET_RECVMSG_E
	// - ts=1687966725502515632
	// - tid=493
	// - args=fd=13(<4u>127.0.0.1:40646->127.0.0.53:53)
	//
	// Let's see the new PPME_SOCKET_RECVMSG_X event!

	constexpr uint64_t ts = 1687966725502520629;
	constexpr int64_t tid = 493;

	constexpr int64_t res = 73;
	constexpr int32_t size = res;
	constexpr uint8_t data[] = {0xe5, 0xa9, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	                            0x01, 0x0e, 'i',  'p',  '-',  '1',  '7',  '2',  '-',  '3',  '1',
	                            '-',  '2',  '4',  '-',  '0',  0x0c, 'e',  'u',  '-',  'c',  'e',
	                            'n',  't',  'r',  'a',  'l',  '-',  '1',  0x07, 'c',  'o',  'm',
	                            'p',  'u',  't',  'e',  0x08, 'i',  'n',  't',  'e',  'r',  'n',
	                            'a',  'l',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04,
	                            0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	sockaddr_in client_sockaddr = test_utils::fill_sockaddr_in(47288, "127.0.0.1");
	sockaddr_in server_sockaddr = test_utils::fill_sockaddr_in(53, "127.0.0.53");
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	constexpr int64_t fd = 13;

	assert_event_presence(
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SOCKET_RECVMSG_X,
	                               6,
	                               res,
	                               size,
	                               scap_const_sized_buffer{data, sizeof(data)},
	                               scap_const_sized_buffer{tuple.data(), tuple.size()},
	                               scap_const_sized_buffer{nullptr, 0},
	                               fd));
}
#endif

////////////////////////////
///// EVENTFD
////////////////////////////

// We don't have scap-files with EVENTFD events. Add it if we face a failure.

////////////////////////////
// MKDIR
////////////////////////////

TEST_F(scap_file_test, mkdir_x_check_final_converted_event) {
	open_filename("mkdir.scap");

	// Inside the scap-file the event `465` is the following:
	// - type=PPME_SYSCALL_MKDIR_2_X,
	// - ts=1749017847850665826
	// - tid=1163259
	// - args=res=-13(EACCES) path=/hello
	//
	// And its corresponding enter event `464` is the following:
	// - type=PPME_SYSCALL_MKDIR_2_E
	// - ts=1749017847850637066
	// - tid=1163259
	// - args=mode=1FF
	//
	// Let's see the new PPME_SYSCALL_MKDIR_2_X event!

	uint64_t ts = 1749017847850665826;
	int64_t tid = 1163259;
	int64_t res = -13;
	constexpr char path[] = "/hello";
	uint32_t mode = 0x1ff;  // 0777 in octal
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_MKDIR_2_X, 3, res, path, mode));
}

////////////////////////////
///// FUTEX
////////////////////////////

TEST_F(scap_file_test, futex_x_check_final_converted_event) {
	open_filename("sample.scap");

	// Inside the scap-file the event `177` is the following:
	// - type=PPME_SYSCALL_FUTEX_X,
	// - ts=1690557262892768316
	// - tid=418
	// - args=res=0
	//
	// And its corresponding enter event `176` is the following:
	// - type=PPME_SYSCALL_FUTEX_E
	// - ts=1690557262892767595
	// - tid=418
	// - args=addr=5600C32351E0 op=129(FUTEX_PRIVATE_FLAG|FUTEX_WAKE) val=1
	//
	// Let's see the new PPME_SYSCALL_FUTEX_X event!

	constexpr uint64_t ts = 1690557262892768316;
	constexpr int64_t tid = 418;
	constexpr int64_t res = 0;
	constexpr uint64_t addr = 0x5600C32351E0;
	constexpr uint16_t op = 129;
	constexpr uint64_t val = 1;
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_FUTEX_X, 4, res, addr, op, val));
}

////////////////////////////
///// EPOLL_WAIT
////////////////////////////

TEST_F(scap_file_test, epoll_wait_x_check_final_converted_event) {
	open_filename("kexec_x86.scap");

	// Inside the scap-file the event `522235` is the following:
	// - type=PPME_SYSCALL_EPOLLWAIT_X,
	// - ts=1687889198957001006
	// - tid=1385
	// - args=res=0
	//
	// And its corresponding enter event `522236` is the following:
	// - type=PPME_SYSCALL_EPOLLWAIT_E
	// - ts=1687889198956999803
	// - tid=1385
	// - args=maxevents=1024
	//
	// Let's see the new PPME_SYSCALL_EPOLLWAIT_X event!

	constexpr uint64_t ts = 1687889198957001006;
	constexpr int64_t tid = 1385;
	constexpr int64_t res = 0;
	constexpr int64_t maxevents = 1024;
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_EPOLLWAIT_X, 2, res, maxevents));
}

////////////////////////////
///// POLL
////////////////////////////

TEST_F(scap_file_test, poll_x_check_final_converted_event) {
	open_filename("kexec_x86.scap");

	// Inside the scap-file the event `520415` is the following:
	// - type=PPME_SYSCALL_POLL_X,
	// - ts=1687889198874896483
	// - tid=99525
	// - args=res=1 fds=22:i1
	//
	// And its corresponding enter event `520414` is the following:
	// - type=PPME_SYSCALL_POLL_E
	// - ts=1687889198874895459
	// - tid=99525
	// - args=fds=20:p1 22:i1 timeout=500
	//
	// Let's see the new PPME_SYSCALL_POLL_X event!

	constexpr uint64_t ts = 1687889198874896483;
	constexpr int64_t tid = 99525;
	constexpr int64_t res = 1;
	constexpr uint8_t fds[] = {0x1, 0x0, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};
	constexpr int64_t timeout = 500;
	assert_event_presence(create_safe_scap_event(ts,
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

// We don't have scap-files with LLSEEK events. Add it if we face a failure.

////////////////////////////
///// IOCTL
////////////////////////////

TEST_F(scap_file_test, ioctl_x_check_final_converted_event) {
	open_filename("kexec_arm64.scap");

	// Inside the scap-file the event `903005` is the following:
	// - type=PPME_SYSCALL_IOCTL_3_X,
	// - ts=1687966733986436903
	// - tid=118552
	// - args=res=0
	//
	// And its corresponding enter event `903004` is the following:
	// - type=PPME_SYSCALL_IOCTL_3_E
	// - ts=1687966733986427631
	// - tid=118552
	// - args=fd=21(<f>/dev/ptmx) request=5414 argument=FFFFD297F908
	//
	// Let's see the new PPME_SYSCALL_IOCTL_3_X event!

	constexpr uint64_t ts = 1687966733986436903;
	constexpr int64_t tid = 118552;
	constexpr int64_t res = 0;
	constexpr int64_t fd = 21;
	constexpr uint64_t request = 0x5414;
	constexpr uint64_t argument = 0xFFFFD297F908;
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_IOCTL_3_X, 4, res, fd, request, argument));
}

////////////////////////////
// PTRACE
////////////////////////////

TEST_F(scap_file_test, ptrace_x_check_final_converted_event) {
	open_filename("ptrace.scap");

	// Inside the scap-file the event `464` is the following:
	// - type=PPME_SYSCALL_PTRACE_X,
	// - ts=1747834548577695347
	// - tid=368860
	// - args=res=0 addr=78 data=3B
	//
	// And its corresponding enter event `463` is the following:
	// - type=PPME_SYSCALL_PTRACE_E
	// - ts=1747834548577692897
	// - tid=368860
	// - args=request=4(PTRACE_PEEKUSR) pid=368861(mystrace)
	//
	// Let's see the new PPME_SYSCALL_PTRACE_X event!

	uint64_t ts = 1747834548577695347;
	int64_t tid = 368860;
	int64_t res = 0;
	uint8_t addr[] = {0x00, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	uint8_t data[] = {0x00, 0x3b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	uint16_t request = 4;
	int64_t pid = 368861;
	assert_event_presence(create_safe_scap_event(ts,
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
// SETNS
////////////////////////////

TEST_F(scap_file_test, setns_x_check_final_converted_event) {
	open_filename("kexec_x86.scap");

	// Inside the scap-file the event `156638` is the following:
	// - type=PPME_SYSCALL_SETNS_X,
	// - ts=1687889193606963670
	// - tid=107363
	// - args=res=0
	//
	// And its corresponding enter event `156637` is the following:
	// - type=PPME_SYSCALL_SETNS_E
	// - ts=1687889193606959614
	// - tid=107363
	// - args=fd=6(<f>/proc/1993/ns/ipc) nstype=8(CLONE_NEWIPC)
	//
	// Let's see the new PPME_SYSCALL_SETNS_X event!

	uint64_t ts = 1687889193606963670;
	int64_t tid = 107363;
	int64_t res = 0;
	int64_t fd = 6;
	uint32_t nstype = 8;  // CLONE_NEWIPC
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETNS_X, 3, res, fd, nstype));
}

////////////////////////////
// FCHDIR
////////////////////////////

TEST_F(scap_file_test, fchdir_x_check_final_converted_event) {
	open_filename("fchdir.scap");

	// Inside the scap-file the event `370` is the following:
	// - type=PPME_SYSCALL_FCHDIR_X,
	// - ts=1749117249748433380
	// - tid=1377498
	// - args=res=-9(EBADF)
	//
	// And its corresponding enter event `369` is the following:
	// - type=PPME_SYSCALL_FCHDIR_E,
	// - ts=1749117249748432840
	// - tid=1377498
	// - args=fd=25
	//
	// Let's see the new PPME_SYSCALL_FCHDIR_X event!

	uint64_t ts = 1749117249748433380;
	int64_t tid = 1377498;
	int64_t res = -9;
	int64_t fd = 25;
	assert_event_presence(create_safe_scap_event(ts, tid, PPME_SYSCALL_FCHDIR_X, 2, res, fd));
}

////////////////////////////
// SETPGID
////////////////////////////

TEST_F(scap_file_test, setpgid_x_check_final_converted_event) {
	open_filename("kexec_x86.scap");

	// Inside the scap-file the event `123127` is the following:
	// - type=PPME_SYSCALL_SETPGID_X,
	// - ts=1687889193490376726
	// - tid=107344
	// - args=res=0
	//
	// And its corresponding enter event `123126` is the following:
	// - type=PPME_SYSCALL_SETPGID_E
	// - ts=1687889193490374360
	// - tid=107344
	// - args=pid=0 pgid=107344(zsh)
	//
	// Let's see the new PPME_SYSCALL_SETPGID_X event!

	uint64_t ts = 1687889193490376726;
	int64_t tid = 107344;
	int64_t res = 0;
	int64_t pid = 0;
	int64_t pgid = 107344;  // zsh process ID
	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_SETPGID_X, 3, res, pid, pgid));
}
