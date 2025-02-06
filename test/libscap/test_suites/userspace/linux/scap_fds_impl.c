#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/linux/scap_linux_int.h>
#include <libscap/linux/scap_fds.c>

// This file decouples the C++ test framework from the C code we're testing.

// Mock a buffer that has a TIME_WAIT socket at the very end and test it.
int32_t test_time_wait_socket_at_buffer_end(void) {
	static char error[SCAP_LASTERR_SIZE];
	// TODO: Make this the same size as the real buffer.
	char buffer[4096];
	memset(buffer, 0, sizeof(buffer));

	int pos = 0;
	for(int i = 0; i < 100; i++) {
		// Resembles typical socket entries.
		pos += snprintf(buffer + pos,
		                sizeof(buffer) - pos,
		                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
		                "retrnsmt   uid  timeout inode\n"
		                "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 "
		                "00000000     0        0 123456\n");
	}

	// Imitates TIME_WAIT sockets with inode=0.
	snprintf(buffer + pos,
	         sizeof(buffer) - pos,
	         "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0    "
	         "    0 0");

	scap_fdinfo* sockets = NULL;
	return scap_fd_read_ipv4_sockets_from_proc_fs(buffer, SCAP_L4_TCP, &sockets, error);
}
