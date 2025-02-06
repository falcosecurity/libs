#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

static const char* SOCKET_HEADER =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
        "timeout inode\n";

static const char* SOCKET_ENTRY =
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        "
        "0 123456\n";

static const char* TIME_WAIT_ENTRY =
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        "
        "0 0";

// Mock a buffer that has a TIME_WAIT socket at the very end and test it.
int32_t test_time_wait_socket_at_buffer_end(void) {
	static char error[SCAP_LASTERR_SIZE];

	// Calculate exact size needed for header + 100 entries + TIME_WAIT entry
	size_t buffer_size =
	        strlen(SOCKET_HEADER) + (100 * strlen(SOCKET_ENTRY)) + strlen(TIME_WAIT_ENTRY);
	char buffer[buffer_size];
	memset(buffer, 0, buffer_size);

	int pos = 0;
	pos += snprintf(buffer + pos, buffer_size - pos, "%s", SOCKET_HEADER);

	for(int i = 0; i < 100; i++) {
		pos += snprintf(buffer + pos, buffer_size - pos, "%s", SOCKET_ENTRY);
	}

	snprintf(buffer + pos, buffer_size - pos, "%s", TIME_WAIT_ENTRY);

	scap_fdinfo* sockets = NULL;
	return scap_fd_read_ipv4_sockets_from_proc_fs(buffer, SCAP_L4_TCP, &sockets, error);
}
