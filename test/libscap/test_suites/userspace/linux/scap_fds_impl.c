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
#include <libscap_test_var.h>

// This file decouples the C++ test framework from the C code we're testing.

int32_t test_time_wait_socket_at_buffer_end(void) {
	static char error[SCAP_LASTERR_SIZE];
	scap_fdinfo* sockets = NULL;
	char filepath[PATH_MAX];

	snprintf(filepath, sizeof(filepath), "%s/scap_test_sockets.txt", LIBSCAP_TEST_DATA_PATH);

	const int32_t result = parse_procfs_proc_pid_socket_table_file(filepath,
	                                                               AF_INET,
	                                                               SCAP_L4_TCP,
	                                                               &sockets,
	                                                               error);

	scap_fd_free_table(&sockets);

	return result;
}
