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

#include <libscap/scap.h>

#include <inttypes.h>
#include <stdio.h>

#if defined(_WIN32)
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define LABEL_FMT "%-15s"

static const char *scap_fd_type_name(const scap_fd_type type) {
	switch(type) {
	case SCAP_FD_UNINITIALIZED:
		return "UNINITIALIZED";
	case SCAP_FD_UNKNOWN:
		return "UNKNOWN";
	case SCAP_FD_FILE:
		return "FILE";
	case SCAP_FD_DIRECTORY:
		return "DIRECTORY";
	case SCAP_FD_IPV4_SOCK:
		return "IPV4_SOCK";
	case SCAP_FD_IPV6_SOCK:
		return "IPV6_SOCK";
	case SCAP_FD_IPV4_SERVSOCK:
		return "IPV4_SERVSOCK";
	case SCAP_FD_IPV6_SERVSOCK:
		return "IPV6_SERVSOCK";
	case SCAP_FD_FIFO:
		return "FIFO";
	case SCAP_FD_UNIX_SOCK:
		return "UNIX_SOCK";
	case SCAP_FD_EVENT:
		return "EVENT";
	case SCAP_FD_UNSUPPORTED:
		return "UNSUPPORTED";
	case SCAP_FD_SIGNALFD:
		return "SIGNALFD";
	case SCAP_FD_EVENTPOLL:
		return "EVENTPOLL";
	case SCAP_FD_INOTIFY:
		return "INOTIFY";
	case SCAP_FD_TIMERFD:
		return "TIMERFD";
	case SCAP_FD_NETLINK:
		return "NETLINK";
	case SCAP_FD_FILE_V2:
		return "FILE_V2";
	case SCAP_FD_BPF:
		return "BPF";
	case SCAP_FD_USERFAULTFD:
		return "USERFAULTFD";
	case SCAP_FD_IOURING:
		return "IOURING";
	case SCAP_FD_MEMFD:
		return "MEMFD";
	case SCAP_FD_PIDFD:
		return "PIDFD";
	default:
		return "UNKNOWN";
	}
}

static void scap_print_fdinfo_ipv4_sock(const scap_fdinfo *fdinfo) {
	char sip_buf[INET_ADDRSTRLEN] = {0};
	char dip_buf[INET_ADDRSTRLEN] = {0};

	const uint8_t *ip = (const uint8_t *)&fdinfo->info.ipv4info.sip;
	snprintf(sip_buf, sizeof(sip_buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	ip = (const uint8_t *)&fdinfo->info.ipv4info.dip;
	snprintf(dip_buf, sizeof(dip_buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	printf(LABEL_FMT " %-20s " LABEL_FMT " %-20s " LABEL_FMT " %-20" PRIu16 "\n" LABEL_FMT
	                 " %-20" PRIu16 " " LABEL_FMT " %-20" PRIu8 "\n",
	       "sip:",
	       sip_buf,
	       "dip:",
	       dip_buf,
	       "sport:",
	       fdinfo->info.ipv4info.sport,
	       "dport:",
	       fdinfo->info.ipv4info.dport,
	       "l4proto:",
	       fdinfo->info.ipv4info.l4proto);
}

static void scap_print_fdinfo_ipv6_sock(const scap_fdinfo *fdinfo) {
	char sip_buf[INET6_ADDRSTRLEN] = {0};
	char dip_buf[INET6_ADDRSTRLEN] = {0};

	inet_ntop(AF_INET6, fdinfo->info.ipv6info.sip, sip_buf, sizeof(sip_buf));
	inet_ntop(AF_INET6, fdinfo->info.ipv6info.dip, dip_buf, sizeof(dip_buf));

	printf(LABEL_FMT " %s\n" LABEL_FMT " %s\n" LABEL_FMT " %-20" PRIu16 " " LABEL_FMT " %-20" PRIu16
	                 " " LABEL_FMT " %-20" PRIu8 "\n",
	       "sip:",
	       sip_buf,
	       "dip:",
	       dip_buf,
	       "sport:",
	       fdinfo->info.ipv6info.sport,
	       "dport:",
	       fdinfo->info.ipv6info.dport,
	       "l4proto:",
	       fdinfo->info.ipv6info.l4proto);
}

static void scap_print_fdinfo_ipv4_servsock(const scap_fdinfo *fdinfo) {
	char sip_buf[INET_ADDRSTRLEN] = {0};
	const uint8_t *ip = (const uint8_t *)&fdinfo->info.ipv4serverinfo.ip;
	snprintf(sip_buf, sizeof(sip_buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	printf(LABEL_FMT " %-20s " LABEL_FMT " %-20" PRIu16 " " LABEL_FMT " %-20" PRIu8 "\n",
	       "ip:",
	       sip_buf,
	       "port:",
	       fdinfo->info.ipv4serverinfo.port,
	       "l4proto:",
	       fdinfo->info.ipv4serverinfo.l4proto);
}

static void scap_print_fdinfo_ipv6_servsock(const scap_fdinfo *fdinfo) {
	char sip_buf[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, fdinfo->info.ipv6serverinfo.ip, sip_buf, sizeof(sip_buf));

	printf(LABEL_FMT " %s\n" LABEL_FMT " %-20" PRIu16 " " LABEL_FMT " %-20" PRIu8 "\n",
	       "ip:",
	       sip_buf,
	       "port:",
	       fdinfo->info.ipv6serverinfo.port,
	       "l4proto:",
	       fdinfo->info.ipv6serverinfo.l4proto);
}

static void scap_print_fdinfo_unix_sock(const scap_fdinfo *fdinfo) {
	printf(LABEL_FMT " 0x%-18" PRIx64 " " LABEL_FMT " 0x%-18" PRIx64 "\n" LABEL_FMT " %.*s\n",
	       "source:",
	       fdinfo->info.unix_socket_info.source,
	       "destination:",
	       fdinfo->info.unix_socket_info.destination,
	       "fname:",
	       SCAP_MAX_PATH_SIZE,
	       fdinfo->info.unix_socket_info.fname);
}

static void scap_print_fdinfo_file_v2(const scap_fdinfo *fdinfo) {
	printf(LABEL_FMT " 0x%-18" PRIx32 " " LABEL_FMT " %-20" PRIu32 " " LABEL_FMT " %-20" PRIu32
	                 "\n" LABEL_FMT " %.*s\n",
	       "open_flags:",
	       fdinfo->info.regularinfo.open_flags,
	       "mount_id:",
	       fdinfo->info.regularinfo.mount_id,
	       "dev:",
	       fdinfo->info.regularinfo.dev,
	       "fname:",
	       SCAP_MAX_PATH_SIZE,
	       fdinfo->info.regularinfo.fname);
}

static void scap_print_fdinfo_generic(const scap_fdinfo *fdinfo) {
	printf(LABEL_FMT " %.*s\n", "fname:", SCAP_MAX_PATH_SIZE, fdinfo->info.fname);
}

void scap_print_fdinfo(const scap_fdinfo *fdinfo) {
	if(!fdinfo) {
		printf("----------------------- FDINFO (NULL)\n");
		return;
	}

	printf("----------------------- FDINFO\n");
	printf(LABEL_FMT " %-20" PRId64 " " LABEL_FMT " %-20" PRIu64 " " LABEL_FMT " %-20s\n",
	       "fd:",
	       fdinfo->fd,
	       "ino:",
	       fdinfo->ino,
	       "type:",
	       scap_fd_type_name(fdinfo->type));

	switch(fdinfo->type) {
	case SCAP_FD_IPV4_SOCK:
		scap_print_fdinfo_ipv4_sock(fdinfo);
		break;
	case SCAP_FD_IPV6_SOCK:
		scap_print_fdinfo_ipv6_sock(fdinfo);
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		scap_print_fdinfo_ipv4_servsock(fdinfo);
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		scap_print_fdinfo_ipv6_servsock(fdinfo);
		break;
	case SCAP_FD_UNIX_SOCK:
		scap_print_fdinfo_unix_sock(fdinfo);
		break;
	case SCAP_FD_FILE_V2:
		scap_print_fdinfo_file_v2(fdinfo);
		break;
	case SCAP_FD_UNINITIALIZED:
	case SCAP_FD_UNKNOWN:
		break;
	default:
		scap_print_fdinfo_generic(fdinfo);
		break;
	}
	printf("----------------------- \n");
}
