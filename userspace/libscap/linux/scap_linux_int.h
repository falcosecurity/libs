/*
Copyright (C) 2022 The Falco Authors.

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

#include <stdbool.h>
#include <stdint.h>

#include "uthash.h"

typedef struct scap_fdinfo scap_fdinfo;

struct scap_ns_socket_list
{
	int64_t net_ns;
	scap_fdinfo* sockets;
	UT_hash_handle hh;
};

struct scap_platform;
struct scap_linux_platform;
struct scap_proclist;
typedef struct scap_threadinfo scap_threadinfo;

int32_t scap_linux_create_iflist(struct scap_platform* platform);
int32_t scap_linux_create_userlist(struct scap_platform* platform);

uint32_t scap_linux_get_device_by_mount_id(struct scap_platform* platform, const char *procdir, unsigned long requested_mount_id);
struct scap_threadinfo* scap_linux_proc_get(struct scap_platform* platform, struct scap_proclist* proclist, int64_t tid, bool scan_sockets);

// read all sockets and add them to the socket table hashed by their ino
int32_t scap_fd_read_sockets(char* procdir, struct scap_ns_socket_list* sockets, char *error);
void scap_fd_free_ns_sockets_list(struct scap_ns_socket_list** sockets);
// read the file descriptors for a given process directory
int32_t scap_fd_scan_fd_dir(struct scap_linux_platform *linux_platform, struct scap_proclist *proclist, char * procdir, scap_threadinfo* pi, struct scap_ns_socket_list** sockets_by_ns, uint64_t* num_fds_ret, char *error);
