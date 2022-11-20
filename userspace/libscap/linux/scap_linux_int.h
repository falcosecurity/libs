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

struct scap_ns_socket_list;

// read all sockets and add them to the socket table hashed by their ino
int32_t scap_fd_read_sockets(char* procdir, struct scap_ns_socket_list* sockets, char *error);
void scap_fd_free_ns_sockets_list(struct scap_ns_socket_list** sockets);
