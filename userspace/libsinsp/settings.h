// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_EVT_BUF_SIZE won't be be stored in the LIFO.
//
#define SP_EVT_BUF_SIZE 4096

//
// Max size that the FD table of a process can reach
//
#define MAX_FD_TABLE_SIZE 4096

//
// How often the container table is scanned for inactive containers
//
#define DEFAULT_INACTIVE_CONTAINER_SCAN_TIME_S 30

//
// How often the users/groups tables are scanned for deleted users/groups
//
#define DEFAULT_DELETED_USERS_GROUPS_SCAN_TIME_S 60

//
// Default snaplen
//
#define DEFAULT_SNAPLEN 80

//
// The time after which a clone should be considered stale
//
#define CLONE_STALE_TIME_NS 2 * SECOND_TO_NS

//
// Port range to enable larger snaplen on
//
#define DEFAULT_INCREASE_SNAPLEN_PORT_RANGE {0, 0}

