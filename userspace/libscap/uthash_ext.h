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

#define uthash_fatal(msg) uth_status = SCAP_FAILURE 

/* `uthash.h` is generated at build time, see `uthash.cmake` */
#include "uthash.h"

/* Further definitions on top of 'uthash.h' */
#define HASH_FIND_INT32(head,findint,out)                                        \
    HASH_FIND(hh,head,findint,sizeof(uint32_t),out)
#define HASH_ADD_INT32(head,intfield,add)                                        \
    HASH_ADD(hh,head,intfield,sizeof(uint32_t),add)
#define HASH_FIND_INT64(head,findint,out)                                        \
    HASH_FIND(hh,head,findint,sizeof(uint64_t),out)
#define HASH_ADD_INT64(head,intfield,add)                                        \
    HASH_ADD(hh,head,intfield,sizeof(uint64_t),add)
