/*
Copyright (C) 2021 The Falco Authors.

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

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

#include <inttypes.h>
#include <stdbool.h>

//
// Import/typedef in userspace the kernel types
//
#if defined(__linux__) && !defined(UDIG)
#include <linux/types.h>
#else 
typedef unsigned long long __u64;
typedef long long __s64;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint8_t __u8;
typedef int8_t __s8;
#endif
