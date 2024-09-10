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

//
// Fallback implementation of memmem
//
#if !defined(_GNU_SOURCE) && !defined(__APPLE__)
#include <string.h>

static inline void *memmem(const void *haystack,
                           size_t haystacklen,
                           const void *needle,
                           size_t needlelen) {
	const unsigned char *ptr;
	const unsigned char *end;

	if(needlelen == 0) {
		return (void *)haystack;
	}

	if(haystacklen < needlelen) {
		return NULL;
	}

	end = (const unsigned char *)haystack + haystacklen - needlelen;
	for(ptr = (const unsigned char *)haystack; ptr <= end; ptr++) {
		if(!memcmp(ptr, needle, needlelen)) {
			return (void *)ptr;
		}
	}

	return NULL;
}
#endif
