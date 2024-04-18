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

#include <sys/types.h>
#include <string.h>
#include <libscap/scap_strl_config.h>

#pragma once

/*!
  \brief Copy up to size - 1 characters from the NUL-terminated string src to dst, NUL-terminating the result.

  \return The length of the source string.
*/

#ifndef HAVE_STRLCPY
static inline size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srcsize = strlen(src);
    if (size == 0) {
        return srcsize;
    }

    size_t copysize = srcsize;

    if (copysize > size - 1) {
        copysize = size - 1;
    }

    memcpy(dst, src, copysize);
    dst[copysize] = '\0';

    return srcsize;
}
#endif

/*!
  \brief Append the NUL-terminated string src to the end of dst. It will append at most size − strlen(dst) − 1 bytes, NUL-terminating the result. 

  \return The initial length of dst plus the length of src
*/

#ifndef HAVE_STRLCAT
static inline size_t strlcat(char *dst, const char *src, size_t size) {
    size_t srcsize = strlen(src);
    size_t dstsize = strlen(dst);

    if (dstsize >= size) {
        return size;
    }

    if (srcsize == 0) {
        return dstsize;
    }

    size_t totalsize = srcsize + dstsize;
    if (totalsize > size - 1) {
        totalsize = size - 1;
    }

    size_t copysize = totalsize - dstsize;
    memcpy(dst + dstsize, src, copysize);
    dst[totalsize] = '\0';

    return dstsize + srcsize;
}
#endif
