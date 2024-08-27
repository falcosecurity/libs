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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libscap/scap_assert.h>
#include <libscap/scap_zlib.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Represents a reader for data in SCAP format
 */
typedef struct scap_reader
{
    /**
     * @brief The internal state of each implementation.
     */
    void* handle;

    /**
     * @brief Reads at most len bytes into buf from the given reader.
     * On success, returns the number of bytes read. On failure,
     * returns 0 or a negative value, and error() can be used to
     * retrieve the error.
     */
    int (*read)(struct scap_reader *r, void* buf, uint32_t len);

    /**
     * @brief Returns the current offset in the data being read.
     * On error, returns a negative value and error() can be used to
     * retrieve the error.
     */
    int64_t (*offset)(struct scap_reader *r);

    /**
     * @brief Returns the starting position for the next read().
     * On error, returns a negative value and error() can be used to
     * retrieve the error.
     */
    int64_t (*tell)(struct scap_reader *r);

    /**
     * @brief Sets the starting position for the next read().
     * The whence parameter is defined as in lseek(2) and the support
     * to each whence type is implementation-specific.
     * On error, returns a negative value and error() can be used to
     * retrieve the error.
     */
    int64_t (*seek)(struct scap_reader *r, int64_t offset, int whence);

    /**
     * @brief Returns the message and number for the last error occurred.
     * If there is no error, errnum is set to 0. The message and the
     * error number representations are implementation-specific.
     */
    const char* (*error)(struct scap_reader *r, int *errnum);

    /**
     * @brief Closes the reader and de-allocates it.
     */
    int (*close)(struct scap_reader *r);
} scap_reader_t;

/**
 * @brief Opens a reader from a gzFile
 */
scap_reader_t *scap_reader_open_gzfile(gzFile file);

/**
 * @brief Opens a reader wrapping another reader, and reads data using buffering.
 * This is suitable to support stream-like data, for which buffering reduces
 * the number of data reads and allows seeking (inside the buffer boundaries).
 * @param bufsize is the size of the data buffer
 * @param own_reader if true, the wrapped reader will be closed and de-allocated
 * using its close() function when the buffered reader gets closed.
 */
scap_reader_t *scap_reader_open_buffered(scap_reader_t* reader, uint32_t bufsize, bool own_reader);


#ifdef __cplusplus
}
#endif
