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

#include "scap_reader.h"
#include <string.h>

typedef struct reader_handle
{
    bool m_free_reader; ///< Whether the reader should be free-d on close
    bool m_has_err; ///< True if the most recent m_reader operation had an error
    uint8_t* m_buffer; ///< The buffer used to read data from m_reader
    uint32_t m_buffer_cap; ///< The physical size of the buffer
    uint32_t m_buffer_len; ///< The number of bytes used in the buffer
    uint32_t m_buffer_off; ///< The cursor position in the buffer
    scap_reader_t* m_reader; ///< The reader to read from in buffered mode
} reader_handle_t;

static int buffered_read(scap_reader_t *r, void* buf, uint32_t len)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    uint8_t* buf_bytes = (uint8_t*) buf;
    uint32_t size = 0;
    while (len > 0 && !h->m_has_err)
    {
        if (h->m_buffer_off >= h->m_buffer_len)
        {
            int nread = h->m_reader->read(h->m_reader, h->m_buffer, h->m_buffer_cap);
            if (nread <= 0)
            {
                // invalidate next read
                h->m_has_err = true;
                return buf_bytes - (uint8_t*) buf;
            }
            h->m_buffer_off = 0;
            h->m_buffer_len = (uint32_t) nread;
        }
        size = len <= (h->m_buffer_len - h->m_buffer_off) ? len : (h->m_buffer_len - h->m_buffer_off);
        memcpy(buf_bytes, h->m_buffer + h->m_buffer_off, size);
        buf_bytes += size;
        h->m_buffer_off += size;
        len -= size;
    }
    return buf_bytes - (uint8_t*) buf;
}

static int64_t buffered_offset(scap_reader_t *r)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    return h->m_reader->offset(h->m_reader); 
}

static int64_t buffered_tell(scap_reader_t *r)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    int64_t res = h->m_reader->tell(h->m_reader); 
    if (res < 0)
    {
        return res;
    }
    return res - h->m_buffer_len + h->m_buffer_off;
}

static int64_t buffered_seek(scap_reader_t *r, int64_t offset, int whence)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    if (whence == SEEK_CUR)
    {
        if (offset < 0 && h->m_buffer_off >= (uint32_t) (offset * -1))
        {
            h->m_buffer_off -= (uint32_t) (offset * -1);
            return r->tell(r);
        }
        else if (offset > 0 && h->m_buffer_len >= h->m_buffer_off + (uint32_t) offset)
        {
            h->m_buffer_off += (uint32_t) offset;
            return r->tell(r);
        }
    }
    h->m_buffer_off = 0;
    h->m_buffer_len = 0;
    return h->m_reader->seek(h->m_reader, offset, whence);
}

static const char* buffered_error(scap_reader_t *r, int *errnum)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    return h->m_reader->error(h->m_reader, errnum);
}

static int buffered_close(scap_reader_t *r)
{
    ASSERT(r != NULL);
    reader_handle_t* h = (reader_handle_t*) r->handle;
    int res = h->m_reader->close(h->m_reader);
    if (h->m_free_reader)
    {
        free(h->m_reader);
    }
    free(h->m_buffer);
    free(r->handle);
    return res;
}

scap_reader_t *scap_reader_open_buffered(scap_reader_t* reader, uint32_t bufsize, bool own_reader)
{
    if (reader == NULL || bufsize == 0)
    {
        return NULL;
    }

    reader_handle_t* h = (reader_handle_t *) malloc (sizeof (reader_handle_t));
    h->m_free_reader = own_reader;
    h->m_has_err = false;
    h->m_reader = reader;
    h->m_buffer = (uint8_t*) malloc (sizeof(uint8_t) * bufsize);
    h->m_buffer_cap = bufsize;
    h->m_buffer_len = 0;
    h->m_buffer_off = 0;

    scap_reader_t* r = (scap_reader_t *) malloc (sizeof (scap_reader_t));
    r->handle = h;
    r->read = &buffered_read;
    r->offset = &buffered_offset;
    r->tell = &buffered_tell;
    r->seek = &buffered_seek;
    r->error = &buffered_error;
    r->close = &buffered_close;
    return r;
}
