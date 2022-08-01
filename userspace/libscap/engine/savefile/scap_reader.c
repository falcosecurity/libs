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

int scap_reader_read_buffered(scap_reader_t *r, void* buf, uint32_t len)
{
	uint8_t* buf_bytes = (uint8_t*) buf;
	while (len > 0 && !r->m_has_err)
    {
        if (r->m_buffer_off >= r->m_buffer_len)
        {
            int nread = scap_reader_read(r->m_reader, r->m_buffer, r->m_buffer_cap);
            if (nread <= 0)
            {
                // invalidate next read
                r->m_has_err = true;
                return buf_bytes - (uint8_t*) buf;
            }
            r->m_buffer_off = 0;
            r->m_buffer_len = (uint32_t) nread;
        }
        *(buf_bytes++) = r->m_buffer[r->m_buffer_off++];
        len--;
    }
    return buf_bytes - (uint8_t*) buf;
}

int64_t scap_reader_offset_buffered(scap_reader_t *r)
{
	return scap_reader_offset(r->m_reader);
}

int64_t scap_reader_tell_buffered(scap_reader_t *r)
{
	int64_t res = scap_reader_tell(r->m_reader);
    if (res < 0)
    {
        return res;
    }
    return res - r->m_buffer_len + r->m_buffer_off;
}

int64_t scap_reader_seek_buffered(scap_reader_t *r, int64_t offset, int whence)
{
	if (whence == SEEK_CUR)
    {
        if (offset < 0 && r->m_buffer_off >= (uint32_t) (offset * -1))
        {
            r->m_buffer_off -= (uint32_t) (offset * -1);
            return scap_reader_tell(r);
        }
        else if (offset > 0 && r->m_buffer_len >= r->m_buffer_off + (uint32_t) offset)
        {
            r->m_buffer_off += (uint32_t) offset;
            return scap_reader_tell(r);
        }
    }
    r->m_buffer_off = 0;
    r->m_buffer_len = 0;
    return scap_reader_seek(r->m_reader, offset, whence);
}

const char *scap_reader_error_buffered(scap_reader_t *r, int *errnum)
{
	return scap_reader_error(r->m_reader, errnum);
}

int scap_reader_close_buffered(scap_reader_t *r)
{
	int res = scap_reader_close(r->m_reader);
    if (r->m_free_reader)
    {
        free(r->m_reader);
    }
    free(r->m_buffer);
    return res;
}
