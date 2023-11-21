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

#include <libscap/engine/savefile/scap_reader.h>

typedef struct reader_handle
{
    gzFile m_file; ///< The file to read data from
} reader_handle_t;

static int gzfile_read(scap_reader_t *r, void* buf, uint32_t len)
{
    ASSERT(r != NULL);
    return gzread(((reader_handle_t*)r->handle)->m_file, buf, len);
}

static int64_t gzfile_offset(scap_reader_t *r)
{
    ASSERT(r != NULL);
    return gzoffset(((reader_handle_t*)r->handle)->m_file);
}

static int64_t gzfile_tell(scap_reader_t *r)
{
    ASSERT(r != NULL);
    return gztell(((reader_handle_t*)r->handle)->m_file);
}

static int64_t gzfile_seek(scap_reader_t *r, int64_t offset, int whence)
{
    ASSERT(r != NULL);
    return gzseek(((reader_handle_t*)r->handle)->m_file, offset, whence);
}

static const char* gzfile_error(scap_reader_t *r, int *errnum)
{
    ASSERT(r != NULL);
    return gzerror(((reader_handle_t*)r->handle)->m_file, errnum);
}

static int gzfile_close(scap_reader_t *r)
{
    ASSERT(r != NULL);
    int res = gzclose(((reader_handle_t*)r->handle)->m_file);
    free(r->handle);
    free(r);
    return res;
}

scap_reader_t *scap_reader_open_gzfile(gzFile file)
{
    if (file == NULL)
    {
        return NULL;
    }

    reader_handle_t* h = (reader_handle_t *) malloc (sizeof (reader_handle_t));
    h->m_file = file;
    
    scap_reader_t* r = (scap_reader_t *) malloc (sizeof (scap_reader_t));
    r->handle = h;
    r->read = &gzfile_read;
    r->offset = &gzfile_offset;
    r->tell = &gzfile_tell;
    r->seek = &gzfile_seek;
    r->error = &gzfile_error;
    r->close = &gzfile_close;
    return r;
}
