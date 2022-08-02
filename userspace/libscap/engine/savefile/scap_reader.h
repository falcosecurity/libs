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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "scap_assert.h"
#include "scap_zlib.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ppm_reader_type
{
	RT_FILE = 0,
	RT_BUFFERED = 1,
} ppm_reader_type;

typedef struct scap_reader
{
	ppm_reader_type m_type;
	union
	{
		struct // RT_FILE
		{
			gzFile m_file; ///< The file to read data from
		};
		struct // RT_BUFFERED
		{
			bool m_free_reader; ///< whether the reader should be free-d on close
			bool m_has_err; ///< True if the most recent m_reader operation had an error
			uint8_t* m_buffer; ///< The buffer used to read data from m_reader
			uint32_t m_buffer_cap; ///< The physical size of the buffer
			uint32_t m_buffer_len; ///< The number of bytes used in the buffer
			uint32_t m_buffer_off; ///< The cursor position in the buffer
			struct scap_reader* m_reader; ///< The reader to read from in buffered mode
		};
	};
} scap_reader_t;

static inline scap_reader_t *scap_reader_open_gzfile(gzFile file)
{
	if (file == NULL)
	{
		return NULL;
	}
	scap_reader_t* r = (scap_reader_t *) malloc (sizeof (scap_reader_t));
	r->m_type = RT_FILE;
	r->m_file = file;
	return r;
}

int scap_reader_read_buffered(scap_reader_t *r, void* buf, uint32_t len);
int64_t scap_reader_offset_buffered(scap_reader_t *r);
int64_t scap_reader_tell_buffered(scap_reader_t *r);
int64_t scap_reader_seek_buffered(scap_reader_t *r, int64_t offset, int whence);
const char *scap_reader_error_buffered(scap_reader_t *r, int *errnum);
int scap_reader_close_buffered(scap_reader_t *r);

// wraps another scap reader and reads from it using a buffer of size bufsize.
// if own_reader is true, the wrapped reader will be de-allocated using free()
// when the buffered reader gets closed.
static inline scap_reader_t *scap_reader_open_buffered(scap_reader_t* reader, uint32_t bufsize, bool own_reader)
{
	if (reader == NULL || bufsize == 0)
	{
		return NULL;
	}
	scap_reader_t* r = (scap_reader_t*) malloc (sizeof(scap_reader_t));
	r->m_type = RT_BUFFERED;
	r->m_free_reader = own_reader;
	r->m_has_err = false;
	r->m_reader = reader;
	r->m_buffer = (uint8_t*) malloc (sizeof(uint8_t) * bufsize);
	r->m_buffer_cap = bufsize;
	r->m_buffer_len = 0;
	r->m_buffer_off = 0;
	return r;
}

static inline ppm_reader_type scap_reader_type(scap_reader_t *r)
{
	ASSERT(r != NULL);
	return r->m_type;
}

static inline int scap_reader_read(scap_reader_t *r, void* buf, uint32_t len)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzread(r->m_file, buf, len);
		case RT_BUFFERED:
			return scap_reader_read_buffered(r, buf, len);
		default:
			ASSERT(false);
			return 0;
	}
}

static inline int64_t scap_reader_offset(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzoffset(r->m_file);
		case RT_BUFFERED:
			return scap_reader_offset_buffered(r);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline int64_t scap_reader_tell(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gztell(r->m_file);
		case RT_BUFFERED:
			return scap_reader_tell_buffered(r);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline int64_t scap_reader_seek(scap_reader_t *r, int64_t offset, int whence)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzseek(r->m_file, offset, whence);
		case RT_BUFFERED:
			return scap_reader_seek_buffered(r, offset, whence);
		default:
			ASSERT(false);
			return -1;
	}
}

static inline const char *scap_reader_error(scap_reader_t *r, int *errnum)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzerror(r->m_file, errnum);
		case RT_BUFFERED:
			return scap_reader_error_buffered(r, errnum);
		default:
			ASSERT(false);
			*errnum = -1;
			return "unknown scap_reader type";
	}
}

static inline int scap_reader_close(scap_reader_t *r)
{
	ASSERT(r != NULL);
	switch (r->m_type)
	{
		case RT_FILE:
			return gzclose(r->m_file);
		case RT_BUFFERED:
			return scap_reader_close_buffered(r);
		default:
			ASSERT(false);
			return -1;
	}
}


#ifdef __cplusplus
}
#endif
