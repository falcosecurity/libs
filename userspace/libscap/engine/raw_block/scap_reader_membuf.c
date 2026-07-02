// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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
#include <string.h>

struct membuf_reader_handle {
	uint8_t** buffer_ptr;
	uint64_t* buffer_size_ptr;
	uint64_t offset;
};

static int membuf_read(scap_reader_t* r, void* buf, uint32_t len) {
	struct membuf_reader_handle* h = (struct membuf_reader_handle*)r->handle;
	uint32_t to_read = len;

	uint64_t buf_size = *h->buffer_size_ptr;
	if(h->offset >= buf_size) {
		return 0;
	}

	uint64_t available = buf_size - h->offset;
	if(to_read > available) {
		to_read = (uint32_t)available;
	}

	if(to_read > 0) {
		memcpy(buf, *h->buffer_ptr + h->offset, to_read);
		h->offset += to_read;
	}

	return (int)to_read;
}

static int64_t membuf_offset(scap_reader_t* r) {
	struct membuf_reader_handle* h = (struct membuf_reader_handle*)r->handle;
	return (int64_t)h->offset;
}

static int64_t membuf_tell(scap_reader_t* r) {
	struct membuf_reader_handle* h = (struct membuf_reader_handle*)r->handle;
	return (int64_t)h->offset;
}

static int64_t membuf_seek(scap_reader_t* r, int64_t off, int whence) {
	struct membuf_reader_handle* h = (struct membuf_reader_handle*)r->handle;
	int64_t new_offset;

	switch(whence) {
	case SEEK_SET:
		new_offset = off;
		break;
	case SEEK_CUR:
		new_offset = (int64_t)h->offset + off;
		break;
	case SEEK_END:
		new_offset = (int64_t)*h->buffer_size_ptr + off;
		break;
	default:
		return -1;
	}

	if(new_offset < 0 || (uint64_t)new_offset > *h->buffer_size_ptr) {
		return -1;
	}

	h->offset = (uint64_t)new_offset;
	return new_offset;
}

static const char* membuf_error(scap_reader_t* r, int* errnum) {
	(void)r;
	if(errnum) {
		*errnum = 0;
	}
	return "";
}

static int membuf_close(scap_reader_t* r) {
	if(r) {
		free(r->handle);
		free(r);
	}
	return 0;
}

scap_reader_t* scap_reader_open_membuf(uint8_t** buffer_ptr, uint64_t* buffer_size_ptr) {
	struct membuf_reader_handle* handle = calloc(1, sizeof(*handle));
	if(!handle) {
		return NULL;
	}
	handle->buffer_ptr = buffer_ptr;
	handle->buffer_size_ptr = buffer_size_ptr;
	handle->offset = 0;

	scap_reader_t* reader = calloc(1, sizeof(*reader));
	if(!reader) {
		free(handle);
		return NULL;
	}

	reader->handle = handle;
	reader->read = membuf_read;
	reader->offset = membuf_offset;
	reader->tell = membuf_tell;
	reader->seek = membuf_seek;
	reader->error = membuf_error;
	reader->close = membuf_close;

	return reader;
}
