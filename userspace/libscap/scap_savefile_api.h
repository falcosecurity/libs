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

#include <stdbool.h>
#include <stdint.h>

#include <libscap/scap_const.h>
#include <libscap/scap_zlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scap_platform;

typedef enum ppm_dumper_type
{
	DT_FILE = 0,
	DT_MEM = 1,
	DT_MANAGED_BUF = 2,
} ppm_dumper_type;

#define PPM_DUMPER_MANAGED_BUF_SIZE (3 * 1024 * 1024)
#define PPM_DUMPER_MANAGED_BUF_RESIZE_FACTOR (1.25)

typedef struct scap_dumper
{
	gzFile m_f;
	ppm_dumper_type m_type;
	uint8_t* m_targetbuf;
	uint8_t* m_targetbufcurpos;
	uint8_t* m_targetbufend;
	char m_lasterr[SCAP_LASTERR_SIZE];
} scap_dumper_t;

struct scap_threadinfo;
typedef struct ppm_evt_hdr scap_evt;
struct iovec;

/*!
  \brief Indicates the compression type used when writing a tracefile
*/
typedef enum compression_mode
{
	SCAP_COMPRESSION_NONE = 0,
	SCAP_COMPRESSION_GZIP = 1
} compression_mode;

uint8_t* scap_get_memorydumper_curpos(scap_dumper_t *d);
int32_t scap_write_proc_fds(scap_dumper_t *d, struct scap_threadinfo *tinfo);
scap_dumper_t* scap_write_proclist_begin();
int scap_write_proclist_end(scap_dumper_t *d, scap_dumper_t *proclist_dumper, uint32_t totlen);
scap_dumper_t *scap_memory_dump_open(struct scap_platform* platform, uint8_t* targetbuf, uint64_t targetbufsize, char* lasterr);
scap_dumper_t *scap_managedbuf_dump_create();

// Variant of scap_write_proclist_entry where array-backed information
// about the thread is provided separate from the scap_threadinfo
// struct.
int32_t scap_write_proclist_entry_bufs(scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len,
				       const char *comm,
				       const char *exe,
				       const char *exepath,
				       const struct iovec *args, int argscnt,
				       const struct iovec *envs, int envscnt,
				       const char *cwd,
				       const struct iovec *cgroups, int cgroupscnt,
				       const char *root);

/*!
  \brief Open a trace file for writing

  \param handle Handle to the capture instance.
  \param fname The name of the trace file.

  \return Dump handle that can be used to identify this specific dump instance.
*/
scap_dumper_t *scap_dump_open(struct scap_platform *platform, const char *fname, compression_mode compress,
			      char *lasterr);

/*!
  \brief Open a trace file for writing, using the provided fd.

  \param handle Handle to the capture instance.
  \param fd A file descriptor to which the dumper will write

  \return Dump handle that can be used to identify this specific dump instance.
*/
scap_dumper_t* scap_dump_open_fd(struct scap_platform* platform, int fd, compression_mode compress, bool skip_proc_scan, char* lasterr);

/*!
  \brief Close a trace file.

  \param d The dump handle, returned by \ref scap_dump_open
*/
void scap_dump_close(scap_dumper_t *d);

/*!
  \brief Return the current size of a trace file.

  \param d The dump handle, returned by \ref scap_dump_open
  \return The current size of the dump file pointed by d.
*/
int64_t scap_dump_get_offset(scap_dumper_t *d);

/*!
  \brief Return the position for the next write to a trace file.
         This uses gztell, while scap_dump_get_offset uses gzoffset.

  \param d The dump handle, returned by \ref scap_dump_open
  \return The next write position.
*/
int64_t scap_dump_ftell(scap_dumper_t *d);

/*!
  \brief Flush all pending output into the file.

  \param d The dump handle, returned by \ref scap_dump_open
*/
void scap_dump_flush(scap_dumper_t *d);

/*!
  \brief Write an event to a trace file

  \param d The dump handle, returned by \ref scap_dump_open
  \param e pointer to an event returned by \ref scap_next.
  \param cpuid The cpu from which the event was captured. Returned by \ref scap_next.
  \param flags The event flags. 0 means no flags.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_dump_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_dump(scap_dumper_t *d, scap_evt* e, uint16_t cpuid, uint32_t flags);

/*!
  \brief Return a string with the last error that happened on the given dumper.
*/
const char* scap_dump_getlasterr(scap_dumper_t* handle);

#ifdef __cplusplus
}
#endif
