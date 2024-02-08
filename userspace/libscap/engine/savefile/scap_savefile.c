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


#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/uio.h>
#else
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#endif

#define SCAP_HANDLE_T struct savefile_engine
#include <libscap/engine/savefile/savefile.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile.h>
#include <libscap/engine/savefile/savefile_platform.h>
#include <libscap/engine/savefile/scap_reader.h>
#include <libscap/engine/noop/noop.h>

#include <libscap/strl.h>

//
// Read the section header block
//
inline static int read_block_header(struct savefile_engine* handle, struct scap_reader *r, block_header* h)
{
	int res = sizeof(block_header);
	if (!handle->m_use_last_block_header)
	{
		res = r->read(r, &handle->m_last_block_header, sizeof(block_header));
	}
	memcpy(h, &handle->m_last_block_header, sizeof(block_header));
	handle->m_use_last_block_header = false;
	return res;
}

//
// Load the machine info block
//
static int32_t scap_read_machine_info(scap_reader_t* r, scap_machine_info* machine_info, char* error, uint32_t block_length)
{
	//
	// Read the section header block
	//
	if(r->read(r, machine_info, sizeof(*machine_info)) !=
		sizeof(*machine_info))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Parse a process list block
//
static int32_t scap_read_proclist(scap_reader_t* r, uint32_t block_length, uint32_t block_type, struct scap_proclist *proclist, char *error)
{
	size_t readsize;
	size_t subreadsize = 0;
	size_t totreadsize = 0;
	size_t padding_len;
	uint16_t stlen;
	uint32_t padding;
	uint32_t toread;
	int fseekres;

	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		struct scap_threadinfo tinfo;

		tinfo.fdlist = NULL;
		tinfo.flags = 0;
		tinfo.vmsize_kb = 0;
		tinfo.vmrss_kb = 0;
		tinfo.vmswap_kb = 0;
		tinfo.pfmajor = 0;
		tinfo.pfminor = 0;
		tinfo.env_len = 0;
		tinfo.vtid = -1;
		tinfo.vpid = -1;
		tinfo.cgroups.len = 0;
		tinfo.filtered_out = 0;
		tinfo.root[0] = 0;
		tinfo.sid = -1;
		tinfo.vpgid = -1;
		tinfo.clone_ts = 0;
		tinfo.pidns_init_start_ts = 0;
		tinfo.tty = 0;
		tinfo.exepath[0] = 0;
		tinfo.loginuid = UINT32_MAX;
		tinfo.exe_writable = false;
		tinfo.cap_inheritable = 0;
		tinfo.cap_permitted = 0;
		tinfo.cap_effective = 0;
		tinfo.exe_upper_layer = false;
		tinfo.exe_ino = 0;
		tinfo.exe_ino_ctime = 0;
		tinfo.exe_ino_mtime = 0;
		tinfo.exe_from_memfd = false;

		//
		// len
		//
		uint32_t sub_len = 0;
		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
			break;
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(sub_len), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;
			break;
		default:
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// tid
		//
		readsize = r->read(r, &(tinfo.tid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// pid
		//
		readsize = r->read(r, &(tinfo.pid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// ptid
		//
		readsize = r->read(r, &(tinfo.ptid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
			break;
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(tinfo.sid), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;
			break;
		default:
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// vpgid
		//
		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
			break;
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(tinfo.vpgid), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;
			break;
		default:
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// comm
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "invalid commlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.comm, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.comm[stlen] = 0;

		subreadsize += readsize;

		//
		// exe
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "invalid exelen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.exe, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.exe[stlen] = 0;

		subreadsize += readsize;

		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
			break;
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			//
			// exepath
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if(stlen > SCAP_MAX_PATH_SIZE)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "invalid exepathlen %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, tinfo.exepath, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			tinfo.exepath[stlen] = 0;

			subreadsize += readsize;

			break;
		default:
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// args
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if(stlen > SCAP_MAX_ARGS_SIZE)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "invalid argslen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.args, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.args[stlen] = 0;
		tinfo.args_len = stlen;

		subreadsize += readsize;

		//
		// cwd
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "invalid cwdlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.cwd, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.cwd[stlen] = 0;

		subreadsize += readsize;

		//
		// fdlimit
		//
		readsize = r->read(r, &(tinfo.fdlimit), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// flags
		//
		readsize = r->read(r, &(tinfo.flags), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		//
		// uid
		//
		readsize = r->read(r, &(tinfo.uid), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		//
		// gid
		//
		readsize = r->read(r, &(tinfo.gid), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		switch(block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
			break;
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			//
			// vmsize_kb
			//
			readsize = r->read(r, &(tinfo.vmsize_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// vmrss_kb
			//
			readsize = r->read(r, &(tinfo.vmrss_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// vmswap_kb
			//
			readsize = r->read(r, &(tinfo.vmswap_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// pfmajor
			//
			readsize = r->read(r, &(tinfo.pfmajor), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;

			//
			// pfminor
			//
			readsize = r->read(r, &(tinfo.pfminor), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;

			if(block_type == PL_BLOCK_TYPE_V3 ||
				block_type == PL_BLOCK_TYPE_V3_INT ||
				block_type == PL_BLOCK_TYPE_V4 ||
				block_type == PL_BLOCK_TYPE_V5 ||
				block_type == PL_BLOCK_TYPE_V6 ||
				block_type == PL_BLOCK_TYPE_V7 ||
				block_type == PL_BLOCK_TYPE_V8 ||
				block_type == PL_BLOCK_TYPE_V9)
			{
				//
				// env
				//
				readsize = r->read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

				if(stlen > SCAP_MAX_ENV_SIZE)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "invalid envlen %d", stlen);
					return SCAP_FAILURE;
				}

				subreadsize += readsize;

				readsize = r->read(r, tinfo.env, stlen);
				CHECK_READ_SIZE_ERR(readsize, stlen, error);

				// the string is not null-terminated on file
				tinfo.env[stlen] = 0;
				tinfo.env_len = stlen;

				subreadsize += readsize;
			}

			if(block_type == PL_BLOCK_TYPE_V4 ||
			   block_type == PL_BLOCK_TYPE_V5 ||
			   block_type == PL_BLOCK_TYPE_V6 ||
			   block_type == PL_BLOCK_TYPE_V7 ||
			   block_type == PL_BLOCK_TYPE_V8 ||
			   block_type == PL_BLOCK_TYPE_V9)
			{
				//
				// vtid
				//
				readsize = r->read(r, &(tinfo.vtid), sizeof(int64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

				subreadsize += readsize;

				//
				// vpid
				//
				readsize = r->read(r, &(tinfo.vpid), sizeof(int64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

				subreadsize += readsize;

				//
				// cgroups
				//
				readsize = r->read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

				if(stlen > SCAP_MAX_CGROUPS_SIZE)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "invalid cgroupslen %d", stlen);
					return SCAP_FAILURE;
				}
				tinfo.cgroups.len = stlen;

				subreadsize += readsize;

				readsize = r->read(r, tinfo.cgroups.path, stlen);
				CHECK_READ_SIZE_ERR(readsize, stlen, error);

				subreadsize += readsize;

				if(block_type == PL_BLOCK_TYPE_V5 ||
				   block_type == PL_BLOCK_TYPE_V6 ||
				   block_type == PL_BLOCK_TYPE_V7 ||
				   block_type == PL_BLOCK_TYPE_V8 ||
				   block_type == PL_BLOCK_TYPE_V9)
				{
					readsize = r->read(r, &(stlen), sizeof(uint16_t));
					CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

					if(stlen > SCAP_MAX_PATH_SIZE)
					{
						snprintf(error, SCAP_LASTERR_SIZE, "invalid rootlen %d", stlen);
						return SCAP_FAILURE;
					}

					subreadsize += readsize;

					readsize = r->read(r, tinfo.root, stlen);
					CHECK_READ_SIZE_ERR(readsize, stlen, error);

					// the string is not null-terminated on file
					tinfo.root[stlen] = 0;

					subreadsize += readsize;
				}
			}
			break;
		default:
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		// If new parameters are added, sub_len can be used to
		// see if they are available in the current capture.
		// For example, for a 32bit parameter:
		//
		// if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
		// {
		//    ...
		// }

		// In 0.10.x libs tag, 2 fields were added to the scap file producer,
		// written in the middle of the proclist entry, breaking forward compatibility
		// for old scap file readers.
		// Detect this hacky behavior, and manage it.
		// Added fields:
		// * exe_upper_layer
		// * exe_ino
		// * exe_ino_ctime
		// * exe_ino_mtime
		// * pidns_init_start_ts (in the middle)
		// * tty (in the middle)
		// So, to check if we need to enable the "pre-0.10.x hack",
		// we need to check if remaining data to be read is <= than
		// sum of sizes for fields existent in libs < 0.10.x, ie:
		// * loginuid (4B)
		// * exe_writable (1B)
		// * cap_inheritable (8B)
		// * cap_permitted (8B)
		// * cap_effective (8B)
		// TOTAL: 29B
		bool pre_0_10_0 = false;
		if (sub_len - subreadsize <= 29)
		{
			pre_0_10_0 = true;
		}

		if (!pre_0_10_0)
		{
			// Ok we are in libs >= 0.10.x; read the fields that
			// were added interleaved in libs 0.10.0

			//
			// pidns_init_start_ts
			//
			if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
			{
				readsize = r->read(r, &(tinfo.pidns_init_start_ts), sizeof(uint64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
				subreadsize += readsize;
			}

			//
			// tty
			//
			if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
			{
				readsize = r->read(r, &(tinfo.tty), sizeof(uint32_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);
				subreadsize += readsize;
			}
		}

		//
		// loginuid (auid)
		//
		if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.loginuid), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);
			subreadsize += readsize;
		}

		//
		// exe_writable
		//
		if(sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_writable), sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
		}

		//
		// Capabilities
		//
		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_inheritable), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_permitted), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_effective), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_upper_layer
		if(sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_upper_layer), sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
		}

		// exe_ino
		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_ino_ctime
		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino_ctime), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_ino_mtime
		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino_mtime), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_from_memfd
		if(sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			uint8_t exe_from_memfd = 0;
			readsize = r->read(r, &exe_from_memfd, sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
			tinfo.exe_from_memfd = (exe_from_memfd != 0);
		}

		//
		// All parsed. Add the entry to the table, or fire the notification callback
		//
		proclist->m_proc_callback(proclist->m_proc_callback_context, error, tinfo.tid, &tinfo, NULL, NULL);

		if(sub_len && subreadsize != sub_len)
		{
			if(subreadsize > sub_len)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Had read %lu bytes, but proclist entry have length %u.",
					 subreadsize, sub_len);
				return SCAP_FAILURE;
			}
			toread = sub_len - subreadsize;
			fseekres = (int) r->seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
				         (unsigned int)toread);
				return SCAP_FAILURE;
			}
			subreadsize = sub_len;
		}

		totreadsize += subreadsize;
		subreadsize = 0;
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "scap_read_proclist read more %lu than a block %u", totreadsize, block_length);
		ASSERT(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = (size_t)r->read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE_ERR(readsize, padding_len, error);

	return SCAP_SUCCESS;
}

//
// Parse an interface list block
//
static int32_t scap_read_iflist(scap_reader_t* r, uint32_t block_length, uint32_t block_type, scap_addrlist** addrlist_p, char* error)
{
	int32_t res = SCAP_SUCCESS;
	size_t readsize;
	size_t totreadsize;
	char *readbuf = NULL;
	char *pif;
	uint16_t iftype;
	uint16_t ifnamlen;
	uint32_t toread;
	uint32_t entrysize;
	uint32_t ifcnt4 = 0;
	uint32_t ifcnt6 = 0;

	//
	// If the list of interfaces was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	if((*addrlist_p) != NULL)
	{
		scap_free_iflist((*addrlist_p));
		(*addrlist_p) = NULL;
	}

	//
	// Bring the block to memory
	// We assume that this block is always small enough that we can read it in a single shot
	//
	readbuf = (char *)malloc(block_length);
	if(!readbuf)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_iflist");
		return SCAP_FAILURE;
	}

	readsize = r->read(r, readbuf, block_length);
	CHECK_READ_SIZE_WITH_FREE_ERR(readbuf, readsize, block_length, error);

	//
	// First pass, count the number of addresses
	//
	pif = readbuf;
	totreadsize = 0;

	while(true)
	{
		toread = (int32_t)block_length - (int32_t)totreadsize;

		if(toread < 4)
		{
			break;
		}

		if(block_type != IL_BLOCK_TYPE_V2)
		{
			memcpy(&iftype, pif, sizeof(iftype));
			memcpy(&ifnamlen, pif + 2, sizeof(ifnamlen));

			if(iftype == SCAP_II_IPV4)
			{
				entrysize = sizeof(scap_ifinfo_ipv4) + ifnamlen - SCAP_MAX_PATH_SIZE;
			}
			else if(iftype == SCAP_II_IPV6)
			{
				entrysize = sizeof(scap_ifinfo_ipv6) + ifnamlen - SCAP_MAX_PATH_SIZE;
			}
			else if(iftype == SCAP_II_IPV4_NOLINKSPEED)
			{
				entrysize = sizeof(scap_ifinfo_ipv4_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;
			}
			else if(iftype == SCAP_II_IPV6_NOLINKSPEED)
			{
				entrysize = sizeof(scap_ifinfo_ipv6_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;
			}
			else
			{
				snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}
		}
		else
		{
			memcpy(&entrysize, pif, sizeof(entrysize));
			entrysize += sizeof(uint32_t);
			memcpy(&iftype, pif + 4, sizeof(iftype));
			memcpy(&ifnamlen, pif + 4 + 2, sizeof(ifnamlen));
		}

		if(toread < entrysize)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(2) toread=%u, entrysize=%u", toread, entrysize);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		pif += entrysize;
		totreadsize += entrysize;

		if(iftype == SCAP_II_IPV4 || iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV6 || iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			ifcnt6++;
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}

	//
	// Allocate the handle and the arrays
	//
	(*addrlist_p) = (scap_addrlist *)malloc(sizeof(scap_addrlist));
	if(!(*addrlist_p))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(1)");
		res = SCAP_FAILURE;
		goto scap_read_iflist_error;
	}

	(*addrlist_p)->n_v4_addrs = 0;
	(*addrlist_p)->n_v6_addrs = 0;
	(*addrlist_p)->v4list = NULL;
	(*addrlist_p)->v6list = NULL;
	(*addrlist_p)->totlen = block_length - (ifcnt4 + ifcnt6) * sizeof(uint32_t);

	if(ifcnt4 != 0)
	{
		(*addrlist_p)->v4list = (scap_ifinfo_ipv4 *)malloc(ifcnt4 * sizeof(scap_ifinfo_ipv4));
		if(!(*addrlist_p)->v4list)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(2)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		(*addrlist_p)->v4list = NULL;
	}

	if(ifcnt6 != 0)
	{
		(*addrlist_p)->v6list = (scap_ifinfo_ipv6 *)malloc(ifcnt6 * sizeof(scap_ifinfo_ipv6));
		if(!(*addrlist_p)->v6list)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "getifaddrs allocation failed(3)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		(*addrlist_p)->v6list = NULL;
	}

	(*addrlist_p)->n_v4_addrs = ifcnt4;
	(*addrlist_p)->n_v6_addrs = ifcnt6;

	//
	// Second pass: populate the arrays
	//
	ifcnt4 = 0;
	ifcnt6 = 0;
	pif = readbuf;
	totreadsize = 0;

	while(true)
	{
		toread = (int32_t)block_length - (int32_t)totreadsize;
		entrysize = 0;

		if(toread < 4)
		{
			break;
		}

		if(block_type == IL_BLOCK_TYPE_V2)
		{
			memcpy(&entrysize, pif, sizeof(entrysize));
			totreadsize += sizeof(uint32_t);
			pif += sizeof(uint32_t);
		}

		memcpy(&iftype, pif, sizeof(iftype));
		memcpy(&ifnamlen, pif + 2, sizeof(ifnamlen));

		if(ifnamlen >= SCAP_MAX_PATH_SIZE)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(0)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		// If new parameters are added, entrysize can be used to
		// see if they are available in the current capture.
		// For example, for a 32bit parameter:
		//
		// if(entrysize && (ifsize + sizeof(uint32_t)) <= entrysize)
		// {
		//    ifsize += sizeof(uint32_t);
		//    ...
		// }

		uint32_t ifsize;
		if(iftype == SCAP_II_IPV4)
		{
			ifsize = sizeof(uint16_t) + // type
				sizeof(uint16_t) +  // ifnamelen
				sizeof(uint32_t) +  // addr
				sizeof(uint32_t) +  // netmask
				sizeof(uint32_t) +  // bcast
				sizeof(uint64_t) +  // linkspeed
			        ifnamlen;

			if(toread < ifsize)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(3)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy((*addrlist_p)->v4list + ifcnt4, pif, ifsize - ifnamlen);

			memcpy((*addrlist_p)->v4list[ifcnt4].ifname, pif + ifsize - ifnamlen, ifnamlen);

			// Make sure the name string is NULL-terminated
			*((char *)((*addrlist_p)->v4list + ifcnt4) + ifsize) = 0;

			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			scap_ifinfo_ipv4_nolinkspeed* src;
			scap_ifinfo_ipv4* dst;

			ifsize = sizeof(scap_ifinfo_ipv4_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < ifsize)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(4)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv4_nolinkspeed*)pif;
			dst = (*addrlist_p)->v4list + ifcnt4;

			dst->type = src->type;
			dst->ifnamelen = src->ifnamelen;
			dst->addr = src->addr;
			dst->netmask = src->netmask;
			dst->bcast = src->bcast;
			dst->linkspeed = 0;
			memcpy(dst->ifname, src->ifname, MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1));

			// Make sure the name string is NULL-terminated
			*((char *)(dst->ifname + MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1))) = 0;

			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV6)
		{
			ifsize = sizeof(uint16_t) +  // type
				sizeof(uint16_t) +   // ifnamelen
				SCAP_IPV6_ADDR_LEN + // addr
				SCAP_IPV6_ADDR_LEN + // netmask
				SCAP_IPV6_ADDR_LEN + // bcast
				sizeof(uint64_t) +   // linkspeed
				ifnamlen;

			if(toread < ifsize)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(5)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy((*addrlist_p)->v6list + ifcnt6, pif, ifsize - ifnamlen);

			memcpy((*addrlist_p)->v6list[ifcnt6].ifname, pif + ifsize - ifnamlen, ifnamlen);

			// Make sure the name string is NULL-terminated
			*((char *)((*addrlist_p)->v6list + ifcnt6) + ifsize) = 0;

			ifcnt6++;
		}
		else if(iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			scap_ifinfo_ipv6_nolinkspeed* src;
			scap_ifinfo_ipv6* dst;
			ifsize = sizeof(scap_ifinfo_ipv6_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < ifsize)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(6)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv6_nolinkspeed*)pif;
			dst = (*addrlist_p)->v6list + ifcnt6;

			dst->type = src->type;
			dst->ifnamelen = src->ifnamelen;
			memcpy(dst->addr, src->addr, SCAP_IPV6_ADDR_LEN);
			memcpy(dst->netmask, src->netmask, SCAP_IPV6_ADDR_LEN);
			memcpy(dst->bcast, src->bcast, SCAP_IPV6_ADDR_LEN);
			dst->linkspeed = 0;
			memcpy(dst->ifname, src->ifname, MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1));

			// Make sure the name string is NULL-terminated
			*((char *)(dst->ifname + MIN(dst->ifnamelen, SCAP_MAX_PATH_SIZE - 1))) = 0;

			ifcnt6++;
		}
		else
		{
			ASSERT(false);
			snprintf(error, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}

		entrysize = entrysize ? entrysize : ifsize;

		pif += entrysize;
		totreadsize += entrysize;
	}

	//
	// Release the read storage
	//
	free(readbuf);

	return res;

scap_read_iflist_error:
	scap_free_iflist((*addrlist_p));
	(*addrlist_p) = NULL;

	if(readbuf)
	{
		free(readbuf);
	}

	return res;
}

//
// Parse a user list block
//
static int32_t scap_read_userlist(scap_reader_t* r, uint32_t block_length, uint32_t block_type, scap_userlist** userlist_p, char* error)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t subreadsize = 0;
	size_t padding_len;
	uint32_t padding;
	uint8_t type;
	uint16_t stlen;
	uint32_t toread;
	int fseekres;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first user list block), free it
	//
	if((*userlist_p) != NULL)
	{
		scap_free_userlist((*userlist_p));
		(*userlist_p) = NULL;
	}

	//
	// Allocate and initialize the handle info
	//
	(*userlist_p) = (scap_userlist*)malloc(sizeof(scap_userlist));
	if((*userlist_p) == NULL)
	{
		snprintf(error,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		return SCAP_FAILURE;
	}

	(*userlist_p)->nusers = 0;
	(*userlist_p)->ngroups = 0;
	(*userlist_p)->totsavelen = 0;
	(*userlist_p)->users = NULL;
	(*userlist_p)->groups = NULL;

	//
	// Import the blocks
	//
	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		uint32_t sub_len = 0;
		if(block_type == UL_BLOCK_TYPE_V2)
		{
			//
			// len
			//
			readsize = r->read(r, &(sub_len), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;
		}

		//
		// type
		//
		readsize = r->read(r, &(type), sizeof(type));
		CHECK_READ_SIZE_ERR(readsize, sizeof(type), error);

		subreadsize += readsize;

		if(type == USERBLOCK_TYPE_USER)
		{
			scap_userinfo* puser;

			(*userlist_p)->nusers++;
			scap_userinfo *new_userlist = (scap_userinfo*)realloc((*userlist_p)->users, (*userlist_p)->nusers * sizeof(scap_userinfo));
			if(new_userlist == NULL)
			{
				free((*userlist_p)->users);
				(*userlist_p)->users = NULL;
				snprintf(error, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(1)");
				return SCAP_FAILURE;
			}
			(*userlist_p)->users = new_userlist;

			puser = &(*userlist_p)->users[(*userlist_p)->nusers -1];

			//
			// uid
			//
			readsize = r->read(r, &(puser->uid), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// gid
			//
			readsize = r->read(r, &(puser->gid), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// name
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "invalid user name len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, puser->name, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			puser->name[stlen] = 0;

			subreadsize += readsize;

			//
			// homedir
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "invalid user homedir len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, puser->homedir, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			puser->homedir[stlen] = 0;

			subreadsize += readsize;

			//
			// shell
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "invalid user shell len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, puser->shell, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			puser->shell[stlen] = 0;

			subreadsize += readsize;

			// If new parameters are added, sub_len can be used to
			// see if they are available in the current capture.
			// For example, for a 32bit parameter:
			//
			// if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
			// {
			//    ...
			// }
		}
		else
		{
			scap_groupinfo* pgroup;

			(*userlist_p)->ngroups++;
			scap_groupinfo *new_grouplist = (scap_groupinfo*)realloc((*userlist_p)->groups, (*userlist_p)->ngroups * sizeof(scap_groupinfo));
			if(new_grouplist == NULL)
			{
				free((*userlist_p)->groups);
				(*userlist_p)->groups = NULL;
				snprintf(error, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(2)");
				return SCAP_FAILURE;
			}
			(*userlist_p)->groups = new_grouplist;

			pgroup = &(*userlist_p)->groups[(*userlist_p)->ngroups -1];

			//
			// gid
			//
			readsize = r->read(r, &(pgroup->gid), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// name
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "invalid group name len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, pgroup->name, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			pgroup->name[stlen] = 0;

			subreadsize += readsize;

			// If new parameters are added, sub_len can be used to
			// see if they are available in the current capture.
			// For example, for a 32bit parameter:
			//
			// if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
			// {
			//    ...
			// }
		}

		if(sub_len && subreadsize != sub_len)
		{
			if(subreadsize > sub_len)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Had read %lu bytes, but userlist entry have length %u.",
					 subreadsize, sub_len);
				return SCAP_FAILURE;
			}
			toread = sub_len - subreadsize;
			fseekres = (int) r->seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
				         (unsigned int)toread);
				return SCAP_FAILURE;
			}
			subreadsize = sub_len;
		}

		totreadsize += subreadsize;
		subreadsize = 0;
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		snprintf(error, SCAP_LASTERR_SIZE, "scap_read_userlist read more %lu than a block %u", totreadsize, block_length);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = r->read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE_ERR(readsize, padding_len, error);

	return SCAP_SUCCESS;
}

static uint32_t scap_fd_read_prop_from_disk(void *target, size_t expected_size, size_t *nbytes, scap_reader_t *r, char *error)
{
	size_t readsize;
	readsize = r->read(r, target, (unsigned int)expected_size);
	CHECK_READ_SIZE_ERR(readsize, expected_size, error);
	(*nbytes) += readsize;
	return SCAP_SUCCESS;
}

static uint32_t scap_fd_read_fname_from_disk(char *fname, size_t *nbytes, scap_reader_t *r, char *error)
{
	size_t readsize;
	uint16_t stlen;

	readsize = r->read(r, &(stlen), sizeof(uint16_t));
	CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

	if(stlen >= SCAP_MAX_PATH_SIZE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "invalid filename len %" PRId32, stlen);
		return SCAP_FAILURE;
	}

	(*nbytes) += readsize;

	readsize = r->read(r, fname, stlen);
	CHECK_READ_SIZE_ERR(readsize, stlen, error);

	(*nbytes) += stlen;

	// NULL-terminate the string
	fname[stlen] = 0;
	return SCAP_SUCCESS;
}

//
// Populate the given fd by reading the info from disk
// Returns the number of read bytes.
//
static uint32_t scap_fd_read_from_disk(scap_fdinfo *fdi, size_t *nbytes, uint32_t block_type, scap_reader_t *r, char *error)
{
	uint8_t type;
	uint32_t toread;
	int fseekres;
	uint32_t sub_len = 0;
	uint32_t res = SCAP_SUCCESS;
	*nbytes = 0;

	if((block_type == FDL_BLOCK_TYPE_V2 &&
	    scap_fd_read_prop_from_disk(&sub_len, sizeof(uint32_t), nbytes, r, error)) ||
	   scap_fd_read_prop_from_disk(&(fdi->fd), sizeof(fdi->fd), nbytes, r, error) ||
	   scap_fd_read_prop_from_disk(&(fdi->ino), sizeof(fdi->ino), nbytes, r, error) ||
	   scap_fd_read_prop_from_disk(&type, sizeof(uint8_t), nbytes, r, error))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read prop block for fd");
		return SCAP_FAILURE;
	}

	// If new parameters are added, sub_len can be used to
	// see if they are available in the current capture.
	// For example, for a 32bit parameter:
	//
	// if(sub_len && (*nbytes + sizeof(uint32_t)) <= sub_len)
	// {
	//    ...
	// }

	fdi->type = (scap_fd_type)type;

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		if(r->read(r, &(fdi->info.ipv4info.sip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   r->read(r, &(fdi->info.ipv4info.dip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   r->read(r, &(fdi->info.ipv4info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv4info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv4info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error reading the fd info from file (1)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t));

		break;
	case SCAP_FD_IPV4_SERVSOCK:
		if(r->read(r, &(fdi->info.ipv4serverinfo.ip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   r->read(r, &(fdi->info.ipv4serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv4serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error reading the fd info from file (2)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t));
		break;
	case SCAP_FD_IPV6_SOCK:
		if(r->read(r, (char *)fdi->info.ipv6info.sip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   r->read(r, (char *)fdi->info.ipv6info.dip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   r->read(r, &(fdi->info.ipv6info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv6info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv6info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error writing to file (fi3)");
		}
		(*nbytes) += (sizeof(uint32_t) * 4 + // sip
			      sizeof(uint32_t) * 4 + // dip
			      sizeof(uint16_t) +     // sport
			      sizeof(uint16_t) +     // dport
			      sizeof(uint8_t));      // l4proto
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		if(r->read(r, (char *)fdi->info.ipv6serverinfo.ip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   r->read(r, &(fdi->info.ipv6serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   r->read(r, &(fdi->info.ipv6serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error writing to file (fi4)");
		}
		(*nbytes) += (sizeof(uint32_t) * 4 + // ip
			      sizeof(uint16_t) +     // port
			      sizeof(uint8_t));      // l4proto
		break;
	case SCAP_FD_UNIX_SOCK:
		if(r->read(r, &(fdi->info.unix_socket_info.source), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   r->read(r, &(fdi->info.unix_socket_info.destination), sizeof(uint64_t)) != sizeof(uint64_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error reading the fd info from file (fi5)");
			return SCAP_FAILURE;
		}

		(*nbytes) += (sizeof(uint64_t) + sizeof(uint64_t));
		res = scap_fd_read_fname_from_disk(fdi->info.unix_socket_info.fname, nbytes, r, error);
		break;
	case SCAP_FD_FILE_V2:
		if(r->read(r, &(fdi->info.regularinfo.open_flags), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error reading the fd info from file (fi1)");
			return SCAP_FAILURE;
		}

		(*nbytes) += sizeof(uint32_t);
		res = scap_fd_read_fname_from_disk(fdi->info.regularinfo.fname, nbytes, r, error);
		if(!sub_len || (sub_len < *nbytes + sizeof(uint32_t)))
		{
			break;
		}
		if(r->read(r, &(fdi->info.regularinfo.dev), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(error, SCAP_LASTERR_SIZE, "error reading the fd info from file (dev)");
			return SCAP_FAILURE;
		}
		(*nbytes) += sizeof(uint32_t);
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
	case SCAP_FD_BPF:
	case SCAP_FD_USERFAULTFD:
	case SCAP_FD_IOURING:
	case SCAP_FD_MEMFD:
	case SCAP_FD_PIDFD:
		res = scap_fd_read_fname_from_disk(fdi->info.fname, nbytes, r, error);
		break;
	case SCAP_FD_UNKNOWN:
		ASSERT(false);
		break;
	default:
		// unknown fd type, possibly coming from a newer library version
		fdi->type = SCAP_FD_UNSUPPORTED;
		snprintf(fdi->info.fname, sizeof(fdi->info.fname), "unknown-type:[%d]", (int)type);
		break;
	}

	if(sub_len && *nbytes != sub_len)
	{
		if(*nbytes > sub_len)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Had read %zu bytes, but fdlist entry have length %u.",
				 *nbytes, sub_len);
			return SCAP_FAILURE;
		}
		toread = (uint32_t)(sub_len - *nbytes);
		fseekres = (int) r->seek(r, (long)toread, SEEK_CUR);
		if(fseekres == -1)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
				 (unsigned int)toread);
			return SCAP_FAILURE;
		}
		*nbytes = sub_len;
	}

	return res;
}

//
// Parse a file descriptor list block
//
static int32_t scap_read_fdlist(scap_reader_t* r, uint32_t block_length, uint32_t block_type, struct scap_proclist* proclist, char* error)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t padding_len;
	scap_fdinfo fdi;
	//  uint16_t stlen;
	uint64_t tid;
	uint32_t padding;

	//
	// Read the tid
	//
	readsize = r->read(r, &tid, sizeof(tid));
	CHECK_READ_SIZE_ERR(readsize, sizeof(tid), error);
	totreadsize += readsize;

	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		if(scap_fd_read_from_disk(&fdi, &readsize, block_type, r, error) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
		totreadsize += readsize;
		//
		// Add the entry to the table, or fire the notification callback
		//
		proclist->m_proc_callback(proclist->m_proc_callback_context, error, tid, NULL, &fdi, NULL);
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		snprintf(error, SCAP_LASTERR_SIZE, "scap_read_fdlist read more %lu than a block %u", totreadsize, block_length);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = r->read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE_ERR(readsize, padding_len, error);

	return SCAP_SUCCESS;
}

static int32_t scap_read_section_header(scap_reader_t* r, char* error)
{
	section_header_block sh;
	uint32_t bt;

	//
	// Read the section header block
	//
	if(r->read(r, &sh, sizeof(sh)) != sizeof(sh) ||
	   r->read(r, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(sh.byte_order_magic != 0x1a2b3c4d)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "invalid magic number");
		return SCAP_FAILURE;
	}

	if(sh.major_version > CURRENT_MAJOR_VERSION)
	{
		snprintf(error, SCAP_LASTERR_SIZE,
			 "cannot correctly parse the capture. Upgrade your version.");
		return SCAP_VERSION_MISMATCH;
	}

	return SCAP_SUCCESS;
}

//
// Parse the headers of a trace file and load the tables
//
static int32_t scap_read_init(struct savefile_engine *handle, scap_reader_t* r, scap_machine_info* machine_info_p, struct scap_proclist* proclist_p, scap_addrlist** addrlist_p, scap_userlist** userlist_p, char* error)
{
	block_header bh;
	uint32_t bt;
	size_t readsize;
	size_t toread;
	int fseekres;
	int32_t rc;
	int8_t found_ev = 0;

	//
	// Read the section header block
	//
	if(read_block_header(handle, r, &bh) != sizeof(bh))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(bh.block_type != SHB_BLOCK_TYPE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "invalid block type");
		return SCAP_FAILURE;
	}

	if((rc = scap_read_section_header(r, error)) != SCAP_SUCCESS)
	{
		return rc;
	}

	//
	// Read the metadata blocks (processes, FDs, etc.)
	//
	while(true)
	{
		readsize = read_block_header(handle, r, &bh);

		//
		// If we don't find the event block header,
		// it means there is no event in the file.
		//
		if (readsize == 0 && !found_ev)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "no events in file");
			return SCAP_FAILURE;
		}

		CHECK_READ_SIZE_ERR(readsize, sizeof(bh), error);

		switch(bh.block_type)
		{
		case MI_BLOCK_TYPE:
		case MI_BLOCK_TYPE_INT:

			if(scap_read_machine_info(
				   r,
				   machine_info_p,
				   error,
				   bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3_INT:

			if(scap_read_proclist(r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type, proclist_p, error) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case FDL_BLOCK_TYPE:
		case FDL_BLOCK_TYPE_INT:
		case FDL_BLOCK_TYPE_V2:

			if(scap_read_fdlist(r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type, proclist_p, error) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case EV_BLOCK_TYPE:
		case EV_BLOCK_TYPE_INT:
		case EV_BLOCK_TYPE_V2:
		case EVF_BLOCK_TYPE:
		case EVF_BLOCK_TYPE_V2:
		case EV_BLOCK_TYPE_V2_LARGE:
		case EVF_BLOCK_TYPE_V2_LARGE:
			//
			// We're done with the metadata headers.
			//
			found_ev = 1;
			handle->m_use_last_block_header = true;
			break;
		case IL_BLOCK_TYPE:
		case IL_BLOCK_TYPE_INT:
		case IL_BLOCK_TYPE_V2:

			if(scap_read_iflist(r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type, addrlist_p, error) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case UL_BLOCK_TYPE:
		case UL_BLOCK_TYPE_INT:
		case UL_BLOCK_TYPE_V2:

			if(scap_read_userlist(r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type, userlist_p, error) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		default:
			//
			// Unknown block type. Skip the block.
			//
			toread = bh.block_total_length - sizeof(block_header) - 4;
			fseekres = (int) r->seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip block of type %x and size %u.",
				         (int)bh.block_type,
				         (unsigned int)toread);
				return SCAP_FAILURE;
			}
			break;
		}

		if(found_ev)
		{
			break;
		}

		//
		// Read and validate the trailer
		//
		readsize = r->read(r, &bt, sizeof(bt));
		CHECK_READ_SIZE_ERR(readsize, sizeof(bt), error);

		if(bt != bh.block_total_length)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "wrong block total length, header=%u, trailer=%u",
			         bh.block_total_length,
			         bt);
			return SCAP_FAILURE;
		}
	}

	//
	// NOTE: can't require a user list block, interface list block, or machine info block
	//       any longer--with the introduction of source plugins, it is legitimate to have
	//       trace files that don't contain those blocks
	//

	return SCAP_SUCCESS;
}

//
// Read an event from disk
//
static int32_t next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pdevid, uint32_t *pflags)
{
	struct savefile_engine* handle = engine.m_handle;
	block_header bh;
	size_t readsize;
	uint32_t readlen;
	size_t hdr_len;
	scap_reader_t* r = handle->m_reader;

	ASSERT(r != NULL);

	//
	// We may have to repeat the whole process
	// if the capture contains new syscalls
	//
	while(true)
	{
		//
		// Read the block header
		//
		readsize = read_block_header(handle, r, &bh);

		if(readsize != sizeof(bh))
		{
			int err_no = 0;
#ifdef _WIN32
			const char* err_str = "read error";
#else
			const char* err_str = r->error(r, &err_no);
#endif
			if(err_no)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading file: %s, ernum=%d", err_str, err_no);
				return SCAP_FAILURE;
			}

			if(readsize == 0)
			{
				//
				// We read exactly 0 bytes. This indicates a correct end of file.
				//
				return SCAP_EOF;
			}
			else
			{
				CHECK_READ_SIZE(readsize, sizeof(bh));
			}
		}

		if(bh.block_type != EV_BLOCK_TYPE &&
		   bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EV_BLOCK_TYPE_INT &&
		   bh.block_type != EVF_BLOCK_TYPE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unexpected block type %u", (uint32_t)bh.block_type);
			handle->m_use_last_block_header = true;
			return SCAP_UNEXPECTED_BLOCK;
		}

		hdr_len = sizeof(struct ppm_evt_hdr);
		if(bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			hdr_len -= 4;
		}

		if(bh.block_total_length < sizeof(bh) + hdr_len + 4)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "block length too short %u", (uint32_t)bh.block_total_length);
			return SCAP_FAILURE;
		}

		//
		// Read the event
		//
		readlen = bh.block_total_length - sizeof(bh);
		// Non-large block types have an uint16_max maximum size
		if (bh.block_type != EV_BLOCK_TYPE_V2_LARGE && bh.block_type != EVF_BLOCK_TYPE_V2_LARGE) {
			if(readlen > READER_BUF_SIZE) {
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than NON-LARGE read buffer size %u",
					 readlen,
					 READER_BUF_SIZE);
				return SCAP_FAILURE;
			}
		} else if (readlen > handle->m_reader_evt_buf_size) {
			// Try to allocate a buffer large enough
			char *tmp = realloc(handle->m_reader_evt_buf, readlen);
			if (!tmp) {
				free(handle->m_reader_evt_buf);
				handle->m_reader_evt_buf = NULL;
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than read buffer size %zu",
					 readlen,
					 handle->m_reader_evt_buf_size);
				return SCAP_FAILURE;
			}
			handle->m_reader_evt_buf = tmp;
			handle->m_reader_evt_buf_size = readlen;
		}

		readsize = r->read(r, handle->m_reader_evt_buf, readlen);
		CHECK_READ_SIZE(readsize, readlen);

		//
		// EVF_BLOCK_TYPE has 32 bits of flags
		//
		*pdevid = *(uint16_t *)handle->m_reader_evt_buf;

		if(bh.block_type == EVF_BLOCK_TYPE || bh.block_type == EVF_BLOCK_TYPE_V2 || bh.block_type == EVF_BLOCK_TYPE_V2_LARGE)
		{
			memcpy(pflags, handle->m_reader_evt_buf + sizeof(uint16_t), sizeof(uint32_t));
			*pevent = (struct ppm_evt_hdr *)(handle->m_reader_evt_buf + sizeof(uint16_t) + sizeof(uint32_t));
		}
		else
		{
			*pflags = 0;
			*pevent = (struct ppm_evt_hdr *)(handle->m_reader_evt_buf + sizeof(uint16_t));
		}

		if((*pevent)->type >= PPM_EVENT_MAX)
		{
			//
			// We're reading a capture that contains new syscalls.
			// We can't do anything else that skips them.
			//
			continue;
		}

		if(bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			//
			// We're reading an old capture whose events don't have nparams in the header.
			// Convert it to the current version.
			//
			if((readlen + sizeof(uint32_t)) > READER_BUF_SIZE)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (%lu greater than read buffer size %u)",
					 readlen + sizeof(uint32_t),
					 READER_BUF_SIZE);
				return SCAP_FAILURE;
			}

			memmove((char *)*pevent + sizeof(struct ppm_evt_hdr),
				(char *)*pevent + sizeof(struct ppm_evt_hdr) - sizeof(uint32_t),
				readlen - ((char *)*pevent - handle->m_reader_evt_buf) - (sizeof(struct ppm_evt_hdr) - sizeof(uint32_t)));
			(*pevent)->len += sizeof(uint32_t);

			// In old captures, the length of PPME_NOTIFICATION_E and PPME_INFRASTRUCTURE_EVENT_E
			// is not correct. Adjust it, otherwise the following code will never find a match
			if((*pevent)->type == PPME_NOTIFICATION_E || (*pevent)->type == PPME_INFRASTRUCTURE_EVENT_E)
			{
				(*pevent)->len -= 3;
			}

			//
			// The number of parameters needs to be calculated based on the block len.
			// Use the current number of parameters as starting point and decrease it
			// until size matches.
			//
			char *end = (char *)*pevent + (*pevent)->len;
			uint16_t *lens = (uint16_t *)((char *)*pevent + sizeof(struct ppm_evt_hdr));
			uint32_t nparams;
			bool done = false;
			for(nparams = g_event_info[(*pevent)->type].nparams; (int)nparams >= 0; nparams--)
			{
				char *valptr = (char *)lens + nparams * sizeof(uint16_t);
				if(valptr > end)
				{
					continue;
				}
				uint32_t i;
				for(i = 0; i < nparams; i++)
				{
					valptr += lens[i];
				}
				if(valptr < end)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (corrupted trace file - can't calculate nparams).");
					return SCAP_FAILURE;
				}
				ASSERT(valptr >= end);
				if(valptr == end)
				{
					done = true;
					break;
				}
			}
			if(!done)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (corrupted trace file - can't calculate nparams) (2).");
				return SCAP_FAILURE;
			}
			(*pevent)->nparams = nparams;
		}

		break;
	}

	return SCAP_SUCCESS;
}

uint64_t scap_savefile_ftell(struct scap_engine_handle engine)
{
	scap_reader_t* reader = engine.m_handle->m_reader;
	return reader->tell(reader);
}

void scap_savefile_fseek(struct scap_engine_handle engine, uint64_t off)
{
	scap_reader_t* reader = engine.m_handle->m_reader;
	reader->seek(reader, off, SEEK_SET);
}

static int32_t
scap_savefile_init_platform(struct scap_platform *platform, char *lasterr, struct scap_engine_handle engine,
			    struct scap_open_args *oargs)
{
	return SCAP_SUCCESS;
}

static int32_t scap_savefile_close_platform(struct scap_platform* platform)
{
	return SCAP_SUCCESS;
}

static void scap_savefile_free_platform(struct scap_platform* platform)
{
	free(platform);
}

bool scap_savefile_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm)
{
	return false;
}

static const struct scap_platform_vtable scap_savefile_platform_vtable = {
	.init_platform = scap_savefile_init_platform,
	.is_thread_alive = scap_savefile_is_thread_alive,
	.close_platform = scap_savefile_close_platform,
	.free_platform = scap_savefile_free_platform,
};

struct scap_platform *scap_savefile_alloc_platform(proc_entry_callback proc_callback, void *proc_callback_context)
{
	struct scap_savefile_platform *platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	platform->m_generic.m_vtable = &scap_savefile_platform_vtable;
	platform->m_generic.m_machine_info.num_cpus = (uint32_t)-1;

	init_proclist(&platform->m_generic.m_proclist, proc_callback, proc_callback_context);

	return &platform->m_generic;
}

static struct savefile_engine* alloc_handle(struct scap* main_handle, char* lasterr_ptr)
{
	struct savefile_engine *engine = calloc(1, sizeof(struct savefile_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;

}

static int32_t init(struct scap* main_handle, struct scap_open_args* oargs)
{
	gzFile gzfile;
	int res;
	struct savefile_engine *handle = main_handle->m_engine.m_handle;
	struct scap_savefile_engine_params* params = oargs->engine_params;
	int fd = params->fd;
	const char* fname = params->fname;
	uint64_t start_offset = params->start_offset;
	uint32_t fbuffer_size = params->fbuffer_size;

	struct scap_platform *platform = params->platform;
	handle->m_platform = params->platform;

	if(fd != 0)
	{
		gzfile = gzdopen(fd, "rb");
	}
	else
	{
		gzfile = gzopen(fname, "rb");
	}

	if(gzfile == NULL)
	{
		if(fd != 0)
		{
			snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		}
		else
		{
			snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open file %s", fname);
		}
		return SCAP_FAILURE;
	}

	scap_reader_t* reader = scap_reader_open_gzfile(gzfile);
	if(!reader)
	{
		gzclose(gzfile);
		return SCAP_FAILURE;
	}

	if (fbuffer_size > 0)
	{
		scap_reader_t* buffered_reader = scap_reader_open_buffered(reader, fbuffer_size, true);
		if(!buffered_reader)
		{
			reader->close(reader);
			return SCAP_FAILURE;
		}
		reader = buffered_reader;
	}

	//
	// If this is a merged file, we might have to move the read offset to the next section
	//
	if(start_offset != 0)
	{
		scap_fseek(main_handle, start_offset);
	}

	handle->m_use_last_block_header = false;

	res = scap_read_init(
		handle,
		reader,
		&platform->m_machine_info,
		&platform->m_proclist,
		&platform->m_addrlist,
		&platform->m_userlist,
		main_handle->m_lasterr
	);

	if(res != SCAP_SUCCESS)
	{
		reader->close(reader);
		return res;
	}

	handle->m_reader_evt_buf = (char*)malloc(READER_BUF_SIZE);
	if(!handle->m_reader_evt_buf)
	{
		snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "error allocating the read buffer");
		return SCAP_FAILURE;
	}
	handle->m_reader_evt_buf_size = READER_BUF_SIZE;
	handle->m_reader = reader;

	if(!oargs->import_users)
	{
		if(platform->m_userlist != NULL)
		{
			scap_free_userlist(platform->m_userlist);
			platform->m_userlist = NULL;
		}
	}

	return SCAP_SUCCESS;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

static int32_t scap_savefile_close(struct scap_engine_handle engine)
{
	struct savefile_engine* handle = engine.m_handle;
	if (handle->m_reader)
	{
		handle->m_reader->close(handle->m_reader);
		handle->m_reader = NULL;
	}

	if(handle->m_reader_evt_buf)
	{
		free(handle->m_reader_evt_buf);
		handle->m_reader_evt_buf = NULL;
	}

	return SCAP_SUCCESS;
}

static int32_t scap_savefile_restart_capture(scap_t* handle)
{
	struct savefile_engine *engine = handle->m_engine.m_handle;
	struct scap_platform *platform = engine->m_platform;
	int32_t res;

	scap_platform_close(platform);

	if((res = scap_read_init(
		engine,
		engine->m_reader,
		&platform->m_machine_info,
		&platform->m_proclist,
		&platform->m_addrlist,
		&platform->m_userlist,
		handle->m_lasterr)) != SCAP_SUCCESS)
	{
		char error[SCAP_LASTERR_SIZE];
		snprintf(error, SCAP_LASTERR_SIZE, "could not restart capture: %s", scap_getlasterr(handle));
		strlcpy(handle->m_lasterr, error, SCAP_LASTERR_SIZE);
	}
	return res;
}

static int64_t get_readfile_offset(struct scap_engine_handle engine)
{
	return engine.m_handle->m_reader->offset(engine.m_handle->m_reader);
}

static struct scap_savefile_vtable savefile_ops = {
	.ftell_capture = scap_savefile_ftell,
	.fseek_capture = scap_savefile_fseek,

	.restart_capture = scap_savefile_restart_capture,
	.get_readfile_offset = get_readfile_offset,
};

struct scap_vtable scap_savefile_engine = {
	.name = SAVEFILE_ENGINE,
	.savefile_ops = &savefile_ops,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = free_handle,
	.close = scap_savefile_close,
	.next = next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = noop_get_stats,
	.get_stats_v2 = noop_get_stats_v2,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};
