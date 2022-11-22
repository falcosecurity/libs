/*
Copyright (C) 2021 The Falco Authors.

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

#include "scap.h"
#include "scap-int.h"
#include "uthash.h"
#include <inttypes.h>
#include <string.h>

//
// Calculate the length on disk of an fd entry's info
//
uint32_t scap_fd_info_len(scap_fdinfo *fdi)
{
	//
	// NB: new fields must be appended
	//

	uint32_t res = sizeof(uint32_t) + sizeof(fdi->ino) + 1 + sizeof(fdi->fd);

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		res +=  4 +     // sip
		        4 +     // dip
		        2 +     // sport
		        2 +     // dport
		        1;      // l4proto
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		res +=  4 +     // ip
		        2 +     // port
		        1;      // l4proto
		break;
	case SCAP_FD_IPV6_SOCK:
		res += 	sizeof(uint32_t) * 4 + // sip
				sizeof(uint32_t) * 4 + // dip
				sizeof(uint16_t) + // sport
				sizeof(uint16_t) + // dport
				sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		res += 	sizeof(uint32_t) * 4 + // ip
				sizeof(uint16_t) + // port
				sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_UNIX_SOCK:
		res +=
			sizeof(uint64_t) + // unix source
			sizeof(uint64_t) +  // unix destination
			(uint32_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE) + 2;
		break;
	case SCAP_FD_FILE_V2:
		res += sizeof(uint32_t) + // open_flags
			(uint32_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE) + 2 +
			sizeof(uint32_t); // dev
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
		res += (uint32_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE) + 2;    // 2 is the length field before the string
		break;
	default:
		ASSERT(false);
		break;
	}

	return res;
}

int scap_dump_write(scap_dumper_t *d, void* buf, unsigned len);

//
// Write the given fd info to disk
//
int32_t scap_fd_write_to_disk(scap_t *handle, scap_fdinfo *fdi, scap_dumper_t *d, uint32_t len)
{

	uint8_t type = (uint8_t)fdi->type;
	uint16_t stlen;
	if(scap_dump_write(d, &(len), sizeof(uint32_t)) != sizeof(uint32_t) ||
	        scap_dump_write(d, &(fdi->fd), sizeof(uint64_t)) != sizeof(uint64_t) ||
	        scap_dump_write(d, &(fdi->ino), sizeof(uint64_t)) != sizeof(uint64_t) ||
	        scap_dump_write(d, &(type), sizeof(uint8_t)) != sizeof(uint8_t))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
		return SCAP_FAILURE;
	}

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4info.sip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.dip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi2)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4serverinfo.ip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv4serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi3)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV6_SOCK:
		if(scap_dump_write(d, (char*)fdi->info.ipv6info.sip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, (char*)fdi->info.ipv6info.dip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, &(fdi->info.ipv6info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi7)");
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv6serverinfo.ip), sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		        scap_dump_write(d, &(fdi->info.ipv6serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		        scap_dump_write(d, &(fdi->info.ipv6serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi8)");
		}
		break;
	case SCAP_FD_UNIX_SOCK:
		if(scap_dump_write(d, &(fdi->info.unix_socket_info.source), sizeof(uint64_t)) != sizeof(uint64_t) ||
		        scap_dump_write(d, &(fdi->info.unix_socket_info.destination), sizeof(uint64_t)) != sizeof(uint64_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi4)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		        (stlen > 0 && scap_dump_write(d, fdi->info.unix_socket_info.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi5)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_FILE_V2:
		if(scap_dump_write(d, &(fdi->info.regularinfo.open_flags), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
			(stlen > 0 && scap_dump_write(d, fdi->info.regularinfo.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		if(scap_dump_write(d, &(fdi->info.regularinfo.dev), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (dev)");
			return SCAP_FAILURE;
		}
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
		stlen = (uint16_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen,  sizeof(uint16_t)) != sizeof(uint16_t) ||
		        (stlen > 0 && scap_dump_write(d, fdi->info.fname, stlen) != stlen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi6)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_UNKNOWN:
		// Ignore UNKNOWN fds without failing
		ASSERT(false);
		break;
	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Unknown fdi type %d", fdi->type);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

void scap_fd_free_table(scap_t *handle, scap_fdinfo **fds)
{
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	if(*fds)
	{
		HASH_ITER(hh, *fds, fdi, tfdi)
		{
			HASH_DEL(*fds, fdi);
			free(fdi);
		}
		*fds = NULL;
	}
}

void scap_fd_free_proc_fd_table(scap_t *handle, scap_threadinfo *tinfo)
{
	if(tinfo->fdlist)
	{
		scap_fd_free_table(handle, &tinfo->fdlist);
	}
}


//
// remove an fd from a process table
//
void scap_fd_remove(scap_t *handle, scap_threadinfo *tinfo, int64_t fd)
{
	scap_fdinfo *fdi;

	//
	// Find the fd descriptor
	//
	HASH_FIND_INT64(tinfo->fdlist, &(fd), fdi);
	if(fdi == NULL)
	{
		//
		// Looks like there's no fd to remove.
		// Likely, the fd creation event was dropped.
		//
		//scap_proc_print_info(handle, tinfo);
		//      ASSERT(false);
		return;
	}

	HASH_DEL(tinfo->fdlist, fdi);
	free(fdi);
}

//
// Add the file descriptor info pointed by fdi to the fd table for process tinfo.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
//
int32_t scap_add_fd_to_proc_table(scap_t *handle, scap_threadinfo *tinfo, scap_fdinfo *fdi, char *error)
{
	int32_t uth_status = SCAP_SUCCESS;
	scap_fdinfo *tfdi;

	//
	// Make sure this fd doesn't already exist
	//
	HASH_FIND_INT64(tinfo->fdlist, &(fdi->fd), tfdi);
	if(tfdi != NULL)
	{
		//
		// This can happen if:
		//  - a close() has been dropped when capturing
		//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
		//    which we don't currently parse.
		// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
		// choice.
		//
		HASH_DEL(tinfo->fdlist, tfdi);
		free(tfdi);
	}

	//
	// Add the fd to the table, or fire the notification callback
	//
	if(handle->m_proclist.m_proc_callback == NULL)
	{
		HASH_ADD_INT64(tinfo->fdlist, fd, fdi);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		handle->m_proclist.m_proc_callback(
			handle->m_proclist.m_proc_callback_context,
			handle->m_proclist.m_main_handle, tinfo->tid, tinfo, fdi);
	}

	return SCAP_SUCCESS;
}

//
// Delete a device entry
//
void scap_dev_delete(scap_t* handle, scap_mountinfo* dev)
{
	//
	// First, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_dev_list, dev);

	//
	// Second, free the memory
	//
	free(dev);
}

//
// Free the device table
//
void scap_free_device_table(scap_t* handle)
{
	scap_mountinfo *dev, *tdev;

	HASH_ITER(hh, handle->m_dev_list, dev, tdev)
	{
		scap_dev_delete(handle, dev);
	}
}

int32_t scap_fd_allocate_fdinfo(scap_t *handle, scap_fdinfo **fdi, int64_t fd, scap_fd_type type)
{
	ASSERT(NULL == *fdi);
	*fdi = (scap_fdinfo *)malloc(sizeof(scap_fdinfo));
	if(*fdi == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "fd table allocation error (2)");
		return SCAP_FAILURE;
	}
	(*fdi)->type = type;
	(*fdi)->fd = fd;
	return SCAP_SUCCESS;
}

void scap_fd_free_fdinfo(scap_fdinfo **fdi)
{
	if(NULL != *fdi)
	{
		free(*fdi);
		*fdi = NULL;
	}
}
