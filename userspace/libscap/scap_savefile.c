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

#ifndef WIN32
#include <unistd.h>
#include <sys/uio.h>
#else
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#endif

#include "scap.h"
#include "scap-int.h"
#include "scap_savefile.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// WRITE FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//
// Write data into a dump file
//
int scap_dump_write(scap_dumper_t *d, void* buf, unsigned len)
{
	switch(d->m_type)
	{
	case DT_FILE:
		return gzwrite(d->m_f, buf, len);
	case DT_MEM:
		if(d->m_targetbufcurpos + len < d->m_targetbufend)
		{
			memcpy(d->m_targetbufcurpos, buf, len);

			d->m_targetbufcurpos += len;
			return len;
		}
		else
		{
			return -1;
		}
	case DT_MEMSTREAM:
		return fwrite(buf, 1, len, d->m_memstream);
	default:
		return -1;
	}
}

int scap_dump_writev(scap_dumper_t *d, const struct iovec *iov, int iovcnt)
{
	unsigned totlen = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
	{
		if(scap_dump_write(d, iov[i].iov_base, iov[i].iov_len) < 0)
		{
			return -1;
		}

		totlen += iov[i].iov_len;
	}

	return totlen;
}

#ifdef USE_ZLIB
int32_t compr(uint8_t* dest, uint64_t* destlen, const uint8_t* source, uint64_t sourcelen, int level)
{
	uLongf dl = compressBound(sourcelen);

	if(dl >= *destlen)
	{
		return SCAP_FAILURE;
	}

	int res = compress2(dest, &dl, source, sourcelen, level);
	if(res == Z_OK)
	{
		*destlen = (uint64_t)dl;
		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_FAILURE;
	}
}
#endif

uint8_t* scap_get_memorydumper_curpos(scap_dumper_t *d)
{
	return d->m_targetbufcurpos;
}

#ifndef WIN32
static inline uint32_t scap_normalize_block_len(uint32_t blocklen)
#else
static uint32_t scap_normalize_block_len(uint32_t blocklen)
#endif
{
	return ((blocklen + 3) >> 2) << 2;
}

static int32_t scap_write_padding(scap_dumper_t *d, uint32_t blocklen)
{
	int32_t val = 0;
	uint32_t bytestowrite = scap_normalize_block_len(blocklen) - blocklen;

	if(scap_dump_write(d, &val, bytestowrite) == bytestowrite)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_FAILURE;
	}
}

int32_t scap_write_proc_fds(scap_t *handle, struct scap_threadinfo *tinfo, scap_dumper_t *d)
{
	block_header bh;
	uint32_t bt;
	uint32_t totlen = MEMBER_SIZE(scap_threadinfo, tid);  // This includes the tid
	uint32_t idx = 0;
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	uint32_t* lengths = calloc(HASH_COUNT(tinfo->fdlist), sizeof(uint32_t));
	if(lengths == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_write_proc_fds memory allocation failure");
		return SCAP_FAILURE;
	}

	//
	// First pass of the table to calculate the lengths
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED &&
		   fdi->type != SCAP_FD_UNKNOWN)
		{
			uint32_t fl = scap_fd_info_len(fdi);
			lengths[idx++] = fl;
			totlen += fl;
		}
	}
	idx = 0;

	//
	// Create the block
	//
	bh.block_type = FDL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		free(lengths);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd1)");
		return SCAP_FAILURE;
	}

	//
	// Write the tid
	//
	if(scap_dump_write(d, &tinfo->tid, sizeof(tinfo->tid)) != sizeof(tinfo->tid))
	{
		free(lengths);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd2)");
		return SCAP_FAILURE;
	}

	//
	// Second pass of the table to dump it
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED && fdi->type != SCAP_FD_UNKNOWN)
		{
			if(scap_fd_write_to_disk(handle, fdi, d, lengths[idx++]) != SCAP_SUCCESS)
			{
				free(lengths);
				return SCAP_FAILURE;
			}
		}
	}

	free(lengths);

	//
	// Add the padding
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the fd list blocks
//
static int32_t scap_write_fdlist(scap_t *handle, scap_dumper_t *d)
{
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	int32_t res;

	//
	// No fd list on disk if the source is a plugin
	//
	if(handle->m_mode == SCAP_MODE_PLUGIN)
	{
		return SCAP_SUCCESS;
	}

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(!tinfo->filtered_out)
		{
			res = scap_write_proc_fds(handle, tinfo, d);
			if(res != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

//
// Since the process list isn't thread-safe, we at least reduce the
// time window and write everything at once with a secondary dumper.
// By doing so, the likelihood of having a wrong total length is lower.
//
scap_dumper_t *scap_write_proclist_begin(scap_t *handle)
{
	return scap_memstream_dump_create(handle);
}
int scap_write_proclist_end(scap_t *handle, scap_dumper_t *d, scap_dumper_t *d2, uint32_t totlen)
{
	int res = SCAP_SUCCESS;

	do
	{
		scap_dump_flush(d2);

		if(scap_write_proclist_header(handle, d, totlen) != SCAP_SUCCESS)
		{
			res = SCAP_FAILURE;
			break;
		}
		if(scap_dump_write(d, d2->m_targetbuf, totlen) <= 0)
		{
			res = SCAP_FAILURE;
			break;
		}
		if(scap_write_proclist_trailer(handle, d, totlen) != SCAP_SUCCESS)
		{
			res = SCAP_FAILURE;
			break;
		}
	} while(false);

	scap_dump_close(d2);

	return res;
}

//
// Write the process list block
//
int32_t scap_write_proclist_header(scap_t *handle, scap_dumper_t *d, uint32_t totlen)
{
	block_header bh;

	//
	// Create the block header
	//
	bh.block_type = PL_BLOCK_TYPE_V9;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
int32_t scap_write_proclist_trailer(scap_t *handle, scap_dumper_t *d, uint32_t totlen)
{
	block_header bh;
	uint32_t bt;

	bh.block_type = PL_BLOCK_TYPE_V9;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
int32_t scap_write_proclist_entry(scap_t *handle, scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len)
{
	struct iovec args = {tinfo->args, tinfo->args_len};
	struct iovec env = {tinfo->env, tinfo->env_len};
	struct iovec cgroups = {tinfo->cgroups, tinfo->cgroups_len};

	return scap_write_proclist_entry_bufs(handle, d, tinfo, len,
					      tinfo->comm,
					      tinfo->exe,
					      tinfo->exepath,
					      &args, 1,
					      &env, 1,
					      tinfo->cwd,
					      &cgroups, 1,
					      tinfo->root);
}

static uint16_t iov_size(const struct iovec *iov, uint32_t iovcnt)
{
	uint16_t len = 0;
	uint32_t i;

	for (i = 0; i < iovcnt; i++)
	{
		len += iov[i].iov_len;
	}

	return len;
}

int32_t scap_write_proclist_entry_bufs(scap_t *handle, scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len,
				       const char *comm,
				       const char *exe,
				       const char *exepath,
				       const struct iovec *args, int argscnt,
				       const struct iovec *envs, int envscnt,
				       const char *cwd,
				       const struct iovec *cgroups, int cgroupscnt,
				       const char *root)
{
	uint16_t commlen;
	uint16_t exelen;
	uint16_t exepathlen;
	uint16_t cwdlen;
	uint16_t rootlen;
	uint16_t argslen;
	uint16_t envlen;
	uint16_t cgroupslen;

	commlen = (uint16_t)strnlen(comm, SCAP_MAX_PATH_SIZE);
	exelen = (uint16_t)strnlen(exe, SCAP_MAX_PATH_SIZE);
	exepathlen = (uint16_t)strnlen(exepath, SCAP_MAX_PATH_SIZE);
	cwdlen = (uint16_t)strnlen(cwd, SCAP_MAX_PATH_SIZE);
	rootlen = (uint16_t)strnlen(root, SCAP_MAX_PATH_SIZE);

	argslen = iov_size(args, argscnt);
	envlen = iov_size(envs, envscnt);
	cgroupslen = iov_size(cgroups, cgroupscnt);

	//
	// NB: new fields must be appended
	//
	*len = (uint32_t)(sizeof(uint32_t) + // len
			  sizeof(uint64_t) + // tid
			  sizeof(uint64_t) + // pid
			  sizeof(uint64_t) + // ptid
			  sizeof(uint64_t) + // sid
			  sizeof(uint64_t) + // vpgid
			  2 + commlen +
			  2 + exelen +
			  2 + exepathlen +
			  2 + argslen +
			  2 + cwdlen +
			  sizeof(uint64_t) + // fdlimit
			  sizeof(uint32_t) + // flags
			  sizeof(uint32_t) + // uid
			  sizeof(uint32_t) + // gid
			  sizeof(uint32_t) + // vmsize_kb
			  sizeof(uint32_t) + // vmrss_kb
			  sizeof(uint32_t) + // vmswap_kb
			  sizeof(uint64_t) + // pfmajor
			  sizeof(uint64_t) + // pfminor
			  2 + envlen +
			  sizeof(int64_t) + // vtid
			  sizeof(int64_t) + // vpid
			  2 + cgroupslen +
			  2 + rootlen +
			  sizeof(int32_t) +  // loginuid
			  sizeof(uint8_t) +  // exe_writable
			  sizeof(uint64_t) + // cap_inheritable
			  sizeof(uint64_t) + // cap_permitted
			  sizeof(uint64_t)); // cap_effective

	if(scap_dump_write(d, len, sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->tid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->pid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->ptid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->sid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->vpgid), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &commlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_write(d, (char *) comm, commlen) != commlen ||
		    scap_dump_write(d, &exelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_write(d, (char *) exe, exelen) != exelen ||
                    scap_dump_write(d, &exepathlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_write(d, (char *) exepath, exepathlen) != exepathlen ||
		    scap_dump_write(d, &argslen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_writev(d, args, argscnt) != argslen ||
		    scap_dump_write(d, &cwdlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_write(d, (char *) cwd, cwdlen) != cwdlen ||
		    scap_dump_write(d, &(tinfo->fdlimit), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->flags), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->uid), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->gid), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->vmsize_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->vmrss_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->vmswap_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(tinfo->pfmajor), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &(tinfo->pfminor), sizeof(uint64_t)) != sizeof(uint64_t) ||
		    scap_dump_write(d, &envlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_writev(d, envs, envscnt) != envlen ||
		    scap_dump_write(d, &(tinfo->vtid), sizeof(int64_t)) != sizeof(int64_t) ||
		    scap_dump_write(d, &(tinfo->vpid), sizeof(int64_t)) != sizeof(int64_t) ||
		    scap_dump_write(d, &(cgroupslen), sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_writev(d, cgroups, cgroupscnt) != cgroupslen ||
		    scap_dump_write(d, &rootlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
                    scap_dump_write(d, (char *) root, rootlen) != rootlen ||
            scap_dump_write(d, &(tinfo->loginuid), sizeof(uint32_t)) != sizeof(uint32_t) ||
			scap_dump_write(d, &(tinfo->exe_writable), sizeof(uint8_t)) != sizeof(uint8_t) ||
			scap_dump_write(d, &(tinfo->cap_inheritable), sizeof(uint64_t)) != sizeof(uint64_t) ||
			scap_dump_write(d, &(tinfo->cap_permitted), sizeof(uint64_t)) != sizeof(uint64_t) ||
			scap_dump_write(d, &(tinfo->cap_effective), sizeof(uint64_t)) != sizeof(uint64_t))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (2)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
static int32_t scap_write_proclist(scap_t *handle, scap_dumper_t *d)
{
	//
	// No process list on disk if the source is a plugin
	//
	if(handle->m_mode == SCAP_MODE_PLUGIN)
	{
		return SCAP_SUCCESS;
	}

	//
	// Exit immediately if the process list is empty
	//
	if(HASH_COUNT(handle->m_proclist) == 0)
	{
		return SCAP_SUCCESS;
	}

	scap_dumper_t *d2 = scap_write_proclist_begin(handle);

	uint32_t totlen = 0;
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(tinfo->filtered_out)
		{
			continue;
		}

		uint32_t len = 0;
		if(scap_write_proclist_entry(handle, d2, tinfo, &len) != SCAP_SUCCESS)
		{
			scap_dump_close(d2);
			return SCAP_FAILURE;
		}

		totlen += len;
	}

	return scap_write_proclist_end(handle, d, d2, totlen);
}

//
// Write the machine info block
//
static int32_t scap_write_machine_info(scap_t *handle, scap_dumper_t *d)
{
	block_header bh;
	uint32_t bt;

	//
	// No machine info on disk if the source is a plugin
	//
	if(handle->m_mode == SCAP_MODE_PLUGIN)
	{
		return SCAP_SUCCESS;
	}

	//
	// Write the section header
	//
	bh.block_type = MI_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(scap_machine_info) + 4);

	bt = bh.block_total_length;

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
	        scap_dump_write(d, &handle->m_machine_info, sizeof(handle->m_machine_info)) != sizeof(handle->m_machine_info) ||
	        scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (MI1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the interface list block
//
static int32_t scap_write_iflist(scap_t *handle, scap_dumper_t* d)
{
	block_header bh;
	uint32_t bt;
	uint32_t entrylen;
	uint32_t totlen = 0;
	uint32_t j;

	//
	// No interface list on disk if the source is a plugin
	//
	if(handle->m_mode == SCAP_MODE_PLUGIN)
	{
		return SCAP_SUCCESS;
	}

	//
	// Get the interface list
	//
	if(handle->m_addrlist == NULL)
	{
		//
		// This can happen when the event source is a capture that was generated by a plugin, no big deal
		//
		return SCAP_SUCCESS;
	}

	//
	// Create the block
	//
	bh.block_type = IL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + (handle->m_addrlist->n_v4_addrs + handle->m_addrlist->n_v6_addrs)*sizeof(uint32_t) +
							 handle->m_addrlist->totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the ipv4 list
	//
	for(j = 0; j < handle->m_addrlist->n_v4_addrs; j++)
	{
		scap_ifinfo_ipv4 *entry = &(handle->m_addrlist->v4list[j]);

		entrylen = sizeof(scap_ifinfo_ipv4) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(scap_dump_write(d, &entrylen, sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->type), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->ifnamelen), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->addr), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->netmask), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->bcast), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->linkspeed), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   scap_dump_write(d, &(entry->ifname), entry->ifnamelen) != entry->ifnamelen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += sizeof(uint32_t) + entrylen;
	}

	//
	// Dump the ipv6 list
	//
	for(j = 0; j < handle->m_addrlist->n_v6_addrs; j++)
	{
		scap_ifinfo_ipv6 *entry = &(handle->m_addrlist->v6list[j]);

		entrylen = sizeof(scap_ifinfo_ipv6) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(scap_dump_write(d, &entrylen, sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->type), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->ifnamelen), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->addr), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->netmask), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->bcast), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->linkspeed), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   scap_dump_write(d, &(entry->ifname), entry->ifnamelen) != entry->ifnamelen)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += sizeof(uint32_t) + entrylen;
	}

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the user list block
//
static int32_t scap_write_userlist(scap_t *handle, scap_dumper_t* d)
{
	block_header bh;
	uint32_t bt;
	uint32_t j;
	uint16_t namelen;
	uint16_t homedirlen;
	uint16_t shelllen;
	uint8_t type;
	uint32_t totlen = 0;

	//
	// No user list on disk if the source is a plugin
	//
	if(handle->m_mode == SCAP_MODE_PLUGIN)
	{
		return SCAP_SUCCESS;
	}

	//
	// Make sure we have a user list interface list
	//
	if(handle->m_userlist == NULL)
	{
		//
		// This can happen when the event source is a capture that was generated by a plugin, no big deal
		//
		return SCAP_SUCCESS;
	}

	uint32_t* lengths = calloc(handle->m_userlist->nusers + handle->m_userlist->ngroups, sizeof(uint32_t));
	if(lengths == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_write_userlist memory allocation failure (1)");
		return SCAP_FAILURE;
	}

	//
	// Calculate the lengths
	//
	for(j = 0; j < handle->m_userlist->nusers; j++)
	{
		scap_userinfo* info = &handle->m_userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		// NB: new fields must be appended
		size_t ul = sizeof(uint32_t) + sizeof(type) + sizeof(info->uid) + sizeof(info->gid) + sizeof(uint16_t) +
			namelen + sizeof(uint16_t) + homedirlen + sizeof(uint16_t) + shelllen;
		totlen += ul;
		lengths[j] = ul;
	}

	for(j = 0; j < handle->m_userlist->ngroups; j++)
	{
		scap_groupinfo* info = &handle->m_userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		// NB: new fields must be appended
		uint32_t gl = sizeof(uint32_t) + sizeof(type) + sizeof(info->gid) + sizeof(uint16_t) + namelen;
		totlen += gl;
		lengths[handle->m_userlist->nusers + j] = gl;
	}

	//
	// Create the block
	//
	bh.block_type = UL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		free(lengths);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the users
	//
	type = USERBLOCK_TYPE_USER;
	for(j = 0; j < handle->m_userlist->nusers; j++)
	{
		scap_userinfo* info = &handle->m_userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		if(scap_dump_write(d, &(lengths[j]), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(type), sizeof(type)) != sizeof(type) ||
			scap_dump_write(d, &(info->uid), sizeof(info->uid)) != sizeof(info->uid) ||
		    scap_dump_write(d, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		    scap_dump_write(d, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    scap_dump_write(d, info->name, namelen) != namelen ||
		    scap_dump_write(d, &homedirlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    scap_dump_write(d, info->homedir, homedirlen) != homedirlen ||
		    scap_dump_write(d, &shelllen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    scap_dump_write(d, info->shell, shelllen) != shelllen)
		{
			free(lengths);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U1)");
			return SCAP_FAILURE;
		}
	}

	//
	// Dump the groups
	//
	type = USERBLOCK_TYPE_GROUP;
	for(j = 0; j < handle->m_userlist->ngroups; j++)
	{
		scap_groupinfo* info = &handle->m_userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		if(scap_dump_write(d, &(lengths[handle->m_userlist->nusers + j]), sizeof(uint32_t)) != sizeof(uint32_t) ||
		    scap_dump_write(d, &(type), sizeof(type)) != sizeof(type) ||
			scap_dump_write(d, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		    scap_dump_write(d, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		    scap_dump_write(d, info->name, namelen) != namelen)
		{
			free(lengths);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U2)");
			return SCAP_FAILURE;
		}
	}

	free(lengths);

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Create the dump file headers and add the tables
//
int32_t scap_setup_dump(scap_t *handle, scap_dumper_t* d, const char *fname)
{
	block_header bh;
	section_header_block sh;
	uint32_t bt;

	//
	// Write the section header
	//
	bh.block_type = SHB_BLOCK_TYPE;
	bh.block_total_length = sizeof(block_header) + sizeof(section_header_block) + 4;

	sh.byte_order_magic = SHB_MAGIC;
	sh.major_version = CURRENT_MAJOR_VERSION;
	sh.minor_version = CURRENT_MINOR_VERSION;
	sh.section_length = 0xffffffffffffffffLL;

	bt = bh.block_total_length;

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
	        scap_dump_write(d, &sh, sizeof(sh)) != sizeof(sh) ||
	        scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file %s  (5)", fname);
		return SCAP_FAILURE;
	}

	//
	// If we're dumping in live mode, refresh the process tables list
	// so we don't lose information about processes created in the interval
	// between opening the handle and starting the dump
	//
#if defined(HAS_CAPTURE) && !defined(WIN32)
	if(handle->m_reader == NULL && handle->refresh_proc_table_when_saving)
	{
		proc_entry_callback tcb = handle->m_proc_callback;
		handle->m_proc_callback = NULL;

		scap_proc_free_table(handle);
		char filename[SCAP_MAX_PATH_SIZE];
		snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
		if(scap_proc_scan_proc_dir(handle, filename, handle->m_lasterr) != SCAP_SUCCESS)
		{
			handle->m_proc_callback = tcb;
			return SCAP_FAILURE;
		}

		handle->m_proc_callback = tcb;
	}
#endif

	//
	// Write the machine info
	//
	if(scap_write_machine_info(handle, d) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the interface list
	//
	if(scap_write_iflist(handle, d) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the user list
	//
	if(scap_write_userlist(handle, d) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the process list
	//
	if(scap_write_proclist(handle, d) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the fd lists
	//
	if(scap_write_fdlist(handle, d) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// If the user doesn't need the thread table, free it
	//
	if(handle->m_proc_callback != NULL)
	{
		scap_proc_free_table(handle);
	}

	//
	// Done, return the file
	//
	return SCAP_SUCCESS;
}

// fname is only used for log messages in scap_setup_dump
static scap_dumper_t *scap_dump_open_gzfile(scap_t *handle, gzFile gzfile, const char *fname, bool skip_proc_scan)
{
	scap_dumper_t* res = (scap_dumper_t*)malloc(sizeof(scap_dumper_t));
	res->m_f = gzfile;
	res->m_type = DT_FILE;
	res->m_targetbuf = NULL;
	res->m_targetbufcurpos = NULL;
	res->m_targetbufend = NULL;

	bool tmp_refresh_proc_table_when_saving = handle->refresh_proc_table_when_saving;
	if(skip_proc_scan)
	{
		handle->refresh_proc_table_when_saving = false;
	}

	if(scap_setup_dump(handle, res, fname) != SCAP_SUCCESS)
	{
		res = NULL;
	}

	if(skip_proc_scan)
	{
		handle->refresh_proc_table_when_saving = tmp_refresh_proc_table_when_saving;
	}

	return res;
}

//
// Open a "savefile" for writing.
//
scap_dumper_t *scap_dump_open(scap_t *handle, const char *fname, compression_mode compress, bool skip_proc_scan)
{
	gzFile f = NULL;
	int fd = -1;
	const char* mode;

	switch(compress)
	{
	case SCAP_COMPRESSION_GZIP:
		mode = "wb";
		break;
	case SCAP_COMPRESSION_NONE:
		mode = "wbT";
		break;
	default:
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid compression mode");
		return NULL;
	}

	if(fname[0] == '-' && fname[1] == '\0')
	{
#ifndef	WIN32
		fd = dup(STDOUT_FILENO);
#else
		fd = 1;
#endif
		if(fd != -1)
		{
			f = gzdopen(fd, mode);
			fname = "standard output";
		}
	}
	else
	{
		f = gzopen(fname, mode);
	}

	if(f == NULL)
	{
#ifndef	WIN32
		if(fd != -1)
		{
			close(fd);
		}
#endif

		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open %s", fname);
		return NULL;
	}

	return scap_dump_open_gzfile(handle, f, fname, skip_proc_scan);
}

//
// Open a savefile for writing, using the provided fd
scap_dumper_t* scap_dump_open_fd(scap_t *handle, int fd, compression_mode compress, bool skip_proc_scan)
{
	gzFile f = NULL;

	switch(compress)
	{
	case SCAP_COMPRESSION_GZIP:
		f = gzdopen(fd, "wb");
		break;
	case SCAP_COMPRESSION_NONE:
		f = gzdopen(fd, "wbT");
		break;
	default:
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid compression mode");
		return NULL;
	}
	
	if(f == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		return NULL;
	}

	return scap_dump_open_gzfile(handle, f, "", skip_proc_scan);
}

//
// Open a memory "savefile"
//
scap_dumper_t *scap_memory_dump_open(scap_t *handle, uint8_t* targetbuf, uint64_t targetbufsize)
{
	scap_dumper_t* res = (scap_dumper_t*)malloc(sizeof(scap_dumper_t));
	if(res == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_dump_memory_open memory allocation failure (1)");
		return NULL;
	}

	res->m_f = NULL;
	res->m_type = DT_MEM;
	res->m_targetbuf = targetbuf;
	res->m_targetbufcurpos = targetbuf;
	res->m_targetbufend = targetbuf + targetbufsize;

	//
	// Disable proc parsing since it would be too heavy when saving to memory.
	// Before doing that, backup handle->refresh_proc_table_when_saving so we can
	// restore whatever the current setting is as soon as we're done.
	//
	bool tmp_refresh_proc_table_when_saving = handle->refresh_proc_table_when_saving;
	handle->refresh_proc_table_when_saving = false;

	if(scap_setup_dump(handle, res, "") != SCAP_SUCCESS)
	{
		free(res);
		res = NULL;
	}

	handle->refresh_proc_table_when_saving = tmp_refresh_proc_table_when_saving;

	return res;
}

//
// Create a memstream (see open_memstream) "savefile"
//
scap_dumper_t *scap_memstream_dump_create(scap_t *handle)
{
	scap_dumper_t *res = (scap_dumper_t *)malloc(sizeof(scap_dumper_t));
	if(res == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_memstream_dump_create memory allocation failure (1)");
		return NULL;
	}

	res->m_f = NULL;
	res->m_targetbuf = NULL;
	res->m_targetbufcurpos = NULL;
	res->m_targetbufend = NULL;

	res->m_type = DT_MEMSTREAM;

	// we don't really care about the size, so we recycle m_targetbufend
	res->m_memstream = open_memstream((char **)&res->m_targetbuf, (size_t *)&res->m_targetbufend);
	if (res->m_memstream == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_memstream_dump_create memstream creation failure (1)");
		free(res);
		return NULL;
	}

	return res;
}

//
// Close a "savefile" opened with scap_dump_open
//
void scap_dump_close(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		gzclose(d->m_f);
	}
	else if (d->m_type == DT_MEMSTREAM)
	{
		fclose(d->m_memstream);
		free(d->m_targetbuf);
	}

	free(d);
}

//
// Return the current size of a tracefile
//
int64_t scap_dump_get_offset(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		return gzoffset(d->m_f);
	}
	else
	{
		return (int64_t)d->m_targetbufcurpos - (int64_t)d->m_targetbuf;
	}
}

int64_t scap_dump_ftell(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		return gztell(d->m_f);
	}
	else
	{
		return (int64_t)d->m_targetbufcurpos - (int64_t)d->m_targetbuf;
	}
}

void scap_dump_flush(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		gzflush(d->m_f, Z_FULL_FLUSH);
	}
	else if (d->m_type == DT_MEMSTREAM)
	{
		fflush(d->m_memstream);
	}
}

//
// Tell me how many bytes we will have written if we did.
//
int32_t scap_number_of_bytes_to_write(scap_evt *e, uint16_t cpuid, int32_t *bytes)
{
	*bytes = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + e->len + 4);

	return SCAP_SUCCESS;
}

//
// Write an event to a dump file
//
int32_t scap_dump(scap_t *handle, scap_dumper_t *d, scap_evt *e, uint16_t cpuid, uint32_t flags)
{
	block_header bh;
	uint32_t bt;
	bool large_payload = flags & SCAP_DF_LARGE;

	flags &= ~SCAP_DF_LARGE;
	if(flags == 0)
	{
		//
		// Write the section header
		//
		bh.block_type = large_payload ? EV_BLOCK_TYPE_V2_LARGE : EV_BLOCK_TYPE_V2;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + e->len + 4);
		bt = bh.block_total_length;

		if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
				scap_dump_write(d, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				scap_dump_write(d, e, e->len) != e->len ||
				scap_write_padding(d, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (6)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		//
		// Write the section header
		//
		bh.block_type = large_payload ? EVF_BLOCK_TYPE_V2_LARGE : EVF_BLOCK_TYPE_V2;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + sizeof(flags) + e->len + 4);
		bt = bh.block_total_length;

		if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
				scap_dump_write(d, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				scap_dump_write(d, &flags, sizeof(flags)) != sizeof(flags) ||
				scap_dump_write(d, e, e->len) != e->len ||
				scap_write_padding(d, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (7)");
			return SCAP_FAILURE;
		}
	}

	//
	// Enable this to make sure that everything is saved to disk during the tests
	//
#if 0
	fflush(f);
#endif

	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// READ FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//
// Load the machine info block
//
static int32_t scap_read_machine_info(scap_t *handle, scap_reader_t* r, uint32_t block_length)
{
	//
	// Read the section header block
	//
	if(scap_reader_read(r, &handle->m_machine_info, sizeof(handle->m_machine_info)) !=
		sizeof(handle->m_machine_info))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Parse a process list block
//
static int32_t scap_read_proclist(scap_t *handle, scap_reader_t* r, uint32_t block_length, uint32_t block_type)
{
	size_t readsize;
	size_t subreadsize = 0;
	size_t totreadsize = 0;
	size_t padding_len;
	uint16_t stlen;
	uint32_t padding;
	int32_t uth_status = SCAP_SUCCESS;
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
		tinfo.cgroups_len = 0;
		tinfo.filtered_out = 0;
		tinfo.root[0] = 0;
		tinfo.sid = -1;
		tinfo.vpgid = -1;
		tinfo.clone_ts = 0;
		tinfo.tty = 0;
		tinfo.exepath[0] = 0;
		tinfo.loginuid = -1;
		tinfo.exe_writable = false;
		tinfo.cap_inheritable = 0;
		tinfo.cap_permitted = 0;
		tinfo.cap_effective = 0;

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
			readsize = scap_reader_read(r, &(sub_len), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// tid
		//
		readsize = scap_reader_read(r, &(tinfo.tid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		subreadsize += readsize;

		//
		// pid
		//
		readsize = scap_reader_read(r, &(tinfo.pid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		subreadsize += readsize;

		//
		// ptid
		//
		readsize = scap_reader_read(r, &(tinfo.ptid), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

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
			readsize = scap_reader_read(r, &(tinfo.sid), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			subreadsize += readsize;
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
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
			readsize = scap_reader_read(r, &(tinfo.vpgid), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			subreadsize += readsize;
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// comm
		//
		readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid commlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = scap_reader_read(r, tinfo.comm, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.comm[stlen] = 0;

		subreadsize += readsize;

		//
		// exe
		//
		readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid exelen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = scap_reader_read(r, tinfo.exe, stlen);
		CHECK_READ_SIZE(readsize, stlen);

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
			readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen > SCAP_MAX_PATH_SIZE)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid exepathlen %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = scap_reader_read(r, tinfo.exepath, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			tinfo.exepath[stlen] = 0;

			subreadsize += readsize;

			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		//
		// args
		//
		readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_ARGS_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid argslen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = scap_reader_read(r, tinfo.args, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.args[stlen] = 0;
		tinfo.args_len = stlen;

		subreadsize += readsize;

		//
		// cwd
		//
		readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE(readsize, sizeof(uint16_t));

		if(stlen > SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid cwdlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = scap_reader_read(r, tinfo.cwd, stlen);
		CHECK_READ_SIZE(readsize, stlen);

		// the string is not null-terminated on file
		tinfo.cwd[stlen] = 0;

		subreadsize += readsize;

		//
		// fdlimit
		//
		readsize = scap_reader_read(r, &(tinfo.fdlimit), sizeof(uint64_t));
		CHECK_READ_SIZE(readsize, sizeof(uint64_t));

		subreadsize += readsize;

		//
		// flags
		//
		readsize = scap_reader_read(r, &(tinfo.flags), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

		subreadsize += readsize;

		//
		// uid
		//
		readsize = scap_reader_read(r, &(tinfo.uid), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

		subreadsize += readsize;

		//
		// gid
		//
		readsize = scap_reader_read(r, &(tinfo.gid), sizeof(uint32_t));
		CHECK_READ_SIZE(readsize, sizeof(uint32_t));

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
			readsize = scap_reader_read(r, &(tinfo.vmsize_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// vmrss_kb
			//
			readsize = scap_reader_read(r, &(tinfo.vmrss_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// vmswap_kb
			//
			readsize = scap_reader_read(r, &(tinfo.vmswap_kb), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// pfmajor
			//
			readsize = scap_reader_read(r, &(tinfo.pfmajor), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

			subreadsize += readsize;

			//
			// pfminor
			//
			readsize = scap_reader_read(r, &(tinfo.pfminor), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));

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
				readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE(readsize, sizeof(uint16_t));

				if(stlen > SCAP_MAX_ENV_SIZE)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid envlen %d", stlen);
					return SCAP_FAILURE;
				}

				subreadsize += readsize;

				readsize = scap_reader_read(r, tinfo.env, stlen);
				CHECK_READ_SIZE(readsize, stlen);

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
				readsize = scap_reader_read(r, &(tinfo.vtid), sizeof(int64_t));
				CHECK_READ_SIZE(readsize, sizeof(uint64_t));

				subreadsize += readsize;

				//
				// vpid
				//
				readsize = scap_reader_read(r, &(tinfo.vpid), sizeof(int64_t));
				CHECK_READ_SIZE(readsize, sizeof(uint64_t));

				subreadsize += readsize;

				//
				// cgroups
				//
				readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE(readsize, sizeof(uint16_t));

				if(stlen > SCAP_MAX_CGROUPS_SIZE)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid cgroupslen %d", stlen);
					return SCAP_FAILURE;
				}
				tinfo.cgroups_len = stlen;

				subreadsize += readsize;

				readsize = scap_reader_read(r, tinfo.cgroups, stlen);
				CHECK_READ_SIZE(readsize, stlen);

				subreadsize += readsize;

				if(block_type == PL_BLOCK_TYPE_V5 ||
				   block_type == PL_BLOCK_TYPE_V6 ||
				   block_type == PL_BLOCK_TYPE_V7 ||
				   block_type == PL_BLOCK_TYPE_V8 ||
				   block_type == PL_BLOCK_TYPE_V9)
				{
					readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
					CHECK_READ_SIZE(readsize, sizeof(uint16_t));

					if(stlen > SCAP_MAX_PATH_SIZE)
					{
						snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid rootlen %d", stlen);
						return SCAP_FAILURE;
					}

					subreadsize += readsize;

					readsize = scap_reader_read(r, tinfo.root, stlen);
					CHECK_READ_SIZE(readsize, stlen);

					// the string is not null-terminated on file
					tinfo.root[stlen] = 0;

					subreadsize += readsize;
				}
			}
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted process block type (fd1)");
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

		//
		// loginuid
		//
		if(sub_len && (subreadsize + sizeof(int32_t)) <= sub_len)
		{
			readsize = scap_reader_read(r, &(tinfo.loginuid), sizeof(int32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));
			subreadsize += readsize;
		}

		//
		// exe_writable
		//
		if(sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = scap_reader_read(r, &(tinfo.exe_writable), sizeof(uint8_t));
			CHECK_READ_SIZE(readsize, sizeof(uint8_t));
			subreadsize += readsize;
		}

		//
		// Capabilities
		//
		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = scap_reader_read(r, &(tinfo.cap_inheritable), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));
			subreadsize += readsize;
		}

		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = scap_reader_read(r, &(tinfo.cap_permitted), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));
			subreadsize += readsize;
		}

		if(sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = scap_reader_read(r, &(tinfo.cap_effective), sizeof(uint64_t));
			CHECK_READ_SIZE(readsize, sizeof(uint64_t));
			subreadsize += readsize;
		}

		//
		// All parsed. Add the entry to the table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			//
			// All parsed. Allocate the new entry and copy the temp one into into it.
			//
			struct scap_threadinfo *ntinfo = (scap_threadinfo *)malloc(sizeof(scap_threadinfo));
			if(ntinfo == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd1)");
				return SCAP_FAILURE;
			}

			// Structure copy
			*ntinfo = tinfo;

			HASH_ADD_INT64(handle->m_proclist, tid, ntinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				free(ntinfo);
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo.tid, &tinfo, NULL);
		}

		if(sub_len && subreadsize != sub_len)
		{
			if(subreadsize > sub_len)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Had read %lu bytes, but proclist entry have length %u.",
					 subreadsize, sub_len);
				return SCAP_FAILURE;
			}
			toread = sub_len - subreadsize;
			fseekres = (int)scap_reader_seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
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
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_proclist read more %lu than a block %u", totreadsize, block_length);
		ASSERT(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = (size_t)scap_reader_read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

//
// Parse an interface list block
//
static int32_t scap_read_iflist(scap_t *handle, scap_reader_t* r, uint32_t block_length, uint32_t block_type)
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
	if(handle->m_addrlist != NULL)
	{
		scap_free_iflist(handle->m_addrlist);
		handle->m_addrlist = NULL;
	}

	//
	// Bring the block to memory
	// We assume that this block is always small enough that we can read it in a single shot
	//
	readbuf = (char *)malloc(block_length);
	if(!readbuf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_iflist");
		return SCAP_FAILURE;
	}

	readsize = scap_reader_read(r, readbuf, block_length);
	CHECK_READ_SIZE_WITH_FREE(readbuf, readsize, block_length);

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
			iftype = *(uint16_t *)pif;
			ifnamlen = *(uint16_t *)(pif + 2);

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
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(1)");
				ASSERT(false);
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}
		}
		else
		{
			entrysize = *(uint32_t *)pif + sizeof(uint32_t);
			iftype = *(uint16_t *)(pif + 4);
			ifnamlen = *(uint16_t *)(pif + 4 + 2);
		}

		if(toread < entrysize)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(2) toread=%u, entrysize=%u", toread, entrysize);
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
			ASSERT(false);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}

	//
	// Allocate the handle and the arrays
	//
	handle->m_addrlist = (scap_addrlist *)malloc(sizeof(scap_addrlist));
	if(!handle->m_addrlist)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(1)");
		res = SCAP_FAILURE;
		goto scap_read_iflist_error;
	}

	handle->m_addrlist->n_v4_addrs = 0;
	handle->m_addrlist->n_v6_addrs = 0;
	handle->m_addrlist->v4list = NULL;
	handle->m_addrlist->v6list = NULL;
	handle->m_addrlist->totlen = block_length - (ifcnt4 + ifcnt6) * sizeof(uint32_t);

	if(ifcnt4 != 0)
	{
		handle->m_addrlist->v4list = (scap_ifinfo_ipv4 *)malloc(ifcnt4 * sizeof(scap_ifinfo_ipv4));
		if(!handle->m_addrlist->v4list)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_iflist allocation failed(2)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		handle->m_addrlist->v4list = NULL;
	}

	if(ifcnt6 != 0)
	{
		handle->m_addrlist->v6list = (scap_ifinfo_ipv6 *)malloc(ifcnt6 * sizeof(scap_ifinfo_ipv6));
		if(!handle->m_addrlist->v6list)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "getifaddrs allocation failed(3)");
			res = SCAP_FAILURE;
			goto scap_read_iflist_error;
		}
	}
	else
	{
		handle->m_addrlist->v6list = NULL;
	}

	handle->m_addrlist->n_v4_addrs = ifcnt4;
	handle->m_addrlist->n_v6_addrs = ifcnt6;

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
			entrysize = *(uint32_t *)pif;
			totreadsize += sizeof(uint32_t);
			pif += sizeof(uint32_t);
		}

		iftype = *(uint16_t *)pif;
		ifnamlen = *(uint16_t *)(pif + 2);

		if(ifnamlen >= SCAP_MAX_PATH_SIZE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(0)");
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
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(3)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy(handle->m_addrlist->v4list + ifcnt4, pif, ifsize - ifnamlen);

			memcpy(handle->m_addrlist->v4list[ifcnt4].ifname, pif + ifsize - ifnamlen, ifnamlen);

			// Make sure the name string is NULL-terminated
			*((char *)(handle->m_addrlist->v4list + ifcnt4) + ifsize) = 0;

			ifcnt4++;
		}
		else if(iftype == SCAP_II_IPV4_NOLINKSPEED)
		{
			scap_ifinfo_ipv4_nolinkspeed* src;
			scap_ifinfo_ipv4* dst;

			ifsize = sizeof(scap_ifinfo_ipv4_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < ifsize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(4)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv4_nolinkspeed*)pif;
			dst = handle->m_addrlist->v4list + ifcnt4;

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
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(5)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			memcpy(handle->m_addrlist->v6list + ifcnt6, pif, ifsize - ifnamlen);

			memcpy(handle->m_addrlist->v6list[ifcnt6].ifname, pif + ifsize - ifnamlen, ifnamlen);

			// Make sure the name string is NULL-terminated
			*((char *)(handle->m_addrlist->v6list + ifcnt6) + ifsize) = 0;

			ifcnt6++;
		}
		else if(iftype == SCAP_II_IPV6_NOLINKSPEED)
		{
			scap_ifinfo_ipv6_nolinkspeed* src;
			scap_ifinfo_ipv6* dst;
			ifsize = sizeof(scap_ifinfo_ipv6_nolinkspeed) + ifnamlen - SCAP_MAX_PATH_SIZE;

			if(toread < ifsize)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "trace file has corrupted interface list(6)");
				res = SCAP_FAILURE;
				goto scap_read_iflist_error;
			}

			// Copy the entry
			src = (scap_ifinfo_ipv6_nolinkspeed*)pif;
			dst = handle->m_addrlist->v6list + ifcnt6;

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
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unknown interface type %d", (int)iftype);
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
	scap_free_iflist(handle->m_addrlist);
	handle->m_addrlist = NULL;

	if(readbuf)
	{
		free(readbuf);
	}

	return res;
}

//
// Parse a user list block
//
static int32_t scap_read_userlist(scap_t *handle, scap_reader_t* r, uint32_t block_length, uint32_t block_type)
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
	// not the first interface list block), free it
	//
	if(handle->m_userlist != NULL)
	{
		scap_free_userlist(handle->m_userlist);
		handle->m_userlist = NULL;
	}

	//
	// Allocate and initialize the handle info
	//
	handle->m_userlist = (scap_userlist*)malloc(sizeof(scap_userlist));
	if(handle->m_userlist == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "userlist allocation failed(2)");
		return SCAP_FAILURE;
	}

	handle->m_userlist->nusers = 0;
	handle->m_userlist->ngroups = 0;
	handle->m_userlist->totsavelen = 0;
	handle->m_userlist->users = NULL;
	handle->m_userlist->groups = NULL;

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
			readsize = scap_reader_read(r, &(sub_len), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;
		}

		//
		// type
		//
		readsize = scap_reader_read(r, &(type), sizeof(type));
		CHECK_READ_SIZE(readsize, sizeof(type));

		subreadsize += readsize;

		if(type == USERBLOCK_TYPE_USER)
		{
			scap_userinfo* puser;

			handle->m_userlist->nusers++;
			handle->m_userlist->users = (scap_userinfo*)realloc(handle->m_userlist->users, handle->m_userlist->nusers * sizeof(scap_userinfo));
			if(handle->m_userlist->users == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(1)");
				return SCAP_FAILURE;
			}

			puser = &handle->m_userlist->users[handle->m_userlist->nusers -1];

			//
			// uid
			//
			readsize = scap_reader_read(r, &(puser->uid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// gid
			//
			readsize = scap_reader_read(r, &(puser->gid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// name
			//
			readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user name len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = scap_reader_read(r, puser->name, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			puser->name[stlen] = 0;

			subreadsize += readsize;

			//
			// homedir
			//
			readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user homedir len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = scap_reader_read(r, puser->homedir, stlen);
			CHECK_READ_SIZE(readsize, stlen);

			// the string is not null-terminated on file
			puser->homedir[stlen] = 0;

			subreadsize += readsize;

			//
			// shell
			//
			readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid user shell len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = scap_reader_read(r, puser->shell, stlen);
			CHECK_READ_SIZE(readsize, stlen);

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

			handle->m_userlist->ngroups++;
			handle->m_userlist->groups = (scap_groupinfo*)realloc(handle->m_userlist->groups, handle->m_userlist->ngroups * sizeof(scap_groupinfo));
			if(handle->m_userlist->groups == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "memory allocation error in scap_read_userlist(2)");
				return SCAP_FAILURE;
			}

			pgroup = &handle->m_userlist->groups[handle->m_userlist->ngroups -1];

			//
			// gid
			//
			readsize = scap_reader_read(r, &(pgroup->gid), sizeof(uint32_t));
			CHECK_READ_SIZE(readsize, sizeof(uint32_t));

			subreadsize += readsize;

			//
			// name
			//
			readsize = scap_reader_read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE(readsize, sizeof(uint16_t));

			if(stlen >= MAX_CREDENTIALS_STR_LEN)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid group name len %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = scap_reader_read(r, pgroup->name, stlen);
			CHECK_READ_SIZE(readsize, stlen);

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
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Had read %lu bytes, but userlist entry have length %u.",
					 subreadsize, sub_len);
				return SCAP_FAILURE;
			}
			toread = sub_len - subreadsize;
			fseekres = (int)scap_reader_seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip %u bytes.",
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
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_userlist read more %lu than a block %u", totreadsize, block_length);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = scap_reader_read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

//
// Parse a process list block
//
static int32_t scap_read_fdlist(scap_t *handle, scap_reader_t* r, uint32_t block_length, uint32_t block_type)
{
	size_t readsize;
	size_t totreadsize = 0;
	size_t padding_len;
	struct scap_threadinfo *tinfo;
	scap_fdinfo fdi;
	scap_fdinfo *nfdi;
	//  uint16_t stlen;
	uint64_t tid;
	int32_t uth_status = SCAP_SUCCESS;
	uint32_t padding;

	//
	// Read the tid
	//
	readsize = scap_reader_read(r, &tid, sizeof(tid));
	CHECK_READ_SIZE(readsize, sizeof(tid));
	totreadsize += readsize;

	if(handle->m_proc_callback == NULL)
	{
		//
		// Identify the process descriptor
		//
		HASH_FIND_INT64(handle->m_proclist, &tid, tinfo);
		if(tinfo == NULL)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted trace file. FD block references TID %"PRIu64", which doesn't exist.",
					 tid);
			return SCAP_FAILURE;
		}
	}
	else
	{
		tinfo = NULL;
	}

	while(((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		if(scap_fd_read_from_disk(handle, &fdi, &readsize, block_type, r) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
		totreadsize += readsize;

		//
		// Add the entry to the table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			//
			// Parsed successfully. Allocate the new entry and copy the temp one into into it.
			//
			nfdi = (scap_fdinfo *)malloc(sizeof(scap_fdinfo));
			if(nfdi == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd1)");
				return SCAP_FAILURE;
			}

			// Structure copy
			*nfdi = fdi;

			ASSERT(tinfo != NULL);

			HASH_ADD_INT64(tinfo->fdlist, fd, nfdi);
			if(uth_status != SCAP_SUCCESS)
			{
				free(nfdi);
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process table allocation error (fd2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			ASSERT(tinfo == NULL);

			handle->m_proc_callback(handle->m_proc_callback_context, handle, tid, NULL, &fdi);
		}
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if(totreadsize > block_length)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_read_fdlist read more %lu than a block %u", totreadsize, block_length);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = scap_reader_read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE(readsize, padding_len);

	return SCAP_SUCCESS;
}

int32_t scap_read_section_header(scap_t *handle, scap_reader_t* r)
{
	section_header_block sh;
	uint32_t bt;

	//
	// Read the section header block
	//
	if(scap_reader_read(r, &sh, sizeof(sh)) != sizeof(sh) ||
	   scap_reader_read(r, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(sh.byte_order_magic != 0x1a2b3c4d)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid magic number");
		return SCAP_FAILURE;
	}

	if(sh.major_version > CURRENT_MAJOR_VERSION)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE,
			 "cannot correctly parse the capture. Upgrade your version.");
		return SCAP_VERSION_MISMATCH;
	}

	return SCAP_SUCCESS;
}

//
// Parse the headers of a trace file and load the tables
//
int32_t scap_read_init(scap_t *handle, scap_reader_t* r)
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
	if(scap_reader_read(r, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(bh.block_type != SHB_BLOCK_TYPE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid block type");
		return SCAP_FAILURE;
	}

	if((rc = scap_read_section_header(handle, r)) != SCAP_SUCCESS)
	{
		return rc;
	}

	//
	// Read the metadata blocks (processes, FDs, etc.)
	//
	while(true)
	{
		readsize = scap_reader_read(r, &bh, sizeof(bh));

		//
		// If we don't find the event block header,
		// it means there is no event in the file.
		//
		if (readsize == 0 && !found_ev)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "no events in file");
			return SCAP_FAILURE;
		}

		CHECK_READ_SIZE(readsize, sizeof(bh));

		switch(bh.block_type)
		{
		case MI_BLOCK_TYPE:
		case MI_BLOCK_TYPE_INT:

			if(scap_read_machine_info(handle, r, bh.block_total_length - sizeof(block_header) - 4) != SCAP_SUCCESS)
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

			if(scap_read_proclist(handle, r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case FDL_BLOCK_TYPE:
		case FDL_BLOCK_TYPE_INT:
		case FDL_BLOCK_TYPE_V2:

			if(scap_read_fdlist(handle, r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type) != SCAP_SUCCESS)
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
			found_ev = 1;

			//
			// We're done with the metadata headers. Rewind the file position so we are aligned to start reading the events.
			//
			fseekres = scap_reader_seek(r, (long)0 - sizeof(bh), SEEK_CUR);
			if(fseekres != -1)
			{
				break;
			}
			else
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error seeking in file");
				return SCAP_FAILURE;
			}
		case IL_BLOCK_TYPE:
		case IL_BLOCK_TYPE_INT:
		case IL_BLOCK_TYPE_V2:

			if(scap_read_iflist(handle, r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		case UL_BLOCK_TYPE:
		case UL_BLOCK_TYPE_INT:
		case UL_BLOCK_TYPE_V2:

			if(scap_read_userlist(handle, r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		default:
			//
			// Unknown block type. Skip the block.
			//
			toread = bh.block_total_length - sizeof(block_header) - 4;
			fseekres = (int)scap_reader_seek(r, (long)toread, SEEK_CUR);
			if(fseekres == -1)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip block of type %x and size %u.",
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
		readsize = scap_reader_read(r, &bt, sizeof(bt));
		CHECK_READ_SIZE(readsize, sizeof(bt));

		if(bt != bh.block_total_length)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "wrong block total length, header=%u, trailer=%u",
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
int32_t scap_next_offline(scap_t *handle, OUT scap_evt **pevent, OUT uint16_t *pcpuid)
{
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
		readsize = scap_reader_read(r, &bh, sizeof(bh));

		if(readsize != sizeof(bh))
		{
			int err_no = 0;
#ifdef WIN32
			const char* err_str = "read error";
#else
			const char* err_str = scap_reader_error(r, &err_no);
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
			handle->m_unexpected_block_readsize = readsize;
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
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than read buffer size %zu",
					 readlen,
					 handle->m_reader_evt_buf_size);
				return SCAP_FAILURE;
			}
			handle->m_reader_evt_buf = tmp;
			handle->m_reader_evt_buf_size = readlen;
		}

		readsize = scap_reader_read(r, handle->m_reader_evt_buf, readlen);
		CHECK_READ_SIZE(readsize, readlen);

		//
		// EVF_BLOCK_TYPE has 32 bits of flags
		//
		*pcpuid = *(uint16_t *)handle->m_reader_evt_buf;

		if(bh.block_type == EVF_BLOCK_TYPE || bh.block_type == EVF_BLOCK_TYPE_V2 || bh.block_type == EVF_BLOCK_TYPE_V2_LARGE)
		{
			handle->m_last_evt_dump_flags = *(uint32_t*)(handle->m_reader_evt_buf + sizeof(uint16_t));
			*pevent = (struct ppm_evt_hdr *)(handle->m_reader_evt_buf + sizeof(uint16_t) + sizeof(uint32_t));
		}
		else
		{
			handle->m_last_evt_dump_flags = 0;
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

uint64_t scap_ftell(scap_t *handle)
{
	return scap_reader_tell(handle->m_reader);
}

void scap_fseek(scap_t *handle, uint64_t off)
{
	switch (scap_reader_type(handle->m_reader))
	{
		case RT_FILE:
			scap_reader_seek(handle->m_reader, off, SEEK_SET);
			return;
		default:
			ASSERT(false);
			return;
	}
}
