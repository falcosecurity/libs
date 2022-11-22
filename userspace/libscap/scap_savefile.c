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

#ifndef _WIN32
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
	if(d->m_type == DT_FILE)
	{
		return gzwrite(d->m_f, buf, len);
	}
	else
	{
		if(d->m_targetbufcurpos + len >= d->m_targetbufend)
		{
			if(d->m_type == DT_MEM)
			{
				return -1;
			}

			// DT_MANAGED_BUF, try to increase the size
			size_t targetbufsize = PPM_DUMPER_MANAGED_BUF_RESIZE_FACTOR * (d->m_targetbufend - d->m_targetbuf);

			uint8_t *targetbuf = (uint8_t *)realloc(
				d->m_targetbuf,
				targetbufsize);
			if(targetbuf == NULL)
			{
				return -1;
			}

			size_t offset = (d->m_targetbufcurpos - d->m_targetbuf);
			d->m_targetbuf = targetbuf;
			d->m_targetbufcurpos = targetbuf + offset;
			d->m_targetbufend = targetbuf + targetbufsize;
		}

		memcpy(d->m_targetbufcurpos, buf, len);

		d->m_targetbufcurpos += len;
		return len;
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

#ifndef _WIN32
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

	HASH_ITER(hh, handle->m_proclist.m_proclist, tinfo, ttinfo)
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
	return scap_managedbuf_dump_create(handle);
}
int scap_write_proclist_end(scap_t *handle, scap_dumper_t *d, scap_dumper_t *proclist_dumper, uint32_t totlen)
{
	ASSERT(handle != NULL);
	ASSERT(proclist_dumper != NULL);
	ASSERT(proclist_dumper->m_type == DT_MANAGED_BUF);

	int res = SCAP_SUCCESS;

	do
	{
		scap_dump_flush(proclist_dumper);

		if(scap_write_proclist_header(handle, d, totlen) != SCAP_SUCCESS)
		{
			res = SCAP_FAILURE;
			break;
		}
		if(scap_dump_write(d, proclist_dumper->m_targetbuf, totlen) <= 0)
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

	scap_dump_close(proclist_dumper);

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
	if(HASH_COUNT(handle->m_proclist.m_proclist) == 0)
	{
		return SCAP_SUCCESS;
	}

	scap_dumper_t *proclist_dumper = scap_write_proclist_begin(handle);

	uint32_t totlen = 0;
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	HASH_ITER(hh, handle->m_proclist.m_proclist, tinfo, ttinfo)
	{
		if(tinfo->filtered_out)
		{
			continue;
		}

		uint32_t len = 0;
		if(scap_write_proclist_entry(handle, proclist_dumper, tinfo, &len) != SCAP_SUCCESS)
		{
			scap_dump_close(proclist_dumper);
			return SCAP_FAILURE;
		}

		totlen += len;
	}

	return scap_write_proclist_end(handle, d, proclist_dumper, totlen);
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

	//
	// If we're dumping in live mode, refresh the process tables list
	// so we don't lose information about processes created in the interval
	// between opening the handle and starting the dump
	//
#if defined(HAS_CAPTURE) && !defined(_WIN32)
	if(handle->m_mode != SCAP_MODE_CAPTURE && handle->refresh_proc_table_when_saving && !skip_proc_scan)
	{
		proc_entry_callback tcb = handle->m_proclist.m_proc_callback;
		handle->m_proclist.m_proc_callback = NULL;

		scap_proc_free_table(handle);
		char filename[SCAP_MAX_PATH_SIZE];
		snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
		if(scap_proc_scan_proc_dir(handle, filename, handle->m_lasterr) != SCAP_SUCCESS)
		{
			handle->m_proclist.m_proc_callback = tcb;
			free(res);
			return NULL;
		}

		handle->m_proclist.m_proc_callback = tcb;
	}
#endif

	if(scap_setup_dump(handle, res, fname) != SCAP_SUCCESS)
	{
		res = NULL;
	}

	//
	// If the user doesn't need the thread table, free it
	//
	if(handle->m_proclist.m_proc_callback != NULL)
	{
		scap_proc_free_table(handle);
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
#ifndef	_WIN32
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
#ifndef	_WIN32
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

	if(scap_setup_dump(handle, res, "") != SCAP_SUCCESS)
	{
		free(res);
		res = NULL;
	}

	return res;
}

//
// Create a dumper with an internally managed buffer
//
scap_dumper_t *scap_managedbuf_dump_create(scap_t *handle)
{
	scap_dumper_t *res = (scap_dumper_t *)malloc(sizeof(scap_dumper_t));
	if(res == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_managedbuf_dump_create memory allocation failure (1)");
		return NULL;
	}

	res->m_f = NULL;
	res->m_type = DT_MANAGED_BUF;
	res->m_targetbuf = (uint8_t *)malloc(PPM_DUMPER_MANAGED_BUF_SIZE);
	res->m_targetbufcurpos = res->m_targetbuf;
	res->m_targetbufend = res->m_targetbuf + PPM_DUMPER_MANAGED_BUF_SIZE;

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
	else if (d->m_type == DT_MANAGED_BUF)
	{
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
