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

#include "scap.h"
#include "scap-int.h"
#include "uthash_ext.h"
#include <inttypes.h>
#include <string.h>

void scap_fd_free_table(scap_fdinfo **fds)
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

void scap_fd_free_proc_fd_table(scap_threadinfo *tinfo)
{
	if(tinfo->fdlist)
	{
		scap_fd_free_table(&tinfo->fdlist);
	}
}


//
// Add the file descriptor info pointed by fdi to the fd table for process tinfo.
//
int32_t scap_add_fd_to_proc_table(struct scap_proclist *proclist, scap_threadinfo *tinfo, scap_fdinfo *fdi, char *error)
{
	//
	// Add the fd to the table, or fire the notification callback
	//
	if(proclist->m_proc_callback == NULL)
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

		scap_fdinfo *new_fdi = malloc(sizeof(*new_fdi));
		if(new_fdi == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (1)");
			return SCAP_FAILURE;
		}
		*new_fdi = *fdi;

		HASH_ADD_INT64(tinfo->fdlist, fd, new_fdi);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		proclist->m_proc_callback(
			proclist->m_proc_callback_context, error, tinfo->tid, tinfo, fdi, NULL);
	}

	return SCAP_SUCCESS;
}

//
// Free the device table
//
void scap_free_device_table(scap_mountinfo* dev_list)
{
	scap_mountinfo *dev, *tdev;

	HASH_ITER(hh, dev_list, dev, tdev)
	{
		HASH_DEL(dev_list, dev);
		free(dev);
	}
}
