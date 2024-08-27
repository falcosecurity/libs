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
#include <stdlib.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/uthash_ext.h>
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
