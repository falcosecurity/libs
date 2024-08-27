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
#include <libscap/ringbuffer/devset.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <libscap/strl.h>
#include <libscap/scap.h>
#include <libscap/scap_assert.h>

int32_t devset_init(struct scap_device_set *devset, size_t num_devs, char *lasterr)
{
	devset->m_ndevs = num_devs;

	devset->m_devs = (scap_device*) calloc(devset->m_ndevs, sizeof(scap_device));
	if(!devset->m_devs)
	{
		strlcpy(lasterr, "error allocating the device handles", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	for(size_t j = 0; j < num_devs; ++j)
	{
		devset->m_devs[j].m_buffer = INVALID_MAPPING;
		devset->m_devs[j].m_bufinfo = INVALID_MAPPING;
		devset->m_devs[j].m_bufstatus = INVALID_MAPPING;
		devset->m_devs[j].m_fd = INVALID_FD;
		devset->m_devs[j].m_bufinfo_fd = INVALID_FD;
		devset->m_devs[j].m_lastreadsize = 0;
		devset->m_devs[j].m_sn_len = 0;
	}
	devset->m_buffer_empty_wait_time_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	devset->m_lasterr = lasterr;

	return SCAP_SUCCESS;
}

void devset_close_device(struct scap_device *dev)
{
	devset_munmap(dev->m_buffer, dev->m_mmap_size);
	devset_munmap(dev->m_bufinfo, dev->m_bufinfo_size);
	devset_close(dev->m_fd);
	devset_close(dev->m_bufinfo_fd);
}

void devset_free(struct scap_device_set *devset)
{
	if(devset == NULL || devset->m_devs == NULL)
	{
		return;
	}

	uint32_t j;
	for(j = 0; j < devset->m_ndevs; j++)
	{
		struct scap_device *dev = &devset->m_devs[j];
		devset_close_device(dev);
	}
	free(devset->m_devs);
}
