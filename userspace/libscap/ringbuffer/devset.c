#include "devset.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#else
#define MAP_FAILED	((void *) -1)
#endif

#include "../../common/strlcpy.h"
#include "../scap.h"
#include "../scap-int.h"

int32_t devset_init(struct scap_device_set *devset, size_t num_devs, char *lasterr)
{
	devset->m_ndevs = num_devs;

	devset->m_devs = (scap_device*) calloc(sizeof(scap_device), devset->m_ndevs);
	if(!devset->m_devs)
	{
		strlcpy(lasterr, "error allocating the device handles", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	for(size_t j = 0; j < num_devs; ++j)
	{
		devset->m_devs[j].m_buffer = MAP_FAILED;
		devset->m_devs[j].m_bufinfo = MAP_FAILED;
		devset->m_devs[j].m_bufstatus = MAP_FAILED;
		devset->m_devs[j].m_fd = -1;
		devset->m_devs[j].m_bufinfo_fd = -1;
		devset->m_devs[j].m_lastreadsize = 0;
		devset->m_devs[j].m_sn_len = 0;
	}
	devset->m_buffer_empty_wait_time_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	devset->m_lasterr = lasterr;

	return SCAP_SUCCESS;
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
#ifndef _WIN32
		if(dev->m_buffer != MAP_FAILED)
		{
#ifdef _DEBUG
			int ret;
			ret = munmap(dev->m_buffer, dev->m_mmap_size);
			ASSERT(ret == 0);
#else
			munmap(dev->m_buffer, dev->m_mmap_size);
#endif
		}

		if(dev->m_bufinfo != MAP_FAILED)
		{
			munmap(dev->m_bufinfo, dev->m_bufinfo_size);
		}
#endif
		if(dev->m_fd > 0)
		{
			close(dev->m_fd);
		}
	}
	free(devset->m_devs);
}
