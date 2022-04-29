#include "devset.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32
#include <sys/mman.h>
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
