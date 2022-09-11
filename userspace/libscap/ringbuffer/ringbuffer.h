/*
Copyright (C) 2022 The Falco Authors.

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
#include <stdint.h>

#include "devset.h"
#include "../../../driver/ppm_ringbuffer.h"
#include "barrier.h"
#include "sleep.h"

extern unsigned long per_cpu_buffer_dim;

static inline void set_per_cpu_buffer_dim(unsigned long buf_dim)
{
	per_cpu_buffer_dim = buf_dim;
}

#ifndef GET_BUF_POINTERS
#define GET_BUF_POINTERS ringbuffer_get_buf_pointers
static inline void ringbuffer_get_buf_pointers(scap_device* dev, uint64_t* phead, uint64_t* ptail, uint64_t* pread_size)
{
	struct ppm_ring_buffer_info* bufinfo = dev->m_bufinfo;
	*phead = bufinfo->head;
	*ptail = bufinfo->tail;

	if(*ptail > *phead)
	{
		*pread_size = per_cpu_buffer_dim - *ptail + *phead;
	}
	else
	{
		*pread_size = *phead - *ptail;
	}
}
#endif

#ifndef ADVANCE_TAIL
#define ADVANCE_TAIL ringbuffer_advance_tail
static inline void ringbuffer_advance_tail(struct scap_device* dev)
{
	uint32_t ttail;

	//
	// Update the tail based on the amount of data read in the *previous* call.
	// Tail is never updated when we serve the data, because we assume that the caller is using
	// the buffer we give to her until she calls us again.
	//
	ttail = dev->m_bufinfo->tail + dev->m_lastreadsize;

	//
	// Make sure every read of the old buffer is completed before we move the tail and the
	// producer (on another CPU) can start overwriting it.
	// I use this instead of asm(mfence) because it should be portable even on the weirdest
	// CPUs
	//
	mem_barrier();

	if(ttail < per_cpu_buffer_dim)
	{
		dev->m_bufinfo->tail = ttail;
	}
	else
	{
		dev->m_bufinfo->tail = ttail - per_cpu_buffer_dim;
	}

	dev->m_lastreadsize = 0;
}
#endif

#ifndef READBUF
#define READBUF ringbuffer_readbuf
static inline int32_t ringbuffer_readbuf(struct scap_device *dev, OUT char** buf, OUT uint32_t* len)
{
	uint64_t thead;
	uint64_t ttail;
	uint64_t read_size;

	//
	// Read the pointers.
	//
	ringbuffer_get_buf_pointers(dev,
				    &thead,
				    &ttail,
				    &read_size);

	//
	// Remember read_size so we can update the tail at the next call
	//
	dev->m_lastreadsize = (uint32_t)read_size;

	//
	// Return the results
	//
	*len = (uint32_t)read_size;
	*buf = dev->m_buffer + ttail;

	return SCAP_SUCCESS;
}
#endif

static inline uint64_t buf_size_used(scap_device* dev)
{
	uint64_t read_size;
	uint64_t thead;
	uint64_t ttail;

	GET_BUF_POINTERS(dev, &thead, &ttail, &read_size);

	return read_size;
}

static inline bool are_buffers_empty(struct scap_device_set *devset)
{
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++)
	{
		if(buf_size_used(&devset->m_devs[j]) > BUFFER_EMPTY_THRESHOLD_B)
		{
			return false;
		}
	}

	return true;
}

static inline int32_t refill_read_buffers(struct scap_device_set *devset)
{
	uint32_t j;
	uint32_t ndevs = devset->m_ndevs;

	if(are_buffers_empty(devset))
	{
		sleep_ms(devset->m_buffer_empty_wait_time_us / 1000);
		devset->m_buffer_empty_wait_time_us = MIN(devset->m_buffer_empty_wait_time_us * 2,
							  BUFFER_EMPTY_WAIT_TIME_US_MAX);
	}
	else
	{
		devset->m_buffer_empty_wait_time_us = BUFFER_EMPTY_WAIT_TIME_US_START;
	}

	//
	// Refill our data for each of the devices
	//

	for(j = 0; j < ndevs; j++)
	{
		struct scap_device *dev = &(devset->m_devs[j]);

		int32_t res = READBUF(dev,
				      &dev->m_sn_next_event,
				      &dev->m_sn_len);

		if(res != SCAP_SUCCESS)
		{
			return res;
		}
	}

	//
	// Note: we might return a spurious timeout here in case the previous loop extracted valid data to parse.
	//       It's ok, since this is rare and the caller will just call us again after receiving a
	//       SCAP_TIMEOUT.
	//
	return SCAP_TIMEOUT;
}

#ifndef NEXT_EVENT
#define NEXT_EVENT ringbuffer_next_event
static inline scap_evt* ringbuffer_next_event(scap_device* dev)
{
	return (scap_evt*)dev->m_sn_next_event;
}
#endif

#ifndef ADVANCE_TO_EVT
#define ADVANCE_TO_EVT ringbuffer_advance_to_evt
static inline void ringbuffer_advance_to_evt(scap_device* dev, scap_evt *event)
{
	ASSERT(dev->m_sn_len >= event->len);
	dev->m_sn_len -= event->len;
	dev->m_sn_next_event += event->len;
}
#endif

static inline int32_t ringbuffer_next(struct scap_device_set *devset, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	uint32_t j;
	uint64_t max_ts = 0xffffffffffffffffLL;
	scap_evt* pe = NULL;
	uint32_t ndevs = devset->m_ndevs;

	*pcpuid = 65535;

	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(devset->m_devs[j]);

		if(dev->m_sn_len == 0)
		{
			//
			// If we don't have data from this ring, but we are
			// still occupying, free the resources for the
			// producer rather than sitting on them.
			//
			if(dev->m_lastreadsize > 0)
			{
				ADVANCE_TAIL(dev);
			}

			continue;
		}

		pe = NEXT_EVENT(dev);

		//
		// We want to consume the event with the lowest timestamp
		//
		if(pe->ts < max_ts)
		{
			if(pe->len > dev->m_sn_len)
			{
				snprintf(devset->m_lasterr, SCAP_LASTERR_SIZE, "scap_next buffer corruption");

				//
				// if you get the following assertion, first recompile the driver and libscap
				//
				ASSERT(false);
				return SCAP_FAILURE;
			}

			*pevent = pe;
			*pcpuid = j;
			max_ts = pe->ts;
		}
	}

	//
	// Check which buffer has been picked
	//
	if(*pcpuid != 65535)
	{
		struct scap_device *dev = &devset->m_devs[*pcpuid];

		//
		// Update the pointers.
		//
		ADVANCE_TO_EVT(dev, (*pevent));
		return SCAP_SUCCESS;
	}
	else
	{
		//
		// All the buffers have been consumed. Check if there's enough data to keep going or
		// if we should wait.
		//
		return refill_read_buffers(devset);
	}
}

static inline uint64_t ringbuffer_get_max_buf_used(struct scap_device_set *devset)
{
	uint64_t i;
	uint64_t max = 0;

	for(i = 0; i < devset->m_ndevs; i++)
	{
		uint64_t size = buf_size_used(&devset->m_devs[i]);
		max = size > max ? size : max;
	}

	return max;
}
