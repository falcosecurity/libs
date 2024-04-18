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
#include <stdint.h>

#include <libscap/ringbuffer/devset.h>
#include <driver/ppm_ringbuffer.h>
#include <libscap/scap_barrier.h>
#include <libscap/scap_sleep.h>

/* Check buffer dimension in bytes. 
 * Our 2 eBPF probes require that this number is a power of 2! Right now we force this
 * constraint to all our drivers (also the kernel module and udig) just for conformity.
 */
int32_t check_buffer_bytes_dim(char* error, unsigned long buf_bytes_dim);


#ifndef GET_BUF_POINTERS
#define GET_BUF_POINTERS ringbuffer_get_buf_pointers
static inline void ringbuffer_get_buf_pointers(scap_device* dev, uint64_t* phead, uint64_t* ptail, uint64_t* pread_size)
{
	struct ppm_ring_buffer_info* bufinfo = dev->m_bufinfo;
	*phead = bufinfo->head;
	*ptail = bufinfo->tail;

	if(*ptail > *phead)
	{
		*pread_size = dev->m_buffer_size - *ptail + *phead;
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

	if(ttail < dev->m_buffer_size)
	{
		dev->m_bufinfo->tail = ttail;
	}
	else
	{
		dev->m_bufinfo->tail = ttail - dev->m_buffer_size;
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

/* if at least one buffer has more than `BUFFER_EMPTY_THRESHOLD_B` return false
 * otherwise return true and consider all the buffers empty.
 */
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

	/* In any case (potentially also after a `sleep`) we refill our buffers */
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

	/* Return `SCAP_TIMEOUT` after a refill so we can start consuming the new events. */
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

/* The flow here is:
 * - For every buffer, read how many data are available and save the pointer + its length. (this is what we call a block)
 * - Consume from all these blocks the event with the lowest timestamp. (repeat until all the blocks are empty!)
 *   When we have read all the data from a buffer block, update the consumer position for that buffer, and wait
 *   for all the other buffer blocks to be read.
 * - When we have consumed all the blocks we are ready to read again a new block for every buffer
 * 
 * Possible pain points:
 * - if the buffers are not full enough we sleep and this could be dangerous in this situation!
 * - we increase the consumer position only when we have consumed the entire block, but if the block
 *   is huge we could cause several drops.
 * - before refilling a buffer we have to consume all the others!
 * - we perform a lot of cycles but we have to be super fast here!
 */
static inline int32_t ringbuffer_next(struct scap_device_set* devset, OUT scap_evt** pevent, OUT uint16_t* pdevid,
				      OUT uint32_t* pflags)
{
	uint32_t j;
	uint64_t min_ts = 0xffffffffffffffffLL;
	scap_evt* pe = NULL;
	uint32_t ndevs = devset->m_ndevs;

	*pdevid = 65535;

	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(devset->m_devs[j]);

		/* `dev->m_sn_len` and `dev->m_lastreadsize` initially contain the dimension
		 * of the full buffer block we have read in `refill_read_buffers`.
		 * The difference is that `dev->m_sn_len` is decreased at every new event
		 * that we read while `dev->m_lastreadsize` preserve the block dimension since
		 * it will be used to move the consumer position in `ADVANCE_TAIL`.
		 * 
		 * Note that even if we have consumed the entire block for this buffer we don't refill
		 * it immediately but we wait for all other buffers!
		 */ 
		if(dev->m_sn_len == 0)
		{
			/* If we don't have data from this ring, but we are
			 * still occupying, free the resources for the
			 * producer rather than sitting on them.
			 * 
			 * Please note: this is the unique point in which
			 * we move the consumer position. We move the consumer
			 * position only when we have consumed all the block
			 * previously read in `refill_read_buffers`.
			 * 
			 * This could be quite dangerous if we read huge blocks
			 * because we have to read the entire block before increasing
			 * the consumer!
			 * 
			 * `dev->m_lastreadsize` this contains the full length of the entire 
			 * block we have just consumed.
			 */
			if(dev->m_lastreadsize > 0)
			{
				ADVANCE_TAIL(dev);
			}

			continue;
		}

		/* Get the next event from the block */
		pe = NEXT_EVENT(dev);

		/* Search the event with the lower timestamp */
		if(pe->ts < min_ts)
		{
			/* if the event length is greater than the remaining size in our block there is something wrong! */
			if(pe->len > dev->m_sn_len)
			{
				snprintf(devset->m_lasterr, SCAP_LASTERR_SIZE, "scap_next buffer corruption");

				/* if you get the following assertion, first recompile the driver and `libscap` */
				ASSERT(false);
				return SCAP_FAILURE;
			}

			*pevent = pe;
			*pdevid = j;
			min_ts = pe->ts;
		}
	}

	if(*pdevid != 65535)
	{
		/* Check from which buffer we have read and move the position inside
	 	 * the block with `ADVANCE_TO_EVT`
	 	 */
		struct scap_device* dev = &devset->m_devs[*pdevid];
		ADVANCE_TO_EVT(dev, (*pevent));

		// we don't really store the flags in the ringbuffer anywhere
		*pflags = 0;
		return SCAP_SUCCESS;
	}
	else
	{
		/* If there are enough new data read again one block for every buffer
		 * otherwise sleep!
		 */
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
