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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <libscap/scap.h>
#include <driver/ppm_ringbuffer.h>

int32_t check_buffer_bytes_dim(char* last_err, unsigned long buf_bytes_dim)
{
	/* If you face some memory allocation issues, please remember that:
	 *
	 * Each data page is mapped twice to allow "virtual"
	 * continuous read of samples wrapping around the end of ring
	 * buffer area:
	 *
	 * ------------------------------------------------------
	 * | meta pages |  real data pages  |  same data pages  |
	 * ------------------------------------------------------
	 * |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
	 * ------------------------------------------------------
	 * |            | TA             DA | TA             DA |
	 * ------------------------------------------------------
	 *                               ^^^^^^^
	 *                                  |
	 * Here, no need to worry about special handling of wrapped-around
	 * data due to double-mapped data pages.
	 */

	unsigned long page_size = sysconf(_SC_PAGESIZE);
	if(page_size == SCAP_FAILURE)
	{
		if(last_err != NULL)
		{
			snprintf(last_err, SCAP_LASTERR_SIZE, "unable to get the system page size: %s", strerror(errno));
		}
		return SCAP_FAILURE;
	}

	if(!validate_buffer_bytes_dim(buf_bytes_dim, page_size))
	{
		if(last_err != NULL)
		{
			snprintf(last_err, SCAP_LASTERR_SIZE, "the specified per-CPU ring buffer dimension (%lu) is not allowed! Please use a power of 2 and a multiple of the actual page_size (%lu)!", buf_bytes_dim, page_size);
		}
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}
