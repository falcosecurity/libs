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

#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <scap.h>

#define MAX_ALLOWED_VALUES 12

/* Dimension of a single per-CPU buffer. */
unsigned long per_cpu_buffer_dim;

void set_per_cpu_buffer_dim(unsigned long buf_dim)
{
	per_cpu_buffer_dim = buf_dim;
}

int32_t check_per_cpu_buffer_num_pages(char* last_err, unsigned long buf_num_pages)
{
	/* Allowed page numbers are all the power of 2 from 128(2^7) pages to 256Kpages(2^18) */
	int allowed_num_pages_values[MAX_ALLOWED_VALUES] = {pow(2, 7), pow(2, 8), pow(2, 9), pow(2, 10), pow(2, 11), pow(2, 12), pow(2, 13), pow(2, 14), pow(2, 15), pow(2, 16), pow(2, 17), pow(2, 18)};
	bool found = false;

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

	for(int i = 0; i < MAX_ALLOWED_VALUES; i++)
	{
		if(allowed_num_pages_values[i] == buf_num_pages)
		{
			found = true;
			break;
		}
	}

	if(!found)
	{
		if(last_err != NULL)
		{
			snprintf(last_err, SCAP_LASTERR_SIZE, "Allowed page numbers are all the powers of 2 from 128 pages (2^7) to 256 Kpages (2^18): '%lu' is not a valid value", buf_num_pages);
		}
		return SCAP_FAILURE;
	}
	return SCAP_SUCCESS;
}
