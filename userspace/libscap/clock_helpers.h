/*

Copyright (c) 2021 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __CLOCK_HELPERS_H
#define __CLOCK_HELPERS_H

#define SCAP_GET_CUR_TS_MS_CONTEXT_INIT ((uint64_t)0)
#define SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG ((uint64_t)0x8000000000000000)
#define SCAP_GET_CUR_TS_MS_CONTEXT_PREV_VALUE_MASK ((uint64_t)0x7fffffffffffffff)

#define S_TO_MS(_sec) (((uint64_t)_sec) * (uint64_t)1000)
#define NS_TO_MS(_ns) (((uint64_t)_ns) / ((uint64_t)(1000 * 1000)))

/**
 * Return monotonically increasing time in ms.
 * Caller initializes context to SCAP_GET_CUR_TS_MS_CONTEXT_INIT,
 * Function uses and updates context, to recognize and handle the
 * following cases:
 * - failed clock_gettime() system call
 * - non-monotonic behavior of CLOCK_MONOTONIC
 * - time values that cannot be represented in uint64_t number of msec
 */
static __always_inline uint64_t scap_get_monotonic_ts_ms(uint64_t* context)
{
	// Record previously reported time; will be 0 for first call.
	uint64_t prev_time = ((*context) & SCAP_GET_CUR_TS_MS_CONTEXT_PREV_VALUE_MASK);

	// If context indicates error already detected, just return the
	// last reported time
	if ((*context) & SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG)
	{
		return prev_time;
	}

	// Fetch current monotonic time from kernel
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
	{
		// System call failed.
		// Set error flag
		*context |= SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG;

		// Return previously reported time, now frozen
		return prev_time;
	}

	// Form new time
	uint64_t new_time = S_TO_MS(ts.tv_sec) + NS_TO_MS(ts.tv_nsec);

	// Check for overflow or non-monotonic behavior
	if ((new_time & SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG) ||
	    (new_time < prev_time))
	{
		// System call failed.
		// Set error flag
		*context |= SCAP_GET_CUR_TS_MS_CONTEXT_ERROR_FLAG;

		// Return previously reported time, now frozen
		return prev_time;
	}

	// New time looks OK.
	// Store it into the context, and return it.
	*context = new_time;
	return new_time;
}

#endif /* __CLOCK_HELPERS_H */
