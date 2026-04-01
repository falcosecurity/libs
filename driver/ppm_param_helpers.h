// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2026 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_FLAG_HELPERS_H_
#define PPM_FLAG_HELPERS_H_

// This file just provides helpers for userspace code.
#if !defined(__KERNEL__) && !defined(__USE_VMLINUX__)

#include <assert.h>
#include <stddef.h>
#include "ppm_events_public.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

// Stores the minimum parameter length for a parameter of type `t` in `min_len`. Returns 0 on
// success, a negative number otherwise.
static inline int ppm_param_min_len_from_type(const enum ppm_param_type t, uint32_t *min_len) {
	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		*min_len = 1;
		return 0;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
	case PT_PORT:
		*min_len = 2;
		return 0;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_SIGSET:
	case PT_FD32:
	case PT_PID32:
	case PT_IPV4ADDR:
		*min_len = 4;
		return 0;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		*min_len = 8;
		return 0;

	case PT_IPV6ADDR:
		*min_len = 16;
		return 0;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
	case PT_SOCKADDR:
		*min_len = 0;
		return 0;

	default:
		// We forgot to handle something.
		assert(false);
		return -1;
	}
}

// Stores the maximum parameter length for a parameter of type `t` in `max_len`. The maximum length
// depends on the length size, which could be 2 or 4 bytes. Returns 0 on success, a negative number
// otherwise.
static inline int ppm_param_max_len_from_type(const enum ppm_param_type t,
                                              const size_t len_size,
                                              uint32_t *max_len) {
	if(len_size != sizeof(uint16_t) && len_size != sizeof(uint32_t)) {
		assert(false);
		return -1;
	}

	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		*max_len = 1;
		return 0;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
	case PT_PORT:
		*max_len = 2;
		return 0;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_SIGSET:
	case PT_FD32:
	case PT_PID32:
	case PT_IPV4ADDR:
		*max_len = 4;
		return 0;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		*max_len = 8;
		return 0;

	case PT_IPV6ADDR:
		*max_len = 16;
		return 0;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
	case PT_SOCKADDR:
		switch(len_size) {
		case sizeof(uint16_t): {
			*max_len = UINT16_MAX;
			return 0;
		}
		case sizeof(uint32_t): {
			*max_len = UINT32_MAX;
			return 0;
		}
		default:
			assert(false);
			return -2;
		}

	default:
		// We forgot to handle something.
		assert(false);
		return -3;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* #if !defined(__KERNEL__) && !defined(__USE_VMLINUX__) */

#endif /* #ifndef PPM_FLAG_HELPERS_H_ */
