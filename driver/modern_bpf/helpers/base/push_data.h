// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/common.h>

/*
 * SCAP EVENT FORMAT:
 *
 * +------------------------------------------------------------------+
 * |  Header    | u16 | u16 | u16 | u16 | ... | param1 | param2 | ... |
 * +------------------------------------------------------------------+
 * ^            ^                             ^
 * |            |                             |
 * ppm_hdr      |                             |
 * lengths_arr--+                             |
 * raw_params---------------------------------+
 *
 * This is the format of events pushed to userspace.
 * We have 3 main sections:
 *
 * (1) Fixed-size header (ppm_hdr):
 *
 * struct ppm_evt_hdr {
 *    uint64_t ts;       timestamp, in nanoseconds from epoch
 *    uint64_t tid;	     the tid of the thread that generated this event
 *    uint32_t len;	     the event len, including the header
 *    uint16_t type;	 the event type
 *    uint32_t nparams;  the number of parameters of the event
 * };
 *
 * (2) Array with "nparams" elements (lengths_arr).
 * Every element is on 16 bit and represents the param length.
 *
 * (3) At the end we have all our params written in bytes (raw_params).
 * The length of every param is written in the corresponding element of
 * the `lengths_arr` since before
 *
 * According to this structure is clear that the maximum size of a
 * param is (2^16)-1 bytes (~64 KB). One param should never reach this
 * dimension, we use this number only as an upper bound in our reading
 * operations (macro MAX_PARAM_SIZE defined below), for example when
 * we read a param with `bpf_probe_read_str()` we use `MAX_PARAM_SIZE`
 * as upper bound.
 *
 * Please note: MAX_PARAM_SIZE is (2^16)-1 and so (0xffff), this
 * is why we chose this value as upper bound: with this mask we
 * can simply please the verifer during memory acccess
 * (see SAFE_ACCESS(x) macro below).
 *
 * There is just another bit of information, if you look at the definition
 * of MAX_PARAM_SIZE, you can notice that:
 *
 * #define MAX_PARAM_SIZE MAX_EVENT_SIZE - 1
 *
 * This is because the maximum size of the overall event is exactly (2^16)
 * so just one byte more than the maximum param len. This value fits well
 * our use cases in the current probe so we decided to keep it also in the
 * modern one. If the event collected exceeds this limit, it will be discarded.
 * So if one param reach the upper bound of 64 KB the event will be
 * surely discarded.
 *
 * Just to summarize we can say that:
 *
 * (ppm_hdr + lengths_arr + raw_params) <=  64 KB
 * |                                  |    |     |
 * ------------------------------------    -------
 *              event_len                    max
 *                                        event_len
 */

/* This enum is used to tell our helpers if they have to
 * read from kernel or user memory.
 */
enum read_memory
{
	USER = 0,
	KERNEL = 1,
};

/* Event maximum size */
#define MAX_EVENT_SIZE 64 * 1024

/* Paramater maximum size */
#define MAX_PARAM_SIZE MAX_EVENT_SIZE - 1

/* Helper used to please the verifier during reading
 * operations like `bpf_probe_read_str()`.
 */
#define SAFE_ACCESS(x) x &(MAX_PARAM_SIZE)

/* Given a variable, this returns its `char` pointer. */
#define CHAR_POINTER(x) (char *)&x

///////////////////////////
// PUSH PARAMS LENGTH
///////////////////////////

/**
 * @brief Push the param length in the lengths array.
 *
 * @param data pointer to the buffer that contains the `lengths_arr`.
 * @param lengths_pos pointer to the first empty slot into the `lengths_arr`.
 * @param len length to store inside the array (16 bit).
 */
static __always_inline void push__param_len(uint8_t *data, uint8_t *lengths_pos, uint16_t len)
{
	*((uint16_t *)&data[SAFE_ACCESS(*lengths_pos)]) = len;
	*lengths_pos += sizeof(uint16_t);
}

/* All the following `push__x` helpers can be seen as a sum of two operations:
 * - push some data inside a buffer (pointed by `data`)
 * - increment the actual position inside the buffer (payload_pos)
 *
 * We use these helpers in `auxmap__store_x_param` and`ringbuf__store_x_param`
 * to push into the buffer an entire param or only a portion of that.
 * The `auxmap__store_x_param` and the `ringbuf__store_x_param` will push by
 * definition an entire param but this is not the task of these
 * `push__x` helpers.
 *
 * Please note: the `push__x` helpers don't know if they are used
 * by the ringbuf or the auxamp, they receive only a raw 'data` pointer.
 *
 * These methods return nothing since we know the size that we are pushing
 */

///////////////////////////
// PUSH FIXED DIMENSIONS
///////////////////////////

static __always_inline void push__u8(uint8_t *data, uint64_t *payload_pos, uint8_t param)
{
	*((uint8_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(uint8_t);
}

static __always_inline void push__u16(uint8_t *data, uint64_t *payload_pos, uint16_t param)
{
	*((uint16_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(uint16_t);
}

static __always_inline void push__u32(uint8_t *data, uint64_t *payload_pos, uint32_t param)
{
	*((uint32_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(uint32_t);
}

static __always_inline void push__u64(uint8_t *data, uint64_t *payload_pos, uint64_t param)
{
	*((uint64_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(uint64_t);
}

static __always_inline void push__s16(uint8_t *data, uint64_t *payload_pos, int16_t param)
{
	*((int16_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(int16_t);
}

static __always_inline void push__s32(uint8_t *data, uint64_t *payload_pos, int32_t param)
{
	*((int32_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(int32_t);
}

static __always_inline void push__s64(uint8_t *data, uint64_t *payload_pos, int64_t param)
{
	*((int64_t *)&data[SAFE_ACCESS(*payload_pos)]) = param;
	*payload_pos += sizeof(int64_t);
}

static __always_inline void push__ipv6(uint8_t *data, uint64_t *payload_pos, uint32_t ipv6[4])
{
	__builtin_memcpy(&data[SAFE_ACCESS(*payload_pos)], ipv6, 16);
	*payload_pos += 16;
}

static __always_inline void push__new_character(uint8_t *data, uint64_t *payload_pos, char character)
{
	*((char *)&data[SAFE_ACCESS(*payload_pos)]) = character;
	*payload_pos += sizeof(char);
}

/* This method is a little bit different from the others because we overwrite
 * a previous character. Since we overwrite it we don't need to update
 * `payload_pos`.
 */
static __always_inline void push__previous_character(uint8_t *data, uint64_t *payload_pos, char character)
{
	*((char *)&data[SAFE_ACCESS(*payload_pos - 1)]) = character;
}

///////////////////////////
// PUSH VARIABLE DIMENSIONS
///////////////////////////

/**
 * @brief Take a charbuf pointer an try to push the charbuf into the buffer
 * The maximum length of the charbuf can be at most `limit`.
 *
 * Please note: `bpf_probe_read_str()` returns the number of bytes read in case
 * of success while returns a negative value in case of errors.
 *
 * @param data pointer to the buffer where the event is stored.
 * @param payload_pos pointer to the first empty byte after the last "push" operation.
 * @param charbuf_pointer pointer to the charbuf.
 * @param limit maximum number of bytes that we read in case we don't find a `\0`
 * @param mem tell where it must read: user-space or kernel-space.
 * @return (uint16_t) the number of bytes written in the buffer. Returns '0' if the passed pointer is not valid.
 *         Returns `1` if the provided pointer points to an empty string "".
 */
static __always_inline uint16_t push__charbuf(uint8_t *data, uint64_t *payload_pos, unsigned long charbuf_pointer, uint16_t limit, enum read_memory mem)
{
	int written_bytes = 0;

	if(mem == KERNEL)
	{
		written_bytes = bpf_probe_read_kernel_str(&data[SAFE_ACCESS(*payload_pos)],
							  limit,
							  (char *)charbuf_pointer);
	}
	else
	{
		written_bytes = bpf_probe_read_user_str(&data[SAFE_ACCESS(*payload_pos)],
							limit,
							(char *)charbuf_pointer);
	}

	if(written_bytes < 0)
	{
		/* This is probably a page fault */
		return 0;
	}

	/* Since `bpf_probe_read_user_str` return `0` in case of empty string we push a `\0` and we return 1. */
	if(written_bytes==0)
	{
		*((char *)&data[SAFE_ACCESS(*payload_pos)]) = '\0';
		written_bytes = 1;
	}

	*payload_pos += written_bytes;
	return (uint16_t)written_bytes;
}

/**
 * @brief The difference between `push__bytebuf` and `push__charbuf` is that
 * with `push__charbuf` we try to read until the first `\0` otherwise we read
 * `limit` bytes, while with `push__bytebuf` we have to read exactly
 * `len_to_read` bytes.
 *
 * Please note: `bpf_probe_read()` returns `0` in case
 * of success while returns a negative value in case of errors.
 *
 * @param data pointer to the buffer where the event is stored.
 * @param payload_pos pointer to the first empty byte after the last "push" operation.
 * @param bytebuf_pointer pointer to the bytebuf.
 * @param len_to_read bytes that we need to read from the pointer.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return (uint16_t) the number of bytes written in the buffer. Could be '0' if the passed pointer is not valid.
 */
static __always_inline uint16_t push__bytebuf(uint8_t *data, uint64_t *payload_pos, unsigned long bytebuf_pointer, uint16_t len_to_read, enum read_memory mem)
{
	if(mem == KERNEL)
	{
		if(bpf_probe_read_kernel(&data[SAFE_ACCESS(*payload_pos)],
						      len_to_read,
						      (void *)bytebuf_pointer) != 0)
		{
			return 0;
		}
	}
	else
	{
		if(bpf_probe_read_user(&data[SAFE_ACCESS(*payload_pos)],
						    len_to_read,
						    (void *)bytebuf_pointer) != 0)
		{
			return 0;
		}
	}

	*payload_pos += len_to_read;
	return len_to_read;
}
