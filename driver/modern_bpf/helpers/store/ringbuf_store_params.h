// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/shared_size.h>
#include <helpers/base/push_data.h>
#include <helpers/extract/extract_from_kernel.h>
#include <helpers/base/stats.h>

/* `reserved_size - sizeof(uint64_t)` free space is enough because this is the max dimension
 * we put in the ring buffer in one atomic operation.
 */
#define CHECK_RINGBUF_SPACE(pos, reserved_size) pos >= reserved_size ? reserved_size - sizeof(uint64_t) : pos

#define PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, size)                                                                         \
	__builtin_memcpy(&ringbuf->data[CHECK_RINGBUF_SPACE(ringbuf->payload_pos, ringbuf->reserved_event_size)], &param, size); \
	ringbuf->payload_pos += size;                                                                                            \
	*((uint16_t *)&ringbuf->data[CHECK_RINGBUF_SPACE(ringbuf->lengths_pos, ringbuf->reserved_event_size)]) = size;                \
	ringbuf->lengths_pos += sizeof(uint16_t);

/* Concept of ringbuf(ring buffer):
 *
 * For fixed size events we directly reserve space into the ringbuf. We have
 * a dedicated ringbuf for every CPU. When we collect a fixed size event,
 * as a first thing, we try to reserve space inside the ringbuf. If the
 * operation is successful we save the pointer to this space, otherwise
 * if the buffer is full, we stop immediately the collection without
 * loosing further time.
 *
 * More precisely, in case of success we store the pointer into a struct
 * called `ringbuf_struct`:
 *
 * struct ringbuf_struct
 * {
 *	  uint8_t *data;	   // pointer to the space reserved in the ring buffer.
 *	  uint64_t payload_pos; // position of the first empty byte in the `data` buf.
 *	  uint8_t lengths_pos;  // position the first empty slot into the lengths array of the event.
 * };
 *
 * To better understand the two indexes `payload_pos` and `lengths_pos`
 * please see the description of the event format in
 * `helpers/base/push_data.h`
 *
 * As you may notice this structure is very similar to the `auxiliary_map` struct,
 * but there are some differences:
 * - In `ringbuf_struct` struct `data` is a pointer to some space in the ringbuf
 *   while in the auxamp is a buffer saved inside the struct.
 * - There is a `struct auxiliary_map` for every CPU, and all these structs
 *   are saved in a BPF map. This allow us to use the same struct between
 *   different BPF programs tail called, we have just to take the pointer
 * 	 to this struct and save it in our BPF stack. On the other side, the
 *   struct `ringbuf_struct` is created into the stack directly, we don't use
 * 	 a pointer. So we cannot pass this struct from a BPF program to another,
 *   but this is ok, because right now it is not possible to use a pointer to
 * 	 some space in the ringbuf outside the BPF program in which we call the
 * 	 reserve function. This is due to the fact taht we could cause a memory
 *   leakage, that is not obviously allowed in BPF.
 */

struct ringbuf_struct
{
	uint8_t *data;		 /* pointer to the space reserved in the ring buffer. */
	uint64_t payload_pos;	 /* position of the first empty byte in the `data` buf.*/
	uint8_t lengths_pos;		 /* position the first empty slot into the lengths array of the event. */
	uint16_t reserved_event_size; /* reserved size in the ringbuf. */
	uint16_t event_type; /* event type we want to send to userspace */
};

/////////////////////////////////
// RESERVE SPACE IN THE RINGBUF
////////////////////////////////

/**
 * @brief This helper is used to reserve some space inside the ringbuf
 * for that particular CPU. The number of CPU is taken directly inside
 * `maps__get_ringbuf_map()`.
 *
 * Please note: we need to pass the exact size to reserve, so we need
 * to know the event dimension at compile time.
 *
 * @param ringbuf pointer to the `ringbuf_struct`
 * @param ctx BPF prog context
 * @param event_size exact size of the fixed-size event
 * @return `1` in case of success, `0` in case of failure.
 */
static __always_inline uint32_t ringbuf__reserve_space(struct ringbuf_struct *ringbuf, void* ctx, uint32_t event_size, uint16_t event_type)
{
	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_HOTPLUG_E);
		bpf_printk("failed to tail call into the 'hotplug' prog");
		return 0;
	}

	struct counter_map *counter = maps__get_counter_map();
	if(!counter)
	{
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	uint8_t *space = bpf_ringbuf_reserve(rb, event_size, 0);
	if(!space)
	{
		counter->n_drops_buffer++;
		compute_event_types_stats(event_type, counter);
		return 0;
	}

	ringbuf->data = space;
	ringbuf->event_type = event_type;
	ringbuf->reserved_event_size = event_size;
	return 1;
}

/////////////////////////////////
// STORE EVENT HEADER IN THE RINGBUF
////////////////////////////////

/**
 * @brief Push the event header inside the ringbuf space.
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 */
static __always_inline void ringbuf__store_event_header(struct ringbuf_struct *ringbuf)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)ringbuf->data;
	uint8_t nparams = maps__get_event_num_params(ringbuf->event_type);
	hdr->ts = maps__get_boot_time() + bpf_ktime_get_boot_ns();
	hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	hdr->type = ringbuf->event_type;
	hdr->nparams = nparams;
	hdr->len = ringbuf->reserved_event_size;

	ringbuf->payload_pos = sizeof(struct ppm_evt_hdr) + nparams * sizeof(uint16_t);
	ringbuf->lengths_pos = sizeof(struct ppm_evt_hdr);
}

static __always_inline void ringbuf__rewrite_header_for_calibration(struct ringbuf_struct *ringbuf, pid_t vtid)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)ringbuf->data;
	/* we set this to 0 to recognize this calibration event */
	hdr->nparams = 0;
	/* we cannot send the tid seen by the init namespace we need to send the tid seen by the current pid namespace
	 * to be compliant with what scap expects.
	 */
	hdr->tid = vtid;
}

/////////////////////////////////
// SUBMIT EVENT IN THE RINGBUF
////////////////////////////////

/**
 * @brief This method states that the collection of the event is
 * terminated.
 *
 * `BPF_RB_NO_WAKEUP` option allow to not notify the userspace
 * when a new event is submitted.
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 */
static __always_inline void ringbuf__submit_event(struct ringbuf_struct *ringbuf)
{
	bpf_ringbuf_submit(ringbuf->data, BPF_RB_NO_WAKEUP);
}

/////////////////////////////////
// STORE PARAM TYPE INTO RING BUFFER
////////////////////////////////

/* All these `ringbuf__store_(x)_param` helpers have the task
 * to store a particular param inside the ringbuf space.
 * Note: `push__` functions store only some bytes into this space
 * and increment the payload pos. To store an entire param
 * we could need one or more `push__` helpers and one final `push__param_len`
 * to save the overall param len into the `lengths_array` seen into
 * `helpers/base/push_data.h` file.
 */

/**
 * @brief This helper should be used to store signed 16 bit params.
 * The following types are compatible with this helper:
 * - PT_INT16
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store.
 */
static __always_inline void ringbuf__store_s16(struct ringbuf_struct *ringbuf, int16_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(int16_t));
}

/**
 * @brief This helper should be used to store signed 32 bit params.
 * The following types are compatible with this helper:
 * - PT_INT32
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store.
 */
static __always_inline void ringbuf__store_s32(struct ringbuf_struct *ringbuf, int32_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(int32_t));
}

/**
 * @brief This helper should be used to store signed 64 bit params.
 * The following types are compatible with this helper:
 * - PT_INT64
 * - PT_ERRNO
 * - PT_PID
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_s64(struct ringbuf_struct *ringbuf, int64_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(int64_t));
}

/**
 * @brief This helper should be used to store unsigned 8 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT8
 * - PT_SIGTYPE
 * - PT_FLAGS8
 * - PT_ENUMFLAGS8
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u8(struct ringbuf_struct *ringbuf, uint8_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(uint8_t));
}

/**
 * @brief This helper should be used to store unsigned 16 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT16
 * - PT_FLAGS16
 * - PT_ENUMFLAGS16
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u16(struct ringbuf_struct *ringbuf, uint16_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(uint16_t));
}

/**
 * @brief This helper should be used to store unsigned 32 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT32
 * - PT_UID
 * - PT_GID
 * - PT_SIGSET
 * - PT_MODE
 * - PT_FLAGS32
 * - PT_ENUMFLAGS32
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u32(struct ringbuf_struct *ringbuf, uint32_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(uint32_t));
}

/**
 * @brief This helper should be used to store unsigned 64 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT64
 * - PT_RELTIME
 * - PT_ABSTIME
 *
 * @param ringbuf pointer to the `ringbuf_struct`.
 * @param param param to store
 */
static __always_inline void ringbuf__store_u64(struct ringbuf_struct *ringbuf, uint64_t param)
{
	PUSH_FIXED_SIZE_TO_RINGBUF(ringbuf, param, sizeof(uint64_t));
}

/**
 * @brief Store the size of a message extracted from an `iovec` struct array.
 *
 * @param auxmap pointer to the ringbuf in which we are storing the param.
 * @param iov_pointer pointer to `iovec` struct array.
 * @param iov_cnt number of `iovec` structs to be read from userspace.
 */
static __always_inline void ringbuf__store_iovec_size_param(struct ringbuf_struct *ringbuf, unsigned long iov_pointer, unsigned long iov_cnt)
{
	/* The idea here is to use the auxmap of this CPU as a scratch space
	 * and normally use the ringbuf to send data to userspace. Note that
	 * we are running on this CPU so nobody else can use the auxmap in the meanwhile.
	 * Here we don't have to use the second half of the map, we can use all the space
	 * we want since we will never use the map to send data to userspace!
	 */

	struct auxiliary_map *auxmap = maps__get_auxiliary_map();
	if(!auxmap)
	{
		ringbuf__store_u32(ringbuf, 0);
		return;
	}

	uint32_t total_iovec_size = 0;
	if(!bpf_in_ia32_syscall())
	{
		total_iovec_size = iov_cnt * bpf_core_type_size(struct iovec);
	}
	else
	{
		total_iovec_size = iov_cnt * bpf_core_type_size(struct compat_iovec);
	}

	if(bpf_probe_read_user((void *)&auxmap->data[0],
			       SAFE_ACCESS(total_iovec_size),
			       (void *)iov_pointer))
	{
		ringbuf__store_u32(ringbuf, 0);
		return;
	}

	uint32_t total_size_to_read = 0;

	/* Pointer to iovec structs */
	if(!bpf_in_ia32_syscall())
	{
		const struct iovec *iovec = (const struct iovec *)&auxmap->data[0];
		for(int j = 0; j < MAX_IOVCNT; j++)
		{
			if(j == iov_cnt)
			{
				break;
			}
			total_size_to_read += iovec[j].iov_len;
		}
	}
	else
	{
		const struct compat_iovec *iovec = (const struct compat_iovec *)&auxmap->data[0];
		for(int j = 0; j < MAX_IOVCNT; j++)
		{
			if(j == iov_cnt)
			{
				break;
			}
			total_size_to_read += iovec[j].iov_len;
		}
	}
	ringbuf__store_u32(ringbuf, total_size_to_read);
}
