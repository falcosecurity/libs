/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/push_data.h>
#include <helpers/extract/extract_from_kernel.h>

/* Right now a file path extracted from a file descriptor can
 * have at most `MAX_PATH_POINTERS` components.
 */
#define MAX_PATH_POINTERS 16

/* Concept of auxamp (auxiliary map):
 *
 * For variable size events we cannot directly reserve space into the ringbuf,
 * we need to use a bpf map as a temporary buffer to save our events. So every cpu
 * can use this temporary space when it receives a variable size event.
 *
 * This temporary space is represented as an `auxiliary map struct`. In
 * addition to the raw space (`data`) where we will save our event, there
 * are 2 integers placeholders that help us to understand in which part of
 * the buffer we are writing.
 *
 * struct auxiliary_map
 * {
 *	  u8 data[AUXILIARY_MAP_SIZE]; // raw space to save our variable-size event.
 *	  uint64_t payload_pos;	         // position of the first empty byte in the `data` buf.
 *	  uint8_t lengths_pos;	         // position the first empty slot into the lengths array of the event.
 * };
 *
 * To better understand the two indexes `payload_pos` and `lengths_pos`
 * please see the description of the event format in
 * `helpers/base/push_data.h`
 *
 * Please note: The auxiliary map can contain events of at most 64 KB,
 * but the `AUXILIARY_MAP_SIZE` is 128 KB. We have chosen this
 * size to make the verifier understand that there will always be
 * 64 KB free for a new event parameter. This allow us to easily
 * write data into the map without many extra checks.
 *
 * Look at the macro `SAFE_ACCESS(x)` defined in `helpers/base/push_data.h`.
 * If `payload_pos` is lower than `MAX_PARAM_SIZE` we use this index to write
 * new bytes, otherwise we use `payload_pos & MAX_PARAM_SIZE` as index. So
 * the index will be always lower than `MAX_PARAM_SIZE`!
 *
 * Please note that in this last case we are actually overwriting our event!
 * Using `payload_pos & MAX_PARAM_SIZE` as index means that we have already
 * written at least `MAX_PARAM_SIZE` so we are overwriting our data. This is
 * not an issue! If we have already written more than `MAX_PARAM_SIZE`, the
 * event size will be surely greather than 64 KB, so at the end of the collection
 * phase the entire event will be discarded!
 */

/////////////////////////////////
// GET AUXILIARY MAP
////////////////////////////////

/**
 * @brief Get the auxiliary map pointer for the current CPU.
 *
 * @return pointer to the auxmap
 */
static __always_inline struct auxiliary_map *auxmap__get()
{
	return maps__get_auxiliary_map();
}

/////////////////////////////////
// STORE EVENT HEADER INTO THE AUXILIARY MAP
////////////////////////////////

/**
 * @brief Push the event header inside the auxiliary map.
 *
 * Please note: we call this method `preload` since we cannot completely fill the
 * event header. When we call this method we don't know yet the overall size of
 * the event, we discover it only at the end of the collection phase. We have
 * to use the `auxmap__finalize_event_header` to "finalize" the header, inserting
 * also the total event length.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 * @param event_type This is the type of the event that we are writing into the map.
 */
static __always_inline void auxmap__preload_event_header(struct auxiliary_map *auxmap, u16 event_type)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	u8 nparams = maps__get_event_num_params(event_type);
	hdr->ts = maps__get_boot_time() + bpf_ktime_get_boot_ns();
	hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	hdr->type = event_type;
	hdr->nparams = nparams;
	auxmap->payload_pos = sizeof(struct ppm_evt_hdr) + nparams * sizeof(u16);
	auxmap->lengths_pos = sizeof(struct ppm_evt_hdr);
}

/**
 * @brief Finalize the header writing the overall event len.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 */
static __always_inline void auxmap__finalize_event_header(struct auxiliary_map *auxmap)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	hdr->len = auxmap->payload_pos;
}

/////////////////////////////////
// COPY EVENT FROM AUXMAP TO RINGBUF
////////////////////////////////

/**
 * @brief Copy the entire event from the auxiliary map to bpf ringbuf.
 * If the event is correctly copied in the ringbuf we increments the number
 * of events sent to userspace, otherwise we increment the dropped events.
 *
 * @param auxmap pointer to the auxmap in which we have already written the entire event.
 */
static __always_inline void auxmap__submit_event(struct auxiliary_map *auxmap)
{

	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		return;
	}

	struct counter_map *counter = maps__get_counter_map();
	if(!counter)
	{
		return;
	}

	if(auxmap->payload_pos > MAX_EVENT_SIZE)
	{
		counter->n_drops_max_event_size++;
		return;
	}

	/* `BPF_RB_NO_WAKEUP` means that we don't send to userspace a notification
	 *  when a new event is in the buffer.
	 */
	int err = bpf_ringbuf_output(rb, auxmap->data, auxmap->payload_pos, BPF_RB_NO_WAKEUP);
	if(err)
	{
		counter->n_drops_buffer++;
	}
	else
	{
		counter->n_evts++;
	}
}

/////////////////////////////////
// STORE EVENT PARAMS INTO THE AUXILIARY MAP
////////////////////////////////

/* All these `auxmap__store_(x)_param` helpers have the task
 * to store a particular param inside the bpf auxiliary map.
 * Note: `push__` functions store only some bytes into the map
 * and increment the payload pos. To store an entire param
 * we could need one or more `push__` helpers and one final `push__param_len`
 * to save the overall param len into the `lengths_array` seen into
 * `helpers/base/push_data.h` file.
 */

/**
 * @brief This function must be used when we are not able to correctly
 * collect the param. We simply put the param length to 0 into the
 * `lengths_array` of the event, so the userspace can easely understand
 * that the param is empty.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 */
static __always_inline void auxmap__store_empty_param(struct auxiliary_map *auxmap)
{
	push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
}

/**
 * @brief This helper should be used to store signed 32 bit params.
 * The following types are compatible with this helper:
 * - PT_INT32
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s32_param(struct auxiliary_map *auxmap, s32 param)
{
	push__s32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s32));
}

/**
 * @brief This helper should be used to store signed 64 bit params.
 * The following types are compatible with this helper:
 * - PT_INT64
 * - PT_ERRNO
 * - PT_PID
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s64_param(struct auxiliary_map *auxmap, s64 param)
{
	push__s64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s64));
}

/**
 * @brief This helper should be used to store unsigned 8 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT8
 * - PT_SIGTYPE
 * - PT_FLAGS8
 * - PT_ENUMFLAGS8
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u8_param(struct auxiliary_map *auxmap, u8 param)
{
	push__u8(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8));
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
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u32_param(struct auxiliary_map *auxmap, u32 param)
{
	push__u32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u32));
}

/**
 * @brief This helper should be used to store unsigned 64 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT64
 * - PT_RELTIME
 * - PT_ABSTIME
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u64_param(struct auxiliary_map *auxmap, u64 param)
{
	push__u64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u64));
}

/**
 * @brief This helper stores the charbuf pointed by `charbuf_pointer`
 * into the auxmap. The charbuf can have a maximum length
 * of `MAX_PARAM_SIZE`. For more details, look at the underlying
 * `push__charbuf` method
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param charbuf_pointer pointer to the charbuf to store.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return number of bytes read.
 */
static __always_inline u16 auxmap__store_charbuf_param(struct auxiliary_map *auxmap, unsigned long charbuf_pointer, enum read_memory mem)
{
	u16 charbuf_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, MAX_PARAM_SIZE, mem);
	/* If we are not able to push anything with `push__charbuf`
	 * `charbuf_len` will be equal to `0` so we will send an
	 * empty param to userspace.
	 */
	push__param_len(auxmap->data, &auxmap->lengths_pos, charbuf_len);
	return charbuf_len;
}

/**
 * @brief This helper stores the file path extracted from the `fd`.
 *
 * Please note: Kernel 5.10 introduced a new bpf_helper called `bpf_d_path`
 * to extract a file path starting from a file descriptor but it can be used only
 * with specific hooks:
 *
 * https://github.com/torvalds/linux/blob/e0dccc3b76fb35bb257b4118367a883073d7390e/kernel/trace/bpf_trace.c#L915-L929.
 *
 * So we need to do it by hand and this cause a limit in the max
 * path component that we can retrieve (MAX_PATH_POINTERS).
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param fd file descriptor from which we want to retrieve the file path.
 */
static __always_inline void auxmap__store_path_from_fd(struct auxiliary_map *auxmap, s32 fd)
{
	u16 total_size = 0;
	u8 path_components = 0;
	unsigned long path_pointers[MAX_PATH_POINTERS] = {0};
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
	}

	struct task_struct *t = get_current_task();
	struct dentry *file_dentry = BPF_CORE_READ(f, f_path.dentry);
	struct dentry *root_dentry = READ_TASK_FIELD(t, fs, root.dentry);
	struct vfsmount *original_mount = BPF_CORE_READ(f, f_path.mnt);
	struct mount *mnt = container_of(original_mount, struct mount, mnt);
	struct dentry *mount_dentry = BPF_CORE_READ(mnt, mnt.mnt_root);
	struct dentry *file_dentry_parent = NULL;

	/* this should catch the path from the right mount point. */
	if(file_dentry == mount_dentry && file_dentry != root_dentry)
	{
		BPF_CORE_READ_INTO(&file_dentry, mnt, mnt_mountpoint);
	}

	/* Here we store all the pointers, note that we don't take the pointer
	 * to the root so we will add it manually if it is necessary!
	 */
	for(int k = 0; k < MAX_PATH_POINTERS; ++k)
	{
		if(file_dentry == root_dentry)
		{
			break;
		}

		path_components++;
		BPF_CORE_READ_INTO(&path_pointers[k], file_dentry, d_name.name);
		BPF_CORE_READ_INTO(&file_dentry_parent, file_dentry, d_parent);
		file_dentry = file_dentry_parent;
	}

	/* Reconstruct the path in reverse, using previously collected pointers.
	 *
	 * 1. As a first thing, we have to add the root `/`.
	 *
	 * 2. When we read the string in BPF with `bpf_probe_read_str()` we always
	 * add the `\0` terminator. In this way, we will obtain something like this:
	 *
	 * - "path_1\0"
	 * - "path_2\0"
	 * - "file\0"
	 *
	 * So putting it all together:
	 *
	 * 	"/path_1\0path_2\0file\0"
	 *
	 * (Note that we added `/` manually so there is no `\0`)
	 *
	 * But we want to obtain something like this:
	 *
	 * 	"/path_1/path_2/file\0"
	 *
	 * To obtain it we can replace all `\0` with `/`, but in this way we
	 * obtain:
	 *
	 * 	"/path_1/path_2/file/"
	 *
	 * So we need to replace the last `/` with `\0`.
	 */

	/* 1. Push the root `/` */
	push__new_character(auxmap->data, &auxmap->payload_pos, '/');
	total_size += 1;

	for(int k = MAX_PATH_POINTERS - 1; k >= 0; --k)
	{
		if(path_pointers[k])
		{
			total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, path_pointers[k], MAX_PARAM_SIZE, KERNEL);
			push__previous_character(auxmap->data, &auxmap->payload_pos, '/');
		}
	}

	/* Different cases:
	 * - `path_components==0` we have to add the last `\0`.
	 * - `path_components==1` we need to replace the last `/` with a `\0`.
	 * - `path_components>1` we need to replace the last `/` with a `\0`.
	 */
	if(path_components >= 1)
	{
		push__previous_character(auxmap->data, &auxmap->payload_pos, '\0');
	}
	else
	{
		push__new_character(auxmap->data, &auxmap->payload_pos, '\0');
		total_size += 1;
	}

	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
}
