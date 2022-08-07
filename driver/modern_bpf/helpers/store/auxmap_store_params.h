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
#define MAX_PATH_POINTERS 8

/* Maximum length of unix socket path.
 * We can have at maximum 108 characters plus the `\0` terminator.
 */
#define MAX_UNIX_SOCKET_PATH 108 + 1

/* Network components size. */
#define FAMILY_SIZE sizeof(u8)
#define IPV4_SIZE sizeof(u32)
#define IPV6_SIZE 16
#define PORT_SIZE sizeof(u16)
#define KERNEL_POINTER sizeof(u64)

/* This enum is used to tell network helpers if the connection outbound
 * or inbound
 */
enum connection_direction
{
	OUTBOUND = 0,
	INBOUND = 1,
};

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
 * This version of `auxmap__store_path_from_fd` works smooth on all
 * supported architectures: `s390x`, `ARM64`, `x86_64`.
 * The drawback is that due to its complexity we can catch at most
 * `MAX_PATH_POINTERS==8`.
 *
 * The previous version of this method was able to correctly catch paths
 * under different mount points, but not on `s390x` architecture, where
 * the userspace test `open_by_handle_atX_success_mp` failed.
 *
 * #@Andreagit97: reduce the complexity of this helper to allow the capture
 * of more path components, or enable only this version of the helper on `s390x`,
 * leaving the previous working version on `x86` and `aarch64` architectures.
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
	struct mount *parent_mount = NULL;

	/* Here we store all the pointers, note that we don't take the pointer
	 * to the root so we will add it manually if it is necessary!
	 */
	for(int k = 0; k < MAX_PATH_POINTERS; ++k)
	{
		if(file_dentry == root_dentry)
		{
			break;
		}

		if(file_dentry == mount_dentry)
		{
			BPF_CORE_READ_INTO(&parent_mount, mnt, mnt_parent);
			BPF_CORE_READ_INTO(&file_dentry, mnt, mnt_mountpoint);
			mnt = parent_mount;
			BPF_CORE_READ_INTO(&mount_dentry, mnt, mnt.mnt_root);
			continue;
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

/**
 * @brief Store sockaddr info taken from syscall parameters.
 * This helper doesn't have the concept of `outbound` and `inbound` connections
 * since we read from userspace sockaddr struct. We have no to extract
 * different data in the kernel according to the direction as in
 * `auxmap__store_socktuple_param`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param sockaddr_pointer pointer to the sockaddr struct
 * @param addrlen overall length of the sockaddr struct
 */
static __always_inline void auxmap__store_sockaddr_param(struct auxiliary_map *auxmap, unsigned long sockaddr_pointer, u16 addrlen)
{
	u16 final_param_len = 0;

	/* We put the struct sockaddr in our auxmap, since we have to write other
	 * data in the map, we push this temporary information in the second half
	 * of the map (so in the second 64 KB), that will never be used unless the
	 * event is invalid (too big).
	 *
	 *
	 * Please note: we don't increment `payload pos` since we use this counter
	 * only when we write correct data into our map. Here we use this space
	 * as scratch, we won't push these extra data to userspace!
	 *
	 * AUXMAP:
	 *
	 * 						 first half of the
	 * 						  auxmap ends here
	 * 						   (first 64 KB)
	 * 								 |
	 * 								 v
	 * -----------------------------------
	 * |      |                      | X
	 * -----------------------------------
	 * 	 	  ^                        ^
	 *        |                        |
	 *		we are                  we save
	 *   writing here           here the sockaddr
	 *     our data                  struct
	 */

	/* If we are not able to save the sockaddr return an empty parameter. */
	if(bpf_probe_read_user((void *)&auxmap->data[MAX_PARAM_SIZE],
			       addrlen,
			       (void *)sockaddr_pointer))
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
		return;
	}

	/* Save the pointer to the sockaddr struct in the stack. */
	struct sockaddr *sockaddr = (struct sockaddr *)&auxmap->data[MAX_PARAM_SIZE];
	u16 socket_family = sockaddr->sa_family;

	switch(socket_family)
	{
	case AF_INET:
	{
		/* Map the user-provided address to a sockaddr_in. */
		struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)sockaddr;

		/* Copy address and port into the stack. */
		u32 ipv4 = sockaddr_in->sin_addr.s_addr;
		u16 port = sockaddr_in->sin_port;

		/* Pack the sockaddr info:
		 * - socket family.
		 * - ipv4.
		 * - port.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		push__u32(auxmap->data, &auxmap->payload_pos, ipv4);
		push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port));
		final_param_len = FAMILY_SIZE + IPV4_SIZE + PORT_SIZE;
		break;
	}

	case AF_INET6:
	{
		/* Map the user-provided address to a sockaddr_in6. */
		struct sockaddr_in6 *sockaddr_in6 = (struct sockaddr_in6 *)sockaddr;

		/* Copy address and port into the stack. */
		u32 ipv6[4] = {0, 0, 0, 0};
		__builtin_memcpy(&ipv6, sockaddr_in6->sin6_addr.in6_u.u6_addr32, 16);
		u16 port = sockaddr_in6->sin6_port;

		/* Pack the sockaddr info:
		 * - socket family.
		 * - dest_ipv6.
		 * - dest_port.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6);
		push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port));
		final_param_len = FAMILY_SIZE + IPV6_SIZE + PORT_SIZE;
		break;
	}

	case AF_UNIX:
	{
		/* Map the user-provided address to a sockaddr_un. */
		struct sockaddr_un *sockaddr_un = (struct sockaddr_un *)sockaddr;

		/* Starting at `sockaddr_un` we have the socket family and after it
		 * the `sun_path`.
		 *
		 * Please note exceptions in the `sun_path`:
		 * Taken from: https://man7.org/linux/man-pages/man7/unix.7.html
		 *
		 * An `abstract socket address` is distinguished (from a
		 * pathname socket) by the fact that sun_path[0] is a null byte
		 * ('\0').
		 */

		/* Check the exact point in which we have to start reading our path. */
		unsigned long start_reading_point;
		/* We skip the two bytes of socket family. */
		char first_path_byte = *(char *)sockaddr_un->sun_path;
		if(first_path_byte == '\0')
		{
			/* This is an abstract socket address, we need to skip the initial `\0`. */
			start_reading_point = (unsigned long)sockaddr_un->sun_path + 1;
		}
		else
		{
			start_reading_point = (unsigned long)sockaddr_un->sun_path;
		}

		/* Pack the sockaddr info:
		 * - socket family.
		 * - socket_unix_path (sun_path).
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		u16 written_bytes = push__charbuf(auxmap->data, &auxmap->payload_pos, start_reading_point, MAX_UNIX_SOCKET_PATH, KERNEL);
		final_param_len = FAMILY_SIZE + written_bytes;
		break;
	}

	default:
		final_param_len = 0;
		break;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, final_param_len);
}

/**
 * @brief Store socktuple info taken from kernel socket.
 * We prefer extracting data directly from the kernel to
 * obtain more precise information.
 *
 * Please note:
 * In outbound connections `local` is the src while `remote` is the dest.
 * In inbound connections vice versa.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param socket_fd socket from which we extract information about the tuple.
 * @param direction specifies the connection direction.
 */
static __always_inline void auxmap__store_socktuple_param(struct auxiliary_map *auxmap, u32 socket_fd, int direction)
{
	u16 final_param_len = 0;

	/* Get the socket family directly from the socket */
	u16 socket_family = 0;
	struct file *file = NULL;
	file = extract__file_struct_from_fd(socket_fd);
	struct socket *socket = BPF_CORE_READ(file, private_data);
	struct sock *sk = BPF_CORE_READ(socket, sk);
	BPF_CORE_READ_INTO(&socket_family, socket, ops, family);

	switch(socket_family)
	{
	case AF_INET:
	{

		struct inet_sock *inet = (struct inet_sock *)sk;

		u32 ipv4_local = 0;
		u16 port_local = 0;
		u32 ipv4_remote = 0;
		u16 port_remote = 0;
		BPF_CORE_READ_INTO(&ipv4_local, inet, inet_saddr);
		BPF_CORE_READ_INTO(&port_local, inet, inet_sport);
		BPF_CORE_READ_INTO(&ipv4_remote, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&port_remote, sk, __sk_common.skc_dport);

		/* Pack the tuple info:
		 * - socket family
		 * - src_ipv4
		 * - dest_ipv4
		 * - src_port
		 * - dest_port
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));

		if(direction == OUTBOUND)
		{
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_local);
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
		}
		else
		{
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_remote);
			push__u32(auxmap->data, &auxmap->payload_pos, ipv4_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
		}

		final_param_len = FAMILY_SIZE + IPV4_SIZE + IPV4_SIZE + PORT_SIZE + PORT_SIZE;
		break;
	}

	case AF_INET6:
	{
		/* Map the user-provided address to a sockaddr_in6. */
		struct inet_sock *inet = (struct inet_sock *)sk;

		u32 ipv6_local[4] = {0, 0, 0, 0};
		u16 port_local = 0;
		u32 ipv6_remote[4] = {0, 0, 0, 0};
		u16 port_remote = 0;

		BPF_CORE_READ_INTO(&ipv6_local, inet, pinet6, saddr);
		BPF_CORE_READ_INTO(&port_local, inet, inet_sport);
		BPF_CORE_READ_INTO(&ipv6_remote, sk, __sk_common.skc_v6_daddr);
		BPF_CORE_READ_INTO(&port_remote, sk, __sk_common.skc_dport);

		/* Pack the tuple info:
		 * - socket family
		 * - src_ipv6
		 * - dest_ipv6
		 * - src_port
		 * - dest_port
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));

		if(direction == OUTBOUND)
		{
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_local);
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_remote);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
		}
		else
		{
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_remote);
			push__ipv6(auxmap->data, &auxmap->payload_pos, ipv6_local);
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_remote));
			push__u16(auxmap->data, &auxmap->payload_pos, ntohs(port_local));
		}
		final_param_len = FAMILY_SIZE + IPV6_SIZE + IPV6_SIZE + PORT_SIZE + PORT_SIZE;
		break;
	}

	case AF_UNIX:
	{
		struct unix_sock *socket_local = (struct unix_sock *)sk;
		struct unix_sock *socket_remote = (struct unix_sock *)BPF_CORE_READ(socket_local, peer);
		char *path = NULL;

		/* Pack the tuple info:
		 * - socket family.
		 * - dest OS pointer.
		 * - src OS pointer.
		 * - dest unix_path.
		 */
		push__u8(auxmap->data, &auxmap->payload_pos, socket_family_to_scap(socket_family));
		if(direction == OUTBOUND)
		{
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_remote);
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_local);
			path = BPF_CORE_READ(socket_remote, addr, name[0].sun_path);
		}
		else
		{
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_local);
			push__u64(auxmap->data, &auxmap->payload_pos, (u64)socket_remote);
			path = BPF_CORE_READ(socket_local, addr, name[0].sun_path);
		}

		unsigned long start_reading_point;
		/* We have to skip the two bytes of socket family. */
		char first_path_byte = *(char *)path;
		if(first_path_byte == '\0')
		{
			/* This is an abstract socket address, we need to skip the initial `\0`. */
			start_reading_point = (unsigned long)path + 1;
		}
		else
		{
			start_reading_point = (unsigned long)path;
		}

		u16 written_bytes = push__charbuf(auxmap->data, &auxmap->payload_pos, start_reading_point, MAX_UNIX_SOCKET_PATH, KERNEL);
		final_param_len = FAMILY_SIZE + KERNEL_POINTER + KERNEL_POINTER + written_bytes;
		break;
	}

	default:
		final_param_len = 0;
		break;
	}

	// if we are not able to catch correct programs we push an empty param.
	push__param_len(auxmap->data, &auxmap->lengths_pos, final_param_len);
}

/**
 * @brief Store ptrace addr param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace addr param is sent to userspace.
 *   As in the old probe we send only params of type `PPM_PTRACE_IDX_UINT64`.
 * - 8 byte: the ptrace addr value sent as a `PT_UINT64`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param addr_pointer pointer to the `addr` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_addr_param(struct auxiliary_map *auxmap, long ret, u64 addr_pointer)
{
	push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);

	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
	}
	else
	{
		/* We send the addr pointer as a uint64_t */
		push__u64(auxmap->data, &auxmap->payload_pos, addr_pointer);
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
}

/**
 * @brief Store ptrace data param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace data param is sent to userspace.
 * - a variable size part according to the `ptrace_req`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param ptrace_req ptrace request converted in the scap format.
 * @param data_pointer pointer to the `data` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_data_param(struct auxiliary_map *auxmap, long ret, u16 ptrace_req, u64 data_pointer)
{
	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
		push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
		return;
	}

	u64 dest = 0;
	u16 total_size_to_push = sizeof(u8); /* 1 byte for the PPM type. */
	switch(ptrace_req)
	{
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		bpf_probe_read_user((void *)&dest, sizeof(dest), (void *)data_pointer);
		push__u64(auxmap->data, &auxmap->payload_pos, dest);
		total_size_to_push += sizeof(u64);
		break;

	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_SIGTYPE);
		push__u8(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u8);
		break;

	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u64);
		break;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_push);
}
