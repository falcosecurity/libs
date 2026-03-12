// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

typedef struct {
	uint32_t fd;
	struct mmsghdr *mmh;
} sendmmsg_exit_t;

static __always_inline long handle_exit(uint32_t index, void *ctx) {
	sendmmsg_exit_t *data = (sendmmsg_exit_t *)ctx;

	/* Read individual fields instead of the full struct mmsghdr to keep
	 * frame 1 stack small enough for the 512-byte 3-frame limit.
	 * Handle both native and compat (ia32) layouts.
	 */
	unsigned int msg_len;
	unsigned long msg_iov;
	unsigned long msg_iovlen;
	struct sockaddr *msg_name;

	if(bpf_in_ia32_syscall()) {
		struct compat_mmsghdr *cmmh_ptr = (struct compat_mmsghdr *)data->mmh + index;
		msg_len = BPF_CORE_READ_USER(cmmh_ptr, msg_len);
		msg_iov = (unsigned long)BPF_CORE_READ_USER(cmmh_ptr, msg_hdr.msg_iov);
		msg_iovlen = BPF_CORE_READ_USER(cmmh_ptr, msg_hdr.msg_iovlen);
		msg_name = (struct sockaddr *)(unsigned long)BPF_CORE_READ_USER(cmmh_ptr, msg_hdr.msg_name);
	} else {
		struct mmsghdr *mmh_ptr = data->mmh + index;
		msg_len = BPF_CORE_READ_USER(mmh_ptr, msg_len);
		msg_iov = (unsigned long)BPF_CORE_READ_USER(mmh_ptr, msg_hdr.msg_iov);
		msg_iovlen = BPF_CORE_READ_USER(mmh_ptr, msg_hdr.msg_iovlen);
		msg_name = BPF_CORE_READ_USER(mmh_ptr, msg_hdr.msg_name);
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, msg_len);

	/* Parameter 2: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)data->fd);

	/* Parameter 3: size (type: PT_UINT32) */
	auxmap__store_iovec_size_param(auxmap, msg_iov, msg_iovlen);

	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen_port_range(&snaplen, (int32_t)data->fd, msg_name);
	if(msg_len > 0 && snaplen > msg_len) {
		snaplen = msg_len;
	}

	/* Parameter 4: data (type: PT_BYTEBUF) */
	auxmap__store_iovec_data_param_noinline(auxmap, msg_iov, msg_iovlen, snaplen);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE)*/
	auxmap__store_socktuple_param_noinline(auxmap, data->fd, OUTBOUND, msg_name);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event_noinline(auxmap);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sendmmsg_x, struct pt_regs *regs, long ret) {
	if(ret <= 0) {
		unsigned long fd = 0;
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap) {
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, ret);

		/* Parameter 2: fd (type: PT_FD) */
		extract__network_args(&fd, 1, regs);
		auxmap__store_s64_param(auxmap, (int64_t)(int32_t)fd);

		/* Parameter 3: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 4: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap);
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);
	sendmmsg_exit_t data = {
	        .fd = args[0],
	        .mmh = (struct mmsghdr *)args[1],
	};

	uint32_t nr_loops = ret < MAX_SENDMMSG_RECVMMSG_SIZE ? ret : MAX_SENDMMSG_RECVMMSG_SIZE;
	bpf_loop(nr_loops, handle_exit, &data, 0);

	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sendmmsg_old_x, struct pt_regs *regs, long ret) {
	if(ret <= 0) {
		unsigned long fd = 0;
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap) {
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

		/* Parameter 1: res (type: PT_ERRNO) */
		auxmap__store_s64_param(auxmap, ret);

		/* Parameter 2: fd (type: PT_FD) */
		extract__network_args(&fd, 1, regs);
		auxmap__store_s64_param(auxmap, (int64_t)(int32_t)fd);

		/* Parameter 3: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 4: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap);
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2];
	extract__network_args(args, 2, regs);
	sendmmsg_exit_t data = {
	        .fd = args[0],
	        .mmh = (struct mmsghdr *)args[1],
	};

	// Only first message
	handle_exit(0, &data);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
