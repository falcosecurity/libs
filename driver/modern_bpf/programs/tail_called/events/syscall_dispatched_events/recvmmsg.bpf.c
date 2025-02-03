// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(recvmmsg_e, struct pt_regs *regs, long id) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, RECVMMSG_E_SIZE, PPME_SOCKET_RECVMMSG_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

typedef struct {
	uint32_t fd;
	struct mmsghdr *mmh;
	unsigned long *args;
} recvmmsg_data_t;

static __always_inline long handle_exit(uint32_t index, void *ctx) {
	recvmmsg_data_t *data = (recvmmsg_data_t *)ctx;
	struct mmsghdr mmh = {0};
	if(bpf_probe_read_user((void *)&mmh,
	                       bpf_core_type_size(struct mmsghdr),
	                       (void *)(data->mmh + index)) != 0) {
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, mmh.msg_len);

	/* Parameter 2: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)data->fd);

	/* Parameter 3: size (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, (uint32_t)mmh.msg_len);

	/* We read the minimum between `snaplen` and what we really
	 * have in the buffer.
	 */
	dynamic_snaplen_args snaplen_args = {
	        .only_port_range = true,
	        .evt_type = PPME_SOCKET_RECVMMSG_X,
	        .mmsg_index = index,
	        .mm_args = data->args,
	};
	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(NULL, &snaplen, &snaplen_args);
	if(snaplen > mmh.msg_len) {
		snaplen = mmh.msg_len;
	}

	/* Parameter 4: data (type: PT_BYTEBUF) */
	auxmap__store_iovec_data_param(auxmap,
	                               (unsigned long)mmh.msg_hdr.msg_iov,
	                               mmh.msg_hdr.msg_iovlen,
	                               snaplen);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
	auxmap__store_socktuple_param(auxmap,
	                              data->fd,
	                              INBOUND,
	                              (struct sockaddr *)mmh.msg_hdr.msg_name);

	/* Parameter 6: msg_control (type: PT_BYTEBUF) */
	if(mmh.msg_hdr.msg_control != NULL) {
		auxmap__store_bytebuf_param(auxmap,
		                            (unsigned long)mmh.msg_hdr.msg_control,
		                            mmh.msg_hdr.msg_controllen,
		                            USER);
	} else {
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmmsg_x, struct pt_regs *regs, long ret) {
	if(ret <= 0) {
		unsigned long fd = 0;
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap) {
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMMSG_X);

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

		/* Parameter 6: msg_control (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap);
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);
	recvmmsg_data_t data = {
	        .fd = args[0],
	        .mmh = (struct mmsghdr *)args[1],
	        .args = args,
	};

	uint32_t nr_loops = ret < 1024 ? ret : 1024;
	bpf_loop(nr_loops, handle_exit, &data, 0);

	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmmsg_old_x, struct pt_regs *regs, long ret) {
	if(ret <= 0) {
		unsigned long fd = 0;
		struct auxiliary_map *auxmap = auxmap__get();
		if(!auxmap) {
			return 0;
		}

		auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMMSG_X);

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

		/* Parameter 6: msg_control (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		auxmap__finalize_event_header(auxmap);

		auxmap__submit_event(auxmap);
		return 0;
	}

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);
	recvmmsg_data_t data = {
	        .fd = args[0],
	        .mmh = (struct mmsghdr *)args[1],
	        .args = args,
	};

	// Send only first message
	handle_exit(0, &data);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
