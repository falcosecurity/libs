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
int BPF_PROG(sendmmsg_e, struct pt_regs *regs, long id) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SENDMMSG_E_SIZE, PPME_SOCKET_SENDMMSG_E)) {
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
	struct pt_regs *regs;
	void *ctx;
} sendmmsg_exit_t;

static long handle_exit(uint32_t index, void *ctx) {
	sendmmsg_exit_t *data = (sendmmsg_exit_t *)ctx;
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

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, mmh.msg_len);

	/* Parameter 2: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, (int64_t)data->fd);

	/* Parameter 3: size (type: PT_UINT32) */
	auxmap__store_iovec_size_param(auxmap,
	                               (unsigned long)mmh.msg_hdr.msg_iov,
	                               mmh.msg_hdr.msg_iovlen);

	/* In case of failure `bytes_to_read` could be also lower than `snaplen`
	 * but we will discover it directly into `auxmap__store_iovec_data_param`
	 * otherwise we need to extract it now and it has a cost. Here we check just
	 * the return value if the syscall is successful.
	 */
	dynamic_snaplen_args snaplen_args = {
	        .only_port_range = true,
	        .evt_type = PPME_SOCKET_SENDMMSG_X,
	        .mmsg_index = index,
	};
	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(data->regs, &snaplen, &snaplen_args);
	if(mmh.msg_len > 0 && snaplen > mmh.msg_len) {
		snaplen = mmh.msg_len;
	}

	/* Parameter 4: data (type: PT_BYTEBUF) */
	unsigned long msghdr_pointer = (unsigned long)&mmh.msg_hdr;
	auxmap__store_iovec_data_param(auxmap,
	                               (unsigned long)mmh.msg_hdr.msg_iov,
	                               mmh.msg_hdr.msg_iovlen,
	                               snaplen);

	/* Parameter 5: tuple (type: PT_SOCKTUPLE)*/
	if(data->fd >= 0) {
		auxmap__store_socktuple_param(auxmap, data->fd, OUTBOUND, mmh.msg_hdr.msg_name);
	} else {
		auxmap__store_empty_param(auxmap);
	}
	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
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
	        .regs = regs,
	        .ctx = ctx,
	};

	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop)) {
		uint32_t nr_loops = ret < 1024 ? ret : 1024;
		bpf_loop(nr_loops, handle_exit, &data, 0);
	} else {
		for(int i = 0; i < ret && i < MAX_IOVCNT; i++) {
			handle_exit(i, &data);
		}
	}

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
