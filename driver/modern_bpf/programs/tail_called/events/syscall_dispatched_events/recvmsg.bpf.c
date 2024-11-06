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
int BPF_PROG(recvmsg_e, struct pt_regs *regs, long id) {
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long socket_fd = 0;
	extract__network_args(&socket_fd, 1, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, RECVMSG_E_SIZE, PPME_SOCKET_RECVMSG_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD)*/
	ringbuf__store_s64(&ringbuf, (int64_t)(int32_t)socket_fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(recvmsg_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_RECVMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	if(ret >= 0) {
		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, (uint32_t)ret);

		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, true, PPME_SOCKET_RECVMSG_X);
		if(snaplen > ret) {
			snaplen = ret;
		}

		/* Collect parameters at the beginning to manage socketcalls */
		unsigned long args[2] = {0};
		extract__network_args(args, 2, regs);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		unsigned long msghdr_pointer = args[1];
		struct user_msghdr msghhdr =
		        auxmap__store_msghdr_data_param(auxmap, msghdr_pointer, snaplen);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		uint32_t socket_fd = (uint32_t)args[0];
		auxmap__store_socktuple_param(auxmap, socket_fd, INBOUND, msghhdr.msg_name);

		/* Parameter 5: msg_control (type: PT_BYTEBUF) */
		if(msghhdr.msg_control != NULL) {
			auxmap__store_bytebuf_param(auxmap,
			                            (unsigned long)msghhdr.msg_control,
			                            msghhdr.msg_controllen,
			                            USER);
		} else {
			auxmap__store_empty_param(auxmap);
		}
	} else {
		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 4: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: msg_control (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
