// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(sendmsg_e, struct pt_regs *regs, long id) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[2] = {0};
	extract__network_args(args, 2, regs);

	/* Parameter 1: fd (type: PT_FD) */
	int32_t socket_fd = (int32_t)args[0];
	auxmap__store_s64_param(auxmap, (int64_t)socket_fd);

	/* Parameter 2: size (type: PT_UINT32) */
	unsigned long msghdr_pointer = args[1];
	auxmap__store_msghdr_size_param(auxmap, msghdr_pointer);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	/* TODO: Here we don't know if this fd is a socket or not,
	 * since we are in the enter event and the syscall could fail.
	 * This shouldn't be a problem since if it is not a socket fd
	 * the `bpf_probe_read()` call we fail. Probably we have to move it
	 * in the exit event.
	 */
	if(socket_fd >= 0) {
		struct sockaddr *usrsockaddr;
		struct msghdr *msg = (struct msghdr *)msghdr_pointer;
		BPF_CORE_READ_USER_INTO(&usrsockaddr, msg, msg_name);
		auxmap__store_socktuple_param(auxmap, socket_fd, OUTBOUND, usrsockaddr);
	} else {
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(sendmsg_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Collect parameters at the beginning to manage socketcalls. */
	unsigned long args[2] = {0};
	extract__network_args(args, 2, regs);

	/* Extract socket fd and msghdr pointer syscall parameters. */
	int64_t fd = (int32_t)args[0];
	unsigned long msghdr_pointer = args[1];

	/* Extract the content of msghdr and use it to derive the parameters. */
	struct user_msghdr msghdr = {0};
	if(unlikely(extract__msghdr(&msghdr, msghdr_pointer) < 0)) {
		/* Parameter 2: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 3: fd (type: PT_FD) */
		auxmap__store_s64_param(auxmap, fd);

		/* Parameter 4: size (type: PT_UINT32) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		auxmap__store_empty_param(auxmap);
	} else {
		/* In case of failure `bytes_to_read` could be also lower than `snaplen`
		 * but we will discover it directly into `auxmap__store_iovec_data_param`
		 * otherwise we need to extract it now and it has a cost. Here we check just
		 * the return value if the syscall is successful.
		 */
		uint16_t snaplen = maps__get_snaplen();
		dynamic_snaplen_args snaplen_args = {
		        .only_port_range = true,
		        .evt_type = PPME_SOCKET_SENDMSG_X,
		};
		apply_dynamic_snaplen(regs, &snaplen, &snaplen_args);
		if(ret > 0 && snaplen > ret) {
			snaplen = ret;
		}

		unsigned long iov_pointer = (unsigned long)msghdr.msg_iov;
		uint32_t iov_cnt = msghdr.msg_iovlen;

		/* Parameter 2: data (type: PT_BYTEBUF) */
		auxmap__store_iovec_data_param(auxmap, (unsigned long)iov_pointer, iov_cnt, snaplen);

		/* Parameter 3: fd (type: PT_FD) */
		auxmap__store_s64_param(auxmap, fd);

		/* Parameter 4: size (type: PT_UINT32) */
		/* Use the second part of our auxmap as a scratch space for the `extract__iovec_size` helper
		 * to read the iovec structs in. */
		void *scratch_space = (void *)&auxmap->data[MAX_PARAM_SIZE];
		uint32_t scratch_space_size = SAFE_ACCESS(iov_cnt * bpf_core_type_size(struct iovec));
		uint32_t size =
		        extract__iovec_size(scratch_space, scratch_space_size, iov_pointer, iov_cnt);
		auxmap__store_u32_param(auxmap, size);

		/* Parameter 5: tuple (type: PT_SOCKTUPLE) */
		if(ret >= 0) {
			struct sockaddr *usrsockaddr = (struct sockaddr *)msghdr.msg_name;
			/* Notice: the following will push an empty parameter if something goes wrong. */
			auxmap__store_socktuple_param(auxmap, fd, OUTBOUND, usrsockaddr);
		} else {
			auxmap__store_empty_param(auxmap);
		}
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
