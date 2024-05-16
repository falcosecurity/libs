// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(socketpair_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3] = {0};
	extract__network_args(args, 3, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKETPAIR_E_SIZE, PPME_SOCKET_SOCKETPAIR_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: domain (type: PT_ENUMFLAGS32) */
	/* why to send 32 bits if we need only 8 bits? */
	uint8_t domain = (uint8_t)args[0];
	ringbuf__store_u32(&ringbuf, (uint32_t)socket_family_to_scap(domain));

	/* Parameter 2: type (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t type = (uint32_t)args[1];
	ringbuf__store_u32(&ringbuf, type);

	/* Parameter 3: proto (type: PT_UINT32) */
	/* this should be an int, not a uint32 */
	uint32_t proto = (uint32_t)args[2];
	ringbuf__store_u32(&ringbuf, proto);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(socketpair_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SOCKETPAIR_X_SIZE, PPME_SOCKET_SOCKETPAIR_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	int32_t fds[2] = {-1, -1};
	unsigned long source = 0;
	unsigned long peer = 0;
	unsigned long fds_pointer = 0;

	/* In case of success we have 0. */
	if(ret == 0)
	{
		/* Collect parameters at the beginning to manage socketcalls */
		unsigned long args[4] = {0};
		extract__network_args(args, 4, regs);

		/* Get new sockets. */
		fds_pointer = args[3];
		bpf_probe_read_user((void *)fds, 2 * sizeof(int32_t), (void *)fds_pointer);

		/* Get source and peer. */
		struct file *file = extract__file_struct_from_fd((int32_t)fds[0]);
		struct socket *socket = get_sock_from_file(file);
		if(socket != NULL)
		{
			BPF_CORE_READ_INTO(&source, socket, sk);
			struct unix_sock *us = (struct unix_sock *)source;
			BPF_CORE_READ_INTO(&peer, us, peer);
		}
	}

	/* Parameter 2: fd1 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (int64_t)fds[0]);

	/* Parameter 3: fd2 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (int64_t)fds[1]);

	/* Parameter 4: source (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, source);

	/* Parameter 5: peer (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, peer);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
