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
int BPF_PROG(accept4_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, ACCEPT4_E_SIZE, PPME_SOCKET_ACCEPT4_6_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: flags (type: PT_FLAGS32) */
	/// TODO: we don't support flags yet and so we just return zero.
	///    If implemented, special handling for SYS_ACCEPT socketcall is needed.
	uint32_t flags = 0;
	ringbuf__store_u32(&ringbuf, flags);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(accept4_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_ACCEPT4_6_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* If the syscall `connect` succeeds, it creates a new connected socket
	 * with file descriptor `ret` and we can get some parameters, otherwise we return
	 * default values.
	 */

	/* actual dimension of the server queue. */
	uint32_t queuelen = 0;

	/* max dimension of the server queue. */
	uint32_t queuemax = 0;

	/* occupancy percentage of the server queue. */
	uint8_t queuepct = 0;

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	if(ret >= 0)
	{
		auxmap__store_socktuple_param(auxmap, (int32_t)ret, INBOUND, NULL);

		/* Collect parameters at the beginning to  manage socketcalls */
		unsigned long args[1];
		extract__network_args(args, 1, regs);

		/* Perform some computations to get queue information. */
		/* If the syscall is successful the `sockfd` will be >= 0. We want
		 * to extract information from the listening socket, not from the
		 * new one.
		 */
		int32_t sockfd = (int32_t)args[0];
		struct file *file = NULL;
		file = extract__file_struct_from_fd(sockfd);
		struct socket *socket = BPF_CORE_READ(file, private_data);
		struct sock *sk = BPF_CORE_READ(socket, sk);
		BPF_CORE_READ_INTO(&queuelen, sk, sk_ack_backlog);
		BPF_CORE_READ_INTO(&queuemax, sk, sk_max_ack_backlog);
		if(queuelen && queuemax)
		{
			queuepct = (uint8_t)((uint64_t)queuelen * 100 / queuemax);
		}
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 3: queuepct (type: PT_UINT8) */
	auxmap__store_u8_param(auxmap, queuepct);

	/* Parameter 4: queuelen (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, queuelen);

	/* Parameter 5: queuemax (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, queuemax);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
