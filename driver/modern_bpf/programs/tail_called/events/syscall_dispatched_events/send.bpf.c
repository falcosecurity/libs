// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>
#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(send_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SEND_E_SIZE, PPME_SOCKET_SEND_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int32_t fd = (int32_t)args[0];
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 2: size (type: PT_UINT32) */
	uint32_t size = (uint32_t)args[2];
	ringbuf__store_u32(&ringbuf, size);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(send_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SEND_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	int64_t bytes_to_read = ret > 0 ? ret : args[2];
	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(regs, &snaplen, false);
	if((int64_t)snaplen > bytes_to_read)
	{
		snaplen = bytes_to_read;
	}

	/* Parameter 2: data (type: PT_BYTEBUF) */
	unsigned long sent_data_pointer = args[1];
	auxmap__store_bytebuf_param(auxmap, sent_data_pointer, snaplen, USER);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
