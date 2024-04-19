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
int BPF_PROG(setsockopt_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SETSOCKOPT_E_SIZE, PPME_SOCKET_SETSOCKOPT_E))
	{
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

SEC("tp_btf/sys_exit")
int BPF_PROG(setsockopt_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SETSOCKOPT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[5];
	extract__network_args(args, 5, regs);

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: fd (type: PT_FD) */
	int32_t fd = (int32_t)args[0];
	auxmap__store_s64_param(auxmap, (int64_t)fd);

	/* Parameter 3: level (type: PT_ENUMFLAGS8) */
	int level = (int)args[1];
	auxmap__store_u8_param(auxmap, sockopt_level_to_scap(level));

	/* Parameter 4: optname (type: PT_ENUMFLAGS8) */
	int optname = (int)args[2];
	auxmap__store_u8_param(auxmap, sockopt_optname_to_scap(level, optname));

	/* Parameter 5: optval (type: PT_DYN) */
	unsigned long optval = args[3];
	uint16_t optlen = (uint16_t)args[4];
	auxmap__store_sockopt_param(auxmap, level, optname, optlen, optval);

	/* Parameter 6: optlen (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, (uint32_t)optlen);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
