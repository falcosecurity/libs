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
int BPF_PROG(sendto_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDTO_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[5];
	extract__network_args(args, 5, regs);

	/* Parameter 1: fd (type: PT_FD) */
	int32_t socket_fd = (int32_t)args[0];
	auxmap__store_s64_param(auxmap, (int64_t)socket_fd);

	/* Parameter 2: size (type: PT_UINT32) */
	uint32_t size = (uint32_t)args[2];
	auxmap__store_u32_param(auxmap, size);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	/* TODO: Here we don't know if this fd is a socket or not,
	 * since we are in the enter event and the syscall could fail.
	 * This shouldn't be a problem since if it is not a socket fd
	 * the `bpf_probe_read()` call we fail. Probably we have to move it
	 * in the exit event.
	 */
	if(socket_fd >= 0)
	{
		struct sockaddr *usrsockaddr = (struct sockaddr *)args[4];
		auxmap__store_socktuple_param(auxmap, socket_fd, OUTBOUND, usrsockaddr);
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(sendto_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDTO_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Collect parameters at the beginning to manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	/* If the syscall doesn't fail we use the return value as `size`
	 * otherwise we need to rely on the syscall parameter provided by the user.
	 */
	uint16_t bytes_to_read = ret > 0 ? ret : args[2];
	uint16_t snaplen = maps__get_snaplen();
	apply_dynamic_snaplen(regs, &snaplen, false);
	if(snaplen > bytes_to_read)
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
