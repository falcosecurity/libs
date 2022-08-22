/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(sendmsg_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	s32 socket_fd = (s32)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, (s64)socket_fd);

	/* Parameter 2: size (type: PT_UINT32) */
	unsigned long msghdr_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_iovec_size_param(auxmap, msghdr_pointer);

	/* Parameter 3: tuple (type: PT_SOCKTUPLE)*/
	/* TODO: Here we don't know if this fd is a socket or not,
	 * since we are in the enter event and the syscall could fail.
	 * This shouldn't be a problem since if it is not a socket fd
	 * the `bpf_probe_read()` call we fail. Probably we have to move it
	 * in the exit event.
	 */
	if(socket_fd >= 0)
	{
		auxmap__store_socktuple_param(auxmap, socket_fd, OUTBOUND);
	}
	else
	{
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
int BPF_PROG(sendmsg_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_SENDMSG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: data (type: PT_BYTEBUF) */
	/* Here we want to read some data sent by the `sendmsg()` syscall.
	 * If the syscall fails we send an empty parameter.
	 */
	if(ret >= 0)
	{
		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		unsigned long bytes_to_read = maps__get_snaplen();

		if(bytes_to_read > ret)
		{
			bytes_to_read = ret;
		}

		unsigned long msghdr_pointer = extract__syscall_argument(regs, 1);
		auxmap__store_iovec_data_param(auxmap, msghdr_pointer, bytes_to_read);
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
